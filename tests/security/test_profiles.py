import asyncio
import base64
import hashlib
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken, AuthorizationParams, RegistrationError
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl, ValidationError
from starlette.requests import Request

from yandex_workspace_mcp.auth.scopes import expand_scope_values
from yandex_workspace_mcp.auth.stores import TokenStoreMiss
from yandex_workspace_mcp.config import Settings
from yandex_workspace_mcp.server import ApplicationDependencies, create_application, create_http_app


def profile_settings(profile: str, **updates) -> Settings:
    values = {
        "mcp_profile": profile,
        "mcp_transport": "streamable-http",
        "mcp_auth_mode": "multi-user",
        "yandex_auth_mode": "multi-user",
        "yandex_oauth_client_id": f"{profile}-client",
        "yandex_oauth_client_secret": f"{profile}-secret",
        "mcp_issuer_url": f"https://{profile}.example",
        "mcp_resource_server_url": f"https://{profile}.example/mcp",
        "mcp_oauth_callback_url": f"https://{profile}.example/oauth/yandex/callback",
    }
    values.update(updates)
    return Settings(**values)


def test_profiles_scopes_and_storage_are_separate():
    disk, mail = profile_settings("disk"), profile_settings("mail")
    assert (disk.yandex_disk_enabled, disk.yandex_wiki_enabled, disk.yandex_mail_enabled) == (
        True,
        False,
        False,
    )
    assert (mail.yandex_disk_enabled, mail.yandex_wiki_enabled, mail.yandex_mail_enabled) == (
        False,
        False,
        True,
    )
    assert disk.auth_storage_prefix != mail.auth_storage_prefix
    assert (
        disk.auth_storage_prefix
        != profile_settings("disk", mcp_issuer_url="https://other.example").auth_storage_prefix
    )
    assert expand_scope_values(["mail:delete"]) == ("mail:read", "mail:write", "mail:delete")
    assert expand_scope_values(["workspace:delete"]) == (
        "workspace:read",
        "workspace:write",
        "workspace:delete",
    )
    for updates in (
        {"yandex_disk_enabled": True},
        {"yandex_wiki_enabled": True},
        {"mcp_static_scopes": ["workspace:read"]},
    ):
        with pytest.raises(ValidationError):
            profile_settings("mail", **updates)
    with pytest.raises(ValidationError, match="Global trash"):
        profile_settings("disk", disk_allow_global_destructive=True)


@pytest.mark.asyncio
async def test_profiles_only_publish_their_own_tools_and_scopes():
    disk = create_application(profile_settings("disk", disk_write=True, disk_delete=True))
    mail = create_application(profile_settings("mail", mail_write=True, mail_delete=True))
    disk_names = {tool.name for tool in await disk.mcp_server.list_tools()}
    mail_tools = await mail.mcp_server.list_tools()
    assert disk_names and not any(name.startswith(("mail_", "wiki_")) for name in disk_names)
    assert "disk_empty_trash" not in disk_names
    assert "disk_restore_from_trash" in disk_names
    assert mail_tools and all(tool.name.startswith("mail_") for tool in mail_tools)
    for tool in mail_tools:
        assert tool.meta and all(s.startswith("mail:") for s in tool.meta["required_scopes"])
    assert mail.oauth_provider and disk.oauth_provider
    assert set(mail.oauth_provider.valid_scopes) == {"mail:read", "mail:write", "mail:delete"}
    assert set(disk.oauth_provider.valid_scopes) == {
        "workspace:read",
        "workspace:write",
        "workspace:delete",
    }
    with pytest.raises(RegistrationError):
        await mail.oauth_provider.register_client(
            OAuthClientInformationFull(
                client_id="foreign",
                redirect_uris=[AnyUrl("https://client.example/cb")],
                scope="workspace:read",
            )
        )


@pytest.mark.asyncio
async def test_mail_callback_http_pkce_refresh_revoke_and_cross_profile_isolation():
    account = ["alice"]
    exchanges = []

    def upstream(request: httpx.Request):
        if request.url.host == "oauth.yandex.ru":
            fields = parse_qs(request.content.decode())
            exchanges.append(fields)
            return httpx.Response(
                200,
                json={
                    "access_token": f"upstream-{account[0]}",
                    "refresh_token": f"refresh-{account[0]}",
                    "expires_in": 3600,
                },
            )
        return httpx.Response(
            200, json={"id": account[0], "default_email": f"{account[0]}@yandex.ru"}
        )

    app = create_application(
        profile_settings("mail"),
        ApplicationDependencies(
            oauth_http_client_factory=lambda: httpx.AsyncClient(
                transport=httpx.MockTransport(upstream)
            ),
        ),
    )
    disk = create_application(profile_settings("disk"))
    assert app.oauth_provider and disk.oauth_provider
    provider = app.oauth_provider
    client = OAuthClientInformationFull(
        client_id="public-client",
        redirect_uris=[AnyUrl("https://client.example/cb")],
        scope="mail:read",
        token_endpoint_auth_method="none",
    )
    await provider.register_client(client)
    verifier = "v" * 48
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    subjects = []
    tokens = []
    async with (
        app.lifespan(),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_http_app(app)), base_url="https://mail.example"
        ) as http,
    ):
        for username in ("alice", "bob"):
            account[0] = username
            redirect = await provider.authorize(
                client,
                AuthorizationParams(
                    state="state",
                    scopes=["mail:read"],
                    code_challenge=challenge,
                    redirect_uri=AnyUrl("https://client.example/cb"),
                    redirect_uri_provided_explicitly=True,
                    resource="https://mail.example/mcp",
                ),
            )
            query = parse_qs(urlsplit(redirect).query)
            assert set(query["scope"][0].split()) == {
                "login:email",
                "mail:imap_full",
                "mail:smtp",
            }
            response = await http.get(
                "/oauth/yandex/callback",
                params={
                    "state": query["state"][0],
                    "code": f"code-{username}",
                },
            )
            assert response.status_code == 307
            code = parse_qs(urlsplit(response.headers["location"]).query)["code"][0]
            upstream_challenge = (
                base64.urlsafe_b64encode(
                    hashlib.sha256(exchanges[-1]["code_verifier"][0].encode()).digest()
                )
                .rstrip(b"=")
                .decode()
            )
            assert query["code_challenge"] == [upstream_challenge]
            fields = {
                "grant_type": "authorization_code",
                "client_id": client.client_id,
                "code": code,
                "redirect_uri": "https://client.example/cb",
                "code_verifier": "x" * 48,
            }
            rejected = await http.post("/token", data=fields)
            assert rejected.status_code == 400
            fields["code_verifier"] = verifier
            success = await http.post("/token", data=fields)
            assert success.status_code == 200, success.text
            token = success.json()
            tokens.append(token)
            access = await provider.load_access_token(token["access_token"])
            assert access and access.subject
            subjects.append(access.subject)
            assert await disk.oauth_provider.load_access_token(token["access_token"]) is None
            assert (
                await disk.oauth_provider.load_refresh_token(client, token["refresh_token"]) is None
            )
            assert (await http.post("/token", data=fields)).status_code == 400
            assert (
                await http.get(
                    "/oauth/yandex/callback",
                    params={
                        "state": query["state"][0],
                        "code": "replay",
                    },
                )
            ).status_code == 400
        assert subjects[0] != subjects[1]

        async def credentials(subject):
            ctx = auth_context_var.set(
                AuthenticatedUser(
                    AccessToken(
                        token="local-test",
                        client_id=client.client_id,
                        subject=subject,
                        scopes=["mail:read"],
                    )
                )
            )
            try:
                await asyncio.sleep(0)
                result = await app._mail_credentials()
                return result.token, result.email
            finally:
                auth_context_var.reset(ctx)

        assert await asyncio.gather(*(credentials(subject) for subject in subjects)) == [
            ("upstream-alice", "alice@yandex.ru"),
            ("upstream-bob", "bob@yandex.ru"),
        ]
        refresh = await http.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "client_id": client.client_id,
                "refresh_token": tokens[0]["refresh_token"],
                "scope": "mail:read",
            },
        )
        assert refresh.status_code == 200
        assert await provider.load_access_token(tokens[0]["access_token"]) is None
        rotated = refresh.json()
        revoked = await http.post(
            "/revoke",
            data={
                "client_id": client.client_id,
                "token": rotated["refresh_token"],
                "token_type_hint": "refresh_token",
            },
        )
        assert revoked.status_code == 200
        assert await provider.load_access_token(rotated["access_token"]) is None
        with pytest.raises(TokenStoreMiss):
            await app.auth_store.get_downstream(subjects[0])
        assert await provider.load_access_token(tokens[1]["access_token"]) is not None
        assert (await app.auth_store.get_downstream(subjects[1])).email == "bob@yandex.ru"


@pytest.mark.asyncio
@pytest.mark.parametrize("email", [None, "", "user", "a@b\r\nAUTH secret"])
async def test_mail_callback_rejects_missing_or_invalid_account_email(email):
    def upstream(request):
        payload = (
            {"access_token": "secret", "expires_in": 3600}
            if request.url.host == "oauth.yandex.ru"
            else {
                "id": "subject",
                "default_email": email,
            }
        )
        return httpx.Response(200, json=payload)

    app = create_application(
        profile_settings("mail"),
        ApplicationDependencies(
            oauth_http_client_factory=lambda: httpx.AsyncClient(
                transport=httpx.MockTransport(upstream)
            ),
        ),
    )
    assert app.oauth_provider
    client = OAuthClientInformationFull(
        client_id="client",
        redirect_uris=[AnyUrl("https://client.example/cb")],
        scope="mail:read",
    )
    await app.oauth_provider.register_client(client)
    redirect = await app.oauth_provider.authorize(
        client,
        AuthorizationParams(
            state=None,
            scopes=["mail:read"],
            code_challenge="challenge",
            redirect_uri=AnyUrl("https://client.example/cb"),
            redirect_uri_provided_explicitly=True,
            resource="https://mail.example/mcp",
        ),
    )
    state = parse_qs(urlsplit(redirect).query)["state"][0]
    async with app.lifespan():
        request = Request({"type": "http", "query_string": f"state={state}&code=code".encode()})
        response = await app.require_oauth_callback().handle(request)
        assert "error=access_denied" in response.headers["location"]
        with pytest.raises(TokenStoreMiss):
            await app.auth_store.get_downstream(
                app.oauth_provider.principal_id("client", "subject")
            )


@pytest.mark.asyncio
async def test_refresh_preserves_verified_email_and_other_user_credentials():
    from yandex_workspace_mcp.auth.credentials import StoredCredentialProvider
    from yandex_workspace_mcp.auth.models import DownstreamCredentialRecord, Principal
    from yandex_workspace_mcp.auth.stores import InMemoryTokenStore

    store = InMemoryTokenStore((b"k" * 32,), clock=lambda: 100)
    for subject, expiry in (("alice", 99), ("bob", 200)):
        await store.put_downstream(
            subject,
            DownstreamCredentialRecord(
                principal_id=subject,
                access_token=f"old-{subject}",
                refresh_token=f"refresh-{subject}",
                email=f"{subject}@yandex.ru",
                expires_at=1000,
                access_expires_at=expiry,
            ),
        )

    def upstream(request):
        fields = parse_qs(request.content.decode())
        assert fields["refresh_token"] == ["refresh-alice"]
        return httpx.Response(200, json={"access_token": "new-alice", "expires_in": 3600})

    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as http:
        provider = StoredCredentialProvider(
            store,
            yandex_client_id="mail-client",
            yandex_client_secret="mail-secret",
            client=http,
            clock=lambda: 100,
        )
        alice, bob = await asyncio.gather(
            provider.resolve(Principal("alice")),
            provider.resolve(Principal("bob")),
        )
        assert (alice.token, alice.email) == ("new-alice", "alice@yandex.ru")
        assert (bob.token, bob.email) == ("old-bob", "bob@yandex.ru")


@pytest.mark.asyncio
async def test_revocation_adapter_keeps_confidential_client_and_ownership_checks():
    from yandex_workspace_mcp.auth.models import AccessTokenRecord

    app = create_application(profile_settings("disk"))
    assert app.oauth_provider
    for client_id in ("owner", "other"):
        await app.oauth_provider.register_client(
            OAuthClientInformationFull(
                client_id=client_id,
                client_secret=f"secret-{client_id}",
                redirect_uris=[AnyUrl("https://client.example/cb")],
                scope="workspace:read",
                token_endpoint_auth_method="client_secret_post",
            )
        )
    await app.auth_store.put_access_token(
        "owned-token",
        AccessTokenRecord(
            client_id="owner",
            subject="alice",
            scopes=("workspace:read",),
            resource="https://disk.example/mcp",
        ),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_http_app(app)), base_url="https://disk.example"
    ) as http:
        for secret in (None, "", "wrong"):
            data = {"client_id": "owner", "token": "owned-token"}
            if secret is not None:
                data["client_secret"] = secret
            assert (await http.post("/revoke", data=data)).status_code == 401
            assert await app.oauth_provider.load_access_token("owned-token") is not None
        assert (
            await http.post(
                "/revoke",
                data={
                    "client_id": "other",
                    "client_secret": "secret-other",
                    "token": "owned-token",
                },
            )
        ).status_code == 200
        assert await app.oauth_provider.load_access_token("owned-token") is not None
        assert (
            await http.post(
                "/revoke",
                data={
                    "client_id": "owner",
                    "client_secret": "secret-owner",
                    "token": "owned-token",
                },
            )
        ).status_code == 200
        assert await app.oauth_provider.load_access_token("owned-token") is None
