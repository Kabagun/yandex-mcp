"""OAuth longevity checks use synthetic grants and mocked Yandex responses only."""

import asyncio
from dataclasses import dataclass
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from mcp.server.auth.provider import AuthorizationParams
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl
from starlette.requests import Request

from yandex_workspace_mcp.auth.credentials import StoredCredentialProvider, next_refresh_time
from yandex_workspace_mcp.auth.models import (
    DownstreamCredentialRecord,
    Principal,
    YandexOAuthCredential,
)
from yandex_workspace_mcp.auth.oauth import YandexMcpOAuthProvider, YandexOAuthCallback
from yandex_workspace_mcp.auth.stores import InMemoryTokenStore, TokenStoreMiss
from yandex_workspace_mcp.config import Settings
from yandex_workspace_mcp.models.errors import (
    AuthenticationError,
    ConfigurationError,
    ContractMismatchError,
    RateLimitExceeded,
    UpstreamTimeout,
    UpstreamUnavailable,
)
from yandex_workspace_mcp.server import ApplicationDependencies, create_application, create_http_app

DAY = 24 * 3600


@dataclass
class Clock:
    now: float = 1_000_000.0

    def __call__(self) -> float:
        return self.now


def _provider(store, clock, scope="workspace:read", **policy) -> YandexMcpOAuthProvider:
    return YandexMcpOAuthProvider(
        store=store,
        issuer_url="https://mcp.example",
        resource_server_url="https://mcp.example/mcp",
        yandex_client_id="synthetic-yandex-client",
        yandex_callback_url="https://mcp.example/oauth/yandex/callback",
        valid_scopes=[scope],
        clock=clock,
        **policy,
    )


def _client(scope="workspace:read") -> OAuthClientInformationFull:
    return OAuthClientInformationFull(
        client_id="synthetic-mcp-client",
        client_secret="synthetic-mcp-secret",
        redirect_uris=[AnyUrl("https://client.example/callback")],
        scope=scope,
        token_endpoint_auth_method="client_secret_post",
    )


async def _authorize(provider, client, scope="workspace:read") -> str:
    url = await provider.authorize(
        client,
        AuthorizationParams(
            state="synthetic-client-state",
            scopes=[scope],
            code_challenge="synthetic-pkce-challenge",
            redirect_uri=AnyUrl("https://client.example/callback"),
            redirect_uri_provided_explicitly=True,
            resource="https://mcp.example/mcp",
        ),
    )
    return parse_qs(urlsplit(url).query)["state"][0]


def _callback_request(state: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/oauth/yandex/callback",
            "query_string": f"code=synthetic-code&state={state}".encode(),
            "headers": [],
        }
    )


def _credentials(store, clock, http, **policy) -> StoredCredentialProvider:
    return StoredCredentialProvider(
        store,
        yandex_client_id="synthetic-yandex-client",
        yandex_client_secret="synthetic-yandex-secret",
        client=http,
        clock=clock,
        **policy,
    )


@pytest.mark.parametrize("profile,scope", [("disk", "workspace:read"), ("mail", "mail:read")])
async def test_default_disk_and_mail_grants_survive_ninety_days_with_rotation_and_revocation(
    profile, scope
) -> None:
    clock = Clock()
    store = InMemoryTokenStore((b"k" * 32,), clock=clock)
    provider = _provider(store, clock, scope)
    client = _client(scope)
    await provider.register_client(client)
    registration = await store.get_client(client.client_id)
    assert registration.expires_at is None
    assert registration.client_secret_expires_at is None
    assert registration.metadata["client_secret_expires_at"] == 0
    exchanges = []

    def upstream(request: httpx.Request) -> httpx.Response:
        if request.url.host == "login.yandex.ru":
            return httpx.Response(
                200, json={"id": "synthetic-account", "default_email": "owner@example.test"}
            )
        fields = parse_qs(request.content.decode())
        exchanges.append(fields)
        suffix = "initial" if fields["grant_type"] == ["authorization_code"] else "renewed"
        return httpx.Response(
            200,
            json={
                "access_token": f"synthetic-access-{suffix}",
                "refresh_token": f"synthetic-refresh-{suffix}",
                "expires_in": 3600,
            },
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as http:
        callback = YandexOAuthCallback(
            provider=provider,
            store=store,
            yandex_client_id="synthetic-yandex-client",
            yandex_client_secret="synthetic-yandex-secret",
            callback_url="https://mcp.example/oauth/yandex/callback",
            require_email=profile == "mail",
            client=http,
            clock=clock,
        )
        response = await callback.handle(
            _callback_request(await _authorize(provider, client, scope))
        )
        assert response.status_code == 307
        code_value = parse_qs(urlsplit(response.headers["location"]).query)["code"][0]
        code = await provider.load_authorization_code(client, code_value)
        assert code is not None
        token = await provider.exchange_authorization_code(client, code)
        assert token.expires_in == 3600
        access = await provider.load_access_token(token.access_token)
        assert access is not None and access.subject is not None
        principal = Principal(access.subject)
        grant = await store.get_downstream(principal.principal_id)
        assert grant.expires_at is None
        assert grant.access_expires_at == clock.now + 3600
        assert (
            grant.refresh_after is not None
            and clock.now < grant.refresh_after < grant.access_expires_at
        )
        assert grant.email == ("owner@example.test" if profile == "mail" else None)

        clock.now += 3601
        assert await provider.load_access_token(token.access_token) is None
        clock.now += 90 * DAY - 3601
        assert await provider.get_client(client.client_id) is not None
        assert token.refresh_token is not None
        refresh = await provider.load_refresh_token(client, token.refresh_token)
        assert refresh is not None and refresh.expires_at is None
        assert (
            await store.get_downstream(principal.principal_id)
        ).access_token == grant.access_token

        renewed = await _credentials(store, clock, http).resolve(principal)
        assert isinstance(renewed, YandexOAuthCredential)
        assert renewed.token == "synthetic-access-renewed"
        assert renewed.email == grant.email
        updated = await store.get_downstream(principal.principal_id)
        assert updated.expires_at is None
        assert updated.access_expires_at == clock.now + 3600
        assert updated.refresh_token == "synthetic-refresh-renewed"
        assert exchanges[-1]["refresh_token"] == ["synthetic-refresh-initial"]

        rotated = await provider.exchange_refresh_token(client, refresh, [scope])
        assert rotated.expires_in == 3600
        assert rotated.refresh_token and rotated.refresh_token != token.refresh_token
        assert await provider.load_refresh_token(client, token.refresh_token) is None
        new_refresh = await provider.load_refresh_token(client, rotated.refresh_token)
        assert new_refresh is not None
        await provider.revoke_token(new_refresh)
        assert await provider.load_access_token(rotated.access_token) is None
        assert await provider.load_refresh_token(client, rotated.refresh_token) is None
        with pytest.raises(TokenStoreMiss):
            await store.get_downstream(principal.principal_id)


async def test_valid_legacy_registration_and_grant_are_enrolled_before_old_deadline() -> None:
    clock = Clock()
    store = InMemoryTokenStore((b"k" * 32,), clock=clock)
    client = _client()
    legacy = _provider(store, clock, client_secret_expiry_seconds=30 * DAY)
    await legacy.register_client(client)
    grant = DownstreamCredentialRecord(
        principal_id="legacy-account",
        access_token="synthetic-legacy-access",
        refresh_token="synthetic-legacy-refresh",
        expires_at=clock.now + 30 * DAY,
        access_expires_at=clock.now + 90 * DAY,
        email="verified@example.test",
    )
    await store.put_downstream(grant.principal_id, grant)
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(500))
    ) as http:
        provider = _provider(store, clock)
        loaded = await provider.get_client(client.client_id)
        assert loaded is not None and loaded.client_secret_expires_at == 0
        enrolled = await _credentials(store, clock, http).resolve_record(
            Principal(grant.principal_id)
        )
        assert enrolled.expires_at is None
        assert enrolled.email == grant.email
        assert enrolled.refresh_after is not None and enrolled.refresh_after <= clock.now + 60 * DAY
        clock.now += 31 * DAY
        assert await provider.get_client(client.client_id) is not None
        assert (await store.get_downstream(grant.principal_id)).access_token == grant.access_token


async def test_explicit_finite_policies_still_expire_clients_refresh_tokens_and_grants() -> None:
    clock = Clock()
    store = InMemoryTokenStore((b"k" * 32,), clock=clock)
    provider = _provider(store, clock, client_secret_expiry_seconds=600, refresh_ttl_seconds=900)
    client = _client()
    await provider.register_client(client)
    redirect = await provider.complete_authorization(await _authorize(provider, client), "account")
    code = await provider.load_authorization_code(
        client, parse_qs(urlsplit(redirect).query)["code"][0]
    )
    assert code is not None
    token = await provider.exchange_authorization_code(client, code)
    assert token.refresh_token is not None
    await store.put_downstream(
        "account",
        DownstreamCredentialRecord(
            principal_id="account",
            access_token="synthetic-access",
            refresh_token="synthetic-refresh",
            access_expires_at=clock.now - 1,
        ),
    )
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, json={"access_token": "renewed", "expires_in": 3600})
        )
    ) as http:
        refreshed = await _credentials(
            store, clock, http, credential_ttl_seconds=1200
        ).resolve_record(Principal("account"))
    assert refreshed.expires_at == clock.now + 1200
    clock.now += 601
    assert await provider.get_client(client.client_id) is None
    assert await provider.load_refresh_token(client, token.refresh_token) is not None
    clock.now += 300
    assert await provider.load_refresh_token(client, token.refresh_token) is None
    assert await store.get_downstream("account") is not None
    clock.now += 300
    with pytest.raises(TokenStoreMiss):
        await store.get_downstream("account")


@pytest.mark.parametrize(
    "failure,expected,deleted",
    [
        ("timeout", UpstreamTimeout, False),
        ("transport", UpstreamUnavailable, False),
        ("unavailable", UpstreamUnavailable, False),
        ("invalid-error-payload", UpstreamUnavailable, False),
        ("rate-limit", RateLimitExceeded, False),
        ("malformed", ContractMismatchError, False),
        ("invalid-payload", ContractMismatchError, False),
        ("revoked-400", AuthenticationError, True),
        ("revoked-401", AuthenticationError, True),
        ("invalid-client", ConfigurationError, False),
    ],
)
async def test_refresh_failure_classification_preserves_recoverable_grants(
    failure, expected, deleted
) -> None:
    clock = Clock()
    store = InMemoryTokenStore((b"k" * 32,), clock=clock)
    grant = DownstreamCredentialRecord(
        principal_id="account",
        access_token="synthetic-old-access",
        refresh_token="synthetic-old-refresh",
        access_expires_at=clock.now - 1,
        refresh_after=clock.now - 1,
        email="verified@example.test",
    )
    await store.put_downstream("account", grant)

    def upstream(request: httpx.Request) -> httpx.Response:
        if failure == "timeout":
            raise httpx.ReadTimeout("synthetic-private-provider-detail", request=request)
        if failure == "transport":
            raise httpx.ConnectError("synthetic-private-provider-detail", request=request)
        if failure == "unavailable":
            return httpx.Response(503, text="synthetic-private-provider-detail")
        if failure == "invalid-error-payload":
            return httpx.Response(
                503, json={"error": {"message": "synthetic-private-provider-detail"}}
            )
        if failure == "rate-limit":
            return httpx.Response(429, text="synthetic-private-provider-detail")
        if failure == "malformed":
            return httpx.Response(200, text="synthetic-private-provider-detail")
        if failure == "invalid-payload":
            return httpx.Response(200, json={"access_token": "bad", "expires_in": True})
        error = "invalid_client" if failure == "invalid-client" else "invalid_grant"
        status = 401 if failure == "revoked-401" else 400
        return httpx.Response(
            status, json={"error": error, "error_description": "synthetic-private-provider-detail"}
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as http:
        with pytest.raises(expected) as captured:
            await _credentials(store, clock, http).resolve(Principal("account"))
    assert "synthetic-private-provider-detail" not in str(captured.value)
    if deleted:
        with pytest.raises(TokenStoreMiss):
            await store.get_downstream("account")
        assert await store.list_due_downstream() == []
    else:
        preserved = await store.get_downstream("account")
        assert preserved.access_token == grant.access_token
        assert preserved.refresh_token == grant.refresh_token
        assert preserved.email == grant.email


async def test_due_refresh_retries_after_lease_without_user_request() -> None:
    clock = Clock()
    store = InMemoryTokenStore((b"k" * 32,), clock=clock)
    await store.put_downstream(
        "account",
        DownstreamCredentialRecord(
            principal_id="account",
            access_token="synthetic-access",
            refresh_token="synthetic-refresh",
            access_expires_at=clock.now + 300,
            refresh_after=clock.now - 1,
        ),
    )
    calls = []

    def upstream(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(503, json={"error": "temporarily_unavailable"})
        return httpx.Response(200, json={"access_token": "renewed", "expires_in": 3600})

    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as http:
        credentials = _credentials(store, clock, http)
        assert await credentials.refresh_due() == 0
        assert (await store.get_downstream("account")).refresh_token == "synthetic-refresh"
        assert await credentials.refresh_due() == 0
        assert len(calls) == 1
        clock.now += 301
        assert await credentials.refresh_due() == 1
    refreshed = await store.get_downstream("account")
    assert refreshed.access_token == "renewed"
    assert refreshed.refresh_after is not None and refreshed.refresh_after > clock.now
    assert await store.list_due_downstream() == []


@pytest.mark.parametrize("rejected", [False, True])
async def test_revocation_during_refresh_does_not_resurrect_the_grant(rejected: bool) -> None:
    clock = Clock()
    store = InMemoryTokenStore((b"k" * 32,), clock=clock)
    grant = DownstreamCredentialRecord(
        principal_id="account",
        access_token="synthetic-access",
        refresh_token="synthetic-refresh",
        access_expires_at=clock.now - 1,
        refresh_after=clock.now - 1,
    )
    await store.put_downstream("account", grant)

    async def upstream(_request):
        await store.delete_downstream("account")
        if rejected:
            return httpx.Response(400, json={"error": "invalid_grant"})
        return httpx.Response(200, json={"access_token": "renewed", "expires_in": 3600})

    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as http:
        with pytest.raises(AuthenticationError):
            await _credentials(store, clock, http).resolve(Principal("account"))
    with pytest.raises(TokenStoreMiss):
        await store.get_downstream("account")
    assert await store.list_due_downstream() == []


async def test_old_refresh_failure_does_not_delete_a_new_authorization() -> None:
    clock = Clock()
    store = InMemoryTokenStore((b"k" * 32,), clock=clock)
    old = DownstreamCredentialRecord(
        principal_id="account",
        access_token="old",
        refresh_token="old-refresh",
        access_expires_at=clock.now - 1,
        refresh_after=clock.now - 1,
    )
    fresh = old.model_copy(
        update={
            "access_token": "new-authorization",
            "refresh_token": "new-refresh",
            "access_expires_at": clock.now + 3600,
            "refresh_after": clock.now + 3000,
        }
    )
    await store.put_downstream("account", old)

    async def upstream(_request):
        await store.put_downstream("account", fresh)
        return httpx.Response(400, json={"error": "invalid_grant"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(upstream)) as http:
        resolved = await _credentials(store, clock, http).resolve(Principal("account"))
    assert resolved.token == "new-authorization"
    assert await store.get_downstream("account") == fresh


def test_refresh_schedule_respects_access_expiry_and_sixty_day_inactivity_cap() -> None:
    now = 1_000_000.0
    assert now < next_refresh_time(now, now + 3600) < now + 3600
    assert now < next_refresh_time(now, now + 10) < now + 10
    assert now < next_refresh_time(now, None) <= now + 60 * DAY
    assert now < next_refresh_time(now, now + 365 * DAY) <= now + 60 * DAY


def _settings(**policy) -> Settings:
    return Settings(
        _env_file=None,
        mcp_transport="streamable-http",
        mcp_auth_mode="multi-user",
        yandex_auth_mode="multi-user",
        yandex_oauth_client_id="synthetic-yandex-client",
        yandex_oauth_client_secret="synthetic-yandex-secret",
        mcp_issuer_url="https://mcp.example",
        mcp_resource_server_url="https://mcp.example/mcp",
        mcp_oauth_callback_url="https://mcp.example/oauth/yandex/callback",
        yandex_disk_enabled=False,
        yandex_wiki_enabled=False,
        **policy,
    )


async def test_wire_registration_advertises_non_expiring_secret_by_default() -> None:
    application = create_application(_settings())
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_http_app(application)),
        base_url="https://mcp.example",
    ) as http:
        response = await http.post(
            "/register",
            json={
                "redirect_uris": ["https://client.example/callback"],
                "token_endpoint_auth_method": "client_secret_post",
            },
        )
    assert response.status_code == 201, response.text
    assert response.json()["client_secret_expires_at"] == 0
    await application.close()


async def test_lifespan_starts_refresh_and_cancels_it_before_closing_resources() -> None:
    started, cancelled = asyncio.Event(), asyncio.Event()
    closed_after_cancellation = []

    class TrackedStore(InMemoryTokenStore):
        async def close(self) -> None:
            closed_after_cancellation.append(cancelled.is_set())
            await super().close()

    store = TrackedStore((b"k" * 32,))
    await store.put_downstream(
        "account",
        DownstreamCredentialRecord(
            principal_id="account",
            access_token="synthetic-expired-access",
            refresh_token="synthetic-refresh",
            access_expires_at=1,
            refresh_after=1,
        ),
    )

    async def upstream(request: httpx.Request) -> httpx.Response:
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()
        raise AssertionError("The pending refresh must be cancelled at lifespan exit.")

    http = httpx.AsyncClient(transport=httpx.MockTransport(upstream))
    application = create_application(
        _settings(),
        ApplicationDependencies(
            auth_store_factory=lambda: store,
            oauth_http_client_factory=lambda: http,
        ),
    )
    async with asyncio.timeout(2):
        async with application.lifespan():
            await started.wait()
    assert cancelled.is_set()
    assert closed_after_cancellation == [True]
    assert http.is_closed
