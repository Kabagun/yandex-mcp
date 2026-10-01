from unittest.mock import AsyncMock

import httpx
import pytest
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from pydantic import SecretStr

from yandex_workspace_mcp.auth.models import DownstreamCredentialRecord
from yandex_workspace_mcp.config import Settings


def _settings() -> Settings:
    return Settings(
        yandex_oauth_token=SecretStr("token"),
        disk_allowed_roots=["/Work"],
        wiki_allowed_roots=["Team"],
        disk_read=True,
        wiki_read=True,
    )


class CloseTrackedClient:
    def __init__(self) -> None:
        self.close_count = 0

    async def close(self) -> None:
        self.close_count += 1


def test_create_application_has_no_client_factory_side_effects() -> None:
    from yandex_workspace_mcp.server import ApplicationDependencies, create_application

    calls = 0

    def factory():
        nonlocal calls
        calls += 1
        return CloseTrackedClient()

    application = create_application(
        _settings(),
        ApplicationDependencies(
            disk_client_factory=factory,
            wiki_client_factory=factory,
            cursor_keys=(b"k" * 32,),
        ),
    )

    assert calls == 0
    assert application.state is None


@pytest.mark.asyncio
async def test_lifespan_opens_and_closes_clients_exactly_once() -> None:
    from yandex_workspace_mcp.server import ApplicationDependencies, create_application

    disk = CloseTrackedClient()
    wiki = CloseTrackedClient()
    application = create_application(
        _settings(),
        ApplicationDependencies(
            disk_client_factory=lambda: disk,
            wiki_client_factory=lambda: wiki,
            cursor_keys=(b"k" * 32,),
            service_factory=lambda **_kwargs: (AsyncMock(), AsyncMock(), AsyncMock()),
        ),
    )

    async with application.lifespan() as state:
        assert application.state is state
        assert state.disk_client is disk
        assert state.wiki_client is wiki

    await application.close()
    assert disk.close_count == 1
    assert wiki.close_count == 1


@pytest.mark.asyncio
async def test_write_only_disk_opens_and_closes_both_transfer_policies() -> None:
    from yandex_workspace_mcp.server import ApplicationDependencies, create_application

    disk, signed, source = (CloseTrackedClient() for _ in range(3))
    application = create_application(
        Settings(
            yandex_oauth_token="token",
            disk_allowed_roots=["/Work"],
            disk_read=False,
            disk_write=True,
            yandex_wiki_enabled=False,
        ),
        ApplicationDependencies(
            disk_client_factory=lambda: disk,
            signed_client_factory=lambda: signed,
            file_source_client_factory=lambda: source,
        ),
    )
    async with application.lifespan() as state:
        assert state.signed_client is signed
        assert state.file_source_client is source
        assert state.disk_service is not None
        assert state.disk_service.file_source_client is source
    await application.close()
    assert disk.close_count == signed.close_count == source.close_count == 1


@pytest.mark.asyncio
async def test_partial_startup_closes_already_opened_client() -> None:
    from yandex_workspace_mcp.server import ApplicationDependencies, create_application

    disk = CloseTrackedClient()

    def fail():
        raise RuntimeError("factory failed")

    application = create_application(
        _settings(),
        ApplicationDependencies(
            disk_client_factory=lambda: disk,
            wiki_client_factory=fail,
            cursor_keys=(b"k" * 32,),
        ),
    )

    with pytest.raises(RuntimeError, match="factory failed"):
        async with application.lifespan():
            pass

    assert disk.close_count == 1


@pytest.mark.asyncio
async def test_two_factories_do_not_share_state() -> None:
    from yandex_workspace_mcp.server import ApplicationDependencies, create_application

    deps = ApplicationDependencies(
        disk_client_factory=CloseTrackedClient,
        wiki_client_factory=CloseTrackedClient,
        cursor_keys=(b"k" * 32,),
        service_factory=lambda **_kwargs: (AsyncMock(), AsyncMock(), AsyncMock()),
    )
    first = create_application(_settings(), deps)
    second = create_application(_settings(), deps)

    async with first.lifespan() as first_state, second.lifespan() as second_state:
        assert first_state is not second_state
        assert first_state.disk_client is not second_state.disk_client


@pytest.mark.asyncio
async def test_multi_user_lifespan_resolves_per_request_downstream_credentials() -> None:
    from yandex_workspace_mcp.server import ApplicationDependencies, create_application

    settings = Settings(
        mcp_transport="streamable-http",
        mcp_auth_mode="multi-user",
        yandex_auth_mode="multi-user",
        yandex_oauth_client_id="yandex-client",
        yandex_oauth_client_secret=SecretStr("yandex-secret"),
        mcp_oauth_callback_url="http://localhost:8000/oauth/yandex/callback",
        yandex_disk_enabled=False,
        yandex_wiki_enabled=False,
    )
    oauth_http = httpx.AsyncClient(transport=httpx.MockTransport(lambda _: httpx.Response(500)))
    application = create_application(
        settings,
        ApplicationDependencies(
            cursor_keys=(b"k" * 32,),
            oauth_http_client_factory=lambda: oauth_http,
        ),
    )
    assert application.auth_store is not None
    assert application.oauth_provider is not None

    async with application.lifespan() as state:
        assert state.upload_job_store is None
        assert state.auth_store is not None
        principal_id = "principal-a"
        await state.auth_store.put_downstream(
            principal_id,
            DownstreamCredentialRecord(
                principal_id=principal_id,
                access_token="downstream-a",
                expires_at=4_000_000_000,
                access_expires_at=4_000_000_000,
            ),
        )
        context = auth_context_var.set(
            AuthenticatedUser(
                AccessToken(
                    token="mcp-token",
                    client_id="mcp-client",
                    subject=principal_id,
                    scopes=["workspace:read"],
                )
            )
        )
        try:
            credentials = await application._request_credentials(include_organization=True)
        finally:
            auth_context_var.reset(context)
        assert credentials.authorization == "OAuth downstream-a"
        assert application.principal.principal_id == "unauthenticated"
        assert application.principal.scopes == frozenset()

    assert oauth_http.is_closed
