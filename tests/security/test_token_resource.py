import pytest
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend
from pydantic import AnyHttpUrl
from starlette.requests import HTTPConnection

from yandex_workspace_mcp.config import Settings
from yandex_workspace_mcp.server import StaticTokenVerifier, create_application


@pytest.mark.parametrize("profile", ["static", "disk", "mail"])
def test_http_server_enables_resource_validation_for_every_auth_profile(profile: str) -> None:
    common = {
        "_env_file": None,
        "mcp_transport": "streamable-http",
        "mcp_issuer_url": "https://mcp.example",
        "mcp_resource_server_url": "https://mcp.example/mcp",
    }
    if profile == "static":
        settings = Settings(
            **common,
            mcp_auth_mode="static",
            mcp_auth_token="synthetic-mcp-token",
            yandex_disk_enabled=False,
            yandex_wiki_enabled=False,
        )
    else:
        settings = Settings(
            **common,
            mcp_profile=profile,
            mcp_auth_mode="multi-user",
            yandex_auth_mode="multi-user",
            yandex_oauth_client_id="synthetic-yandex-client",
            yandex_oauth_client_secret="synthetic-yandex-secret",
            mcp_oauth_callback_url="https://mcp.example/oauth/yandex/callback",
        )
    application = create_application(settings)
    assert application.mcp_server.settings.auth is not None
    assert application.mcp_server.settings.auth.validate_token_resource is True


@pytest.mark.parametrize(
    "resource,accepted",
    [
        ("https://mcp.example/mcp", True),
        ("https://other.example/mcp", False),
        (None, False),
    ],
)
async def test_static_token_resource_is_enforced_by_sdk(resource, accepted: bool) -> None:
    verifier = StaticTokenVerifier("synthetic-mcp-token", resource=resource)
    backend = BearerAuthBackend(verifier, resource_server_url=AnyHttpUrl("https://mcp.example/mcp"))
    connection = HTTPConnection(
        {"type": "http", "headers": [(b"authorization", b"Bearer synthetic-mcp-token")]}
    )
    assert (await backend.authenticate(connection) is not None) is accepted


async def test_application_static_verifier_binds_tokens_to_its_configured_resource() -> None:
    application = create_application(
        Settings(
            _env_file=None,
            mcp_transport="streamable-http",
            mcp_auth_mode="static",
            mcp_auth_token="synthetic-mcp-token",
            mcp_resource_server_url="https://mcp.example/configured-resource",
            yandex_disk_enabled=False,
            yandex_wiki_enabled=False,
        )
    )
    verifier = application.mcp_server._token_verifier
    assert verifier is not None
    token = await verifier.verify_token("synthetic-mcp-token")
    assert token is not None and token.resource == "https://mcp.example/configured-resource"
    assert await verifier.verify_token("unrecognized-token") is None
