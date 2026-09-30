import hmac
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import pytest
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken
from pydantic import SecretStr

from yandex_workspace_mcp.auth.scopes import WorkspaceScope
from yandex_workspace_mcp.config import Settings
from yandex_workspace_mcp.models.errors import PermissionDenied
from yandex_workspace_mcp.server import StaticTokenVerifier, create_application


@pytest.mark.asyncio
async def test_static_verifier_uses_constant_time_compare_and_effective_scopes() -> None:
    verifier = StaticTokenVerifier("mcp-secret", [WorkspaceScope.READ.value])
    with patch.object(hmac, "compare_digest", wraps=hmac.compare_digest) as compare:
        token = await verifier.verify_token("mcp-secret")
    compare.assert_called_once_with("mcp-secret", "mcp-secret")
    assert token is not None
    assert token.scopes == ["workspace:read"]
    assert "mcp-secret" not in repr(verifier)
    assert await verifier.verify_token("yandex-secret") is None


@pytest.mark.asyncio
async def test_tool_scope_is_resolved_from_current_mcp_request_before_service_call() -> None:
    application = create_application(
        Settings(
            yandex_oauth_token=SecretStr("yandex-secret"),
            disk_allowed_roots=["/"],
            disk_write=True,
        )
    )
    tool = application.mcp_server._tool_manager._tools["disk_create_folder"]
    request_token = AccessToken(
        token="opaque-mcp-token",
        client_id="client-a",
        subject="principal-a",
        scopes=[WorkspaceScope.READ.value],
    )
    context = auth_context_var.set(AuthenticatedUser(request_token))
    try:
        with pytest.raises(PermissionDenied):
            await tool.fn(path="/folder")
    finally:
        auth_context_var.reset(context)


def test_configured_static_scope_never_exceeds_server_permissions() -> None:
    application = create_application(
        Settings(
            mcp_auth_mode="static",
            mcp_auth_token="mcp-secret",
            mcp_static_scopes=["workspace:delete"],
            disk_read=True,
            disk_write=False,
            disk_delete=False,
            yandex_disk_enabled=True,
            yandex_wiki_enabled=False,
        )
    )
    verifier = application.mcp_server._token_verifier
    assert isinstance(verifier, StaticTokenVerifier)
    assert verifier.scopes == ["workspace:read"]


def test_authenticated_mode_has_no_local_principal_fallback() -> None:
    application = create_application(
        Settings(
            mcp_transport="streamable-http",
            mcp_auth_mode="static",
            mcp_auth_token="mcp-secret",
            yandex_disk_enabled=False,
            yandex_wiki_enabled=False,
        )
    )

    assert application.principal.scopes == frozenset()
    assert application.principal.principal_id == "unauthenticated"


@pytest.mark.asyncio
async def test_every_registered_tool_declares_one_enforced_workspace_scope(tmp_path) -> None:
    application = create_application(
        Settings(
            yandex_oauth_token=SecretStr("yandex-secret"),
            disk_allowed_roots=["/"],
            wiki_allowed_roots=["/"],
            disk_write=True,
            disk_delete=True,
            wiki_write=True,
            wiki_delete=True,
            disk_upload_allowed_dirs=[str(tmp_path)],
            wiki_upload_allowed_dirs=[str(tmp_path)],
            disk_upload_url_allowed_hosts=["downloads.example.test"],
            disk_allowed_public_keys=["public-key"],
        )
    )

    tools = await application.mcp_server.list_tools()
    assert len(tools) == 53
    for tool in tools:
        assert tool.meta is not None
        scopes = tool.meta.get("required_scopes")
        assert scopes in (["workspace:read"], ["workspace:write"], ["workspace:delete"])


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "tool_name,arguments,service_method,required_scope",
    [
        ("disk_info", {}, "info", WorkspaceScope.READ),
        ("disk_create_folder", {"path": "/folder"}, "create_folder", WorkspaceScope.WRITE),
        ("disk_delete", {"path": "/folder"}, "delete", WorkspaceScope.DELETE),
    ],
)
async def test_each_scope_class_denies_before_service_and_allows_sufficient_scope(
    tool_name: str,
    arguments: dict[str, Any],
    service_method: str,
    required_scope: WorkspaceScope,
) -> None:
    application = create_application(
        Settings(
            mcp_transport="streamable-http",
            mcp_auth_mode="static",
            mcp_auth_token="mcp-secret",
            yandex_oauth_token=SecretStr("yandex-secret"),
            disk_allowed_roots=["/"],
            wiki_read=False,
            disk_write=True,
            disk_delete=True,
        )
    )
    service = AsyncMock()
    application.state = cast(Any, SimpleNamespace(disk_service=service))
    tool = application.mcp_server._tool_manager._tools[tool_name]

    insufficient = auth_context_var.set(
        AuthenticatedUser(
            AccessToken(token="low", client_id="client", scopes=[], subject="principal")
        )
    )
    try:
        with pytest.raises(PermissionDenied):
            await tool.fn(**arguments)
    finally:
        auth_context_var.reset(insufficient)
    getattr(service, service_method).assert_not_awaited()

    sufficient = auth_context_var.set(
        AuthenticatedUser(
            AccessToken(
                token="enough",
                client_id="client",
                scopes=[required_scope.value],
                subject="principal",
            )
        )
    )
    try:
        await tool.fn(**arguments)
    finally:
        auth_context_var.reset(sufficient)
    getattr(service, service_method).assert_awaited_once()
