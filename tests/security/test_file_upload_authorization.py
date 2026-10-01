from types import SimpleNamespace
from typing import cast
from unittest.mock import AsyncMock

import pytest
from mcp.server.auth.middleware.auth_context import auth_context_var
from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
from mcp.server.auth.provider import AccessToken

from yandex_workspace_mcp.config import Settings
from yandex_workspace_mcp.models.disk import OpenAIFile
from yandex_workspace_mcp.models.errors import InvalidPath, PermissionDenied
from yandex_workspace_mcp.server import ApplicationState, create_application
from yandex_workspace_mcp.services.disk import DiskService


@pytest.mark.parametrize(
    "can_write,destination,error",
    [(False, "/Work/file.docx", PermissionDenied), (True, "/Private/file.docx", InvalidPath)],
)
async def test_file_upload_authorizes_write_and_destination_before_source(
    can_write, destination, error
) -> None:
    source = AsyncMock()
    disk = AsyncMock()
    signed = AsyncMock()
    service = DiskService(
        disk,
        ["/Work"],
        True,
        can_write,
        False,
        signed_client=signed,
        file_source_client=source,
    )
    with pytest.raises(error):
        await service.upload_file(
            OpenAIFile(
                download_url="https://files.example.test/private?secret=value",
                file_id="/etc/passwd",
            ),
            destination,
        )
    source.download.assert_not_awaited()
    disk.upload_bytes.assert_not_awaited()
    signed.upload_bytes.assert_not_awaited()


async def test_request_write_scope_checked_before_file_service_or_source() -> None:
    application = create_application(
        Settings(
            mcp_transport="streamable-http",
            mcp_auth_mode="static",
            mcp_auth_token="mcp-secret",
            yandex_oauth_token="yandex-secret",
            disk_allowed_roots=["/Work"],
            disk_write=True,
        )
    )
    service = AsyncMock()
    application.state = cast(ApplicationState, SimpleNamespace(disk_service=service))
    context = auth_context_var.set(
        AuthenticatedUser(AccessToken(token="read", client_id="client", scopes=["workspace:read"]))
    )
    try:
        with pytest.raises(PermissionDenied):
            await application.mcp_server._tool_manager._tools["disk_upload_file"].fn(
                file=OpenAIFile(download_url="https://files.example.test/file", file_id="opaque"),
                destination_path="/Work/file.docx",
            )
    finally:
        auth_context_var.reset(context)
    service.upload_file.assert_not_awaited()
