from typing import Any

import pytest
from pydantic import SecretStr

from yandex_workspace_mcp.config import Settings


def _all_enabled_settings() -> Settings:
    return Settings(
        yandex_oauth_token=SecretStr("token"),
        disk_allowed_roots=["/"],
        wiki_allowed_roots=["/"],
        disk_read=True,
        disk_write=True,
        disk_delete=True,
        wiki_read=True,
        wiki_write=True,
        wiki_delete=True,
    )


@pytest.mark.asyncio
async def test_increment_one_preserves_fifteen_tool_compatibility_surface() -> None:
    from yandex_workspace_mcp.server import create_application

    application = create_application(_all_enabled_settings())
    tools = await application.mcp_server.list_tools()

    compatibility = {
        "search",
        "fetch",
        "disk_list",
        "disk_get_metadata",
        "disk_read",
        "disk_upload",
        "disk_create_folder",
        "disk_copy",
        "disk_move",
        "disk_delete",
        "wiki_search",
        "wiki_get_page",
        "wiki_get_tree",
        "wiki_create_page",
        "wiki_update_page",
    }
    assert compatibility <= {tool.name for tool in tools}


DISK_READ_TOOLS = {
    "disk_info",
    "disk_list",
    "disk_recent",
    "disk_search",
    "disk_get_metadata",
    "disk_get_download_url",
    "disk_read",
    "disk_list_trash",
}
DISK_WRITE_TOOLS = {
    "disk_upload",
    "disk_upload_file",
    "disk_create_folder",
    "disk_copy",
    "disk_move",
    "disk_rename",
    "disk_publish",
    "disk_unpublish",
}
DISK_DELETE_TOOLS = {"disk_delete", "disk_restore_from_trash"}
DISK_LOCAL_JOB_TOOLS = {
    "disk_upload_local_file",
    "disk_upload_local_file_background",
    "disk_get_upload_status",
    "disk_list_upload_jobs",
}


async def _disk_tools(settings: Settings):
    from yandex_workspace_mcp.server import create_application

    application = create_application(settings)
    return {
        tool.name: tool
        for tool in await application.mcp_server.list_tools()
        if tool.name.startswith("disk_")
    }


@pytest.mark.asyncio
async def test_exact_disk_tool_sets_and_approved_total_matrix(tmp_path) -> None:
    read_only = Settings(
        yandex_oauth_token=SecretStr("token"),
        disk_allowed_roots=["/Work"],
        wiki_allowed_roots=["/Team"],
    )
    assert set(await _disk_tools(read_only)) == DISK_READ_TOOLS

    public_read = read_only.model_copy(update={"disk_allowed_public_keys": ["public-key"]})
    assert set(await _disk_tools(public_read)) == DISK_READ_TOOLS | {"disk_get_public_resource"}

    local_all = Settings(
        yandex_oauth_token=SecretStr("token"),
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
    local_disk = await _disk_tools(local_all)
    assert set(local_disk) == (
        DISK_READ_TOOLS
        | DISK_WRITE_TOOLS
        | DISK_DELETE_TOOLS
        | DISK_LOCAL_JOB_TOOLS
        | {"disk_get_public_resource", "disk_upload_from_url"}
    )
    from yandex_workspace_mcp.server import create_application

    assert len(await create_application(local_all).mcp_server.list_tools()) == 54

    remote_all = local_all.model_copy(
        update={
            "mcp_transport": "streamable-http",
            "mcp_token_encryption_keys": [SecretStr("eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg")],
        }
    )
    remote_disk = await _disk_tools(remote_all)
    assert not (set(remote_disk) & DISK_LOCAL_JOB_TOOLS)
    assert len(await create_application(remote_all).mcp_server.list_tools()) == 49


@pytest.mark.asyncio
async def test_disk_annotations_and_scope_metadata(tmp_path) -> None:
    tools = await _disk_tools(
        Settings(
            yandex_oauth_token=SecretStr("token"),
            disk_allowed_roots=["/"],
            wiki_read=False,
            disk_write=True,
            disk_delete=True,
            disk_upload_allowed_dirs=[str(tmp_path)],
            disk_upload_url_allowed_hosts=["downloads.example.test"],
            disk_allowed_public_keys=["public-key"],
        )
    )
    for name, tool in tools.items():
        assert tool.annotations is not None
        expected_scope = (
            "workspace:delete"
            if name in DISK_DELETE_TOOLS
            else "workspace:write"
            if name in DISK_WRITE_TOOLS
            or name in DISK_LOCAL_JOB_TOOLS
            or name == "disk_upload_from_url"
            else "workspace:read"
        )
        expected_meta = {"required_scopes": [expected_scope]}
        if name == "disk_upload_file":
            expected_meta["openai/fileParams"] = ["file"]
        assert tool.meta == expected_meta
        assert tool.annotations.destructive_hint is (name in {"disk_delete"})


WIKI_READ_TOOLS = {
    "wiki_search",
    "wiki_get_page",
    "wiki_get_descendants",
    "wiki_get_comments",
    "wiki_get_resources",
    "wiki_get_attachments",
    "wiki_get_grids",
    "wiki_get_grid",
    "wiki_get_tree",
}

WIKI_WRITE_TOOLS = {
    "wiki_create_page",
    "wiki_update_page",
    "wiki_append_page",
    "wiki_clone_page",
    "wiki_add_comment",
    "wiki_recover_page",
    "wiki_create_grid",
    "wiki_update_grid",
    "wiki_copy_grid",
    "wiki_add_grid_rows",
    "wiki_update_grid_cells",
    "wiki_move_grid_row",
    "wiki_add_grid_columns",
    "wiki_move_grid_column",
}

WIKI_DELETE_TOOLS = {
    "wiki_delete_page",
    "wiki_delete_grid",
    "wiki_delete_grid_rows",
    "wiki_delete_grid_columns",
}

WIKI_DELETE_SCOPE_TOOLS = WIKI_DELETE_TOOLS | {"wiki_recover_page"}


async def _wiki_tools(settings: Settings):
    from yandex_workspace_mcp.server import create_application

    application = create_application(settings)
    return {
        tool.name: tool
        for tool in await application.mcp_server.list_tools()
        if tool.name.startswith("wiki_")
    }


@pytest.mark.asyncio
async def test_exact_wiki_tool_sets_for_read_only_local_and_remote_modes(tmp_path) -> None:
    base: dict[str, Any] = {
        "yandex_oauth_token": SecretStr("token"),
        "disk_read": False,
        "wiki_allowed_roots": ["/Team"],
    }
    read_only = await _wiki_tools(Settings(**base))
    assert set(read_only) == WIKI_READ_TOOLS

    local = await _wiki_tools(
        Settings(
            **base,
            wiki_write=True,
            wiki_delete=True,
            wiki_upload_allowed_dirs=[str(tmp_path)],
        )
    )
    assert set(local) == (
        WIKI_READ_TOOLS | WIKI_WRITE_TOOLS | WIKI_DELETE_TOOLS | {"wiki_upload_attachment"}
    )
    assert len(local) == 28

    remote = await _wiki_tools(
        Settings(
            **base,
            mcp_transport="streamable-http",
            wiki_write=True,
            wiki_delete=True,
            mcp_token_encryption_keys=[SecretStr("eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg")],
        )
    )
    assert set(remote) == WIKI_READ_TOOLS | WIKI_WRITE_TOOLS | WIKI_DELETE_TOOLS
    assert len(remote) == 27


@pytest.mark.asyncio
async def test_wiki_tool_annotations_and_scope_metadata(tmp_path) -> None:
    tools = await _wiki_tools(
        Settings(
            yandex_oauth_token=SecretStr("token"),
            disk_read=False,
            wiki_allowed_roots=["/Team"],
            wiki_write=True,
            wiki_delete=True,
            wiki_upload_allowed_dirs=[str(tmp_path)],
        )
    )
    for name, tool in tools.items():
        assert tool.annotations is not None
        assert tool.meta == {
            "required_scopes": [
                "workspace:delete"
                if name in WIKI_DELETE_SCOPE_TOOLS
                else "workspace:write"
                if name in WIKI_WRITE_TOOLS or name == "wiki_upload_attachment"
                else "workspace:read"
            ]
        }
        if name in WIKI_READ_TOOLS:
            assert tool.annotations.read_only_hint is True
            assert tool.annotations.idempotent_hint is True
            assert tool.annotations.destructive_hint is False
        elif name in WIKI_DELETE_TOOLS:
            assert tool.annotations.read_only_hint is False
            assert tool.annotations.destructive_hint is True
            assert tool.annotations.idempotent_hint is False
        else:
            assert tool.annotations.read_only_hint is False
            assert tool.annotations.destructive_hint is False
            assert tool.annotations.idempotent_hint is False


def test_scope_hierarchy_and_server_permission_ceiling() -> None:
    from yandex_workspace_mcp.auth.scopes import (
        OperationClass,
        WorkspacePrincipal,
        require_scope,
        scopes_for_permissions,
    )

    scopes = scopes_for_permissions(can_read=True, can_write=True, can_delete=False)
    principal = WorkspacePrincipal(principal_id="local", scopes=scopes)

    require_scope(principal, OperationClass.READ)
    require_scope(principal, OperationClass.WRITE)
    with pytest.raises(Exception, match="Permission denied"):
        require_scope(principal, OperationClass.DELETE)
