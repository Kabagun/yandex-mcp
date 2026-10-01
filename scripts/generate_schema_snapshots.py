import asyncio
import json
from pathlib import Path

from yandex_workspace_mcp.models import disk, mail, wiki
from yandex_workspace_mcp.models.base import PublicModel

WIKI_INPUT_MODELS = (
    "WikiSearchInput",
    "PageLocatorInput",
    "DescendantsInput",
    "PageListInput",
    "PageResourceListInput",
    "GridGetInput",
    "PageCreateInput",
    "PageUpdateInput",
    "PageAppendInput",
    "PageCloneInput",
    "CommentCreateInput",
    "PageDeleteInput",
    "PageRecoverInput",
    "WikiAttachmentUploadInput",
    "GridCreateInput",
    "GridUpdateInput",
    "GridCopyInput",
    "GridDeleteInput",
    "GridRowsAddInput",
    "GridCellsUpdateInput",
    "GridRowsDeleteInput",
    "GridRowMoveInput",
    "GridColumnsAddInput",
    "GridColumnsDeleteInput",
    "GridColumnMoveInput",
)

DISK_MODELS = (
    "DiskListInput",
    "DiskRecentInput",
    "DiskSearchInput",
    "DiskPathInput",
    "DiskDeleteInput",
    "DiskCopyInput",
    "DiskMoveInput",
    "DiskRenameInput",
    "DiskLocalUploadInput",
    "OpenAIFile",
    "DiskFileUploadInput",
    "UploadJobIDInput",
    "UploadJobListInput",
    "DiskURLUploadInput",
    "DiskPublicResourceInput",
    "DiskTrashListInput",
    "DiskTrashRestoreInput",
    "DiskInfo",
    "DiskResource",
    "DiskPublicResource",
    "DiskResourcePage",
    "DiskSearchResponse",
    "DiskOperationResponse",
    "DiskLinkResponse",
    "UploadJobResponse",
    "UploadJobListResponse",
)


async def mail_schemas() -> dict:
    """Return Mail model and actual MCP tool schemas for contract drift checks."""
    from yandex_workspace_mcp.config import Settings
    from yandex_workspace_mcp.server import create_application

    application = create_application(
        Settings(
            mcp_profile="mail",
            mcp_transport="streamable-http",
            mcp_auth_mode="multi-user",
            yandex_auth_mode="multi-user",
            yandex_oauth_client_id="schema-only",
            yandex_oauth_client_secret="schema-only",
            mcp_oauth_callback_url="http://localhost:18003/oauth/yandex/callback",
            mail_write=True,
            mail_delete=True,
        )
    )
    return {
        "models": {
            name: model.model_json_schema()
            for name, model in vars(mail).items()
            if isinstance(model, type)
            and issubclass(model, PublicModel)
            and model.__module__ == mail.__name__
        },
        "tools": {
            tool.name: tool.model_dump(mode="json", exclude_none=True)
            for tool in await application.mcp_server.list_tools()
        },
    }


def main() -> None:
    output = Path("tests/snapshots/wiki_tool_schemas.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    schemas = {name: getattr(wiki, name).model_json_schema() for name in WIKI_INPUT_MODELS}
    output.write_text(
        json.dumps(schemas, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    disk_output = Path("tests/snapshots/disk_tool_schemas.json")
    disk_schemas = {name: getattr(disk, name).model_json_schema() for name in DISK_MODELS}
    disk_output.write_text(
        json.dumps(disk_schemas, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    Path("tests/snapshots/mail_tool_schemas.json").write_text(
        json.dumps(asyncio.run(mail_schemas()), ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
