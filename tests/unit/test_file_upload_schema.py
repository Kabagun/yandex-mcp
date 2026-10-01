import pytest
from pydantic import SecretStr, ValidationError

from yandex_workspace_mcp.config import Settings
from yandex_workspace_mcp.models.disk import OpenAIFile
from yandex_workspace_mcp.server import create_application
from yandex_workspace_mcp.tools.disk import WRITE_ANNOTATIONS


@pytest.mark.parametrize("profile", ["disk", "workspace"])
async def test_chatgpt_file_tool_declares_exact_openai_contract(profile) -> None:
    application = create_application(
        Settings(
            mcp_profile=profile,
            mcp_transport="streamable-http",
            yandex_oauth_token=SecretStr("token"),
            disk_allowed_roots=["/Work"],
            disk_write=True,
        )
    )
    tools = {tool.name: tool for tool in await application.mcp_server.list_tools()}
    tool = tools["disk_upload_file"]
    assert tool.meta == {"required_scopes": ["workspace:write"], "openai/fileParams": ["file"]}
    assert tool.annotations == WRITE_ANNOTATIONS
    schema = tool.input_schema
    assert set(schema["properties"]) == {"file", "destination_path", "overwrite"}
    assert schema["required"] == ["file", "destination_path"]
    assert schema["properties"]["overwrite"]["default"] is False
    file_schema = schema["$defs"]["OpenAIFile"]
    assert schema["properties"]["file"]["$ref"] == "#/$defs/OpenAIFile"
    assert file_schema["type"] == "object" and file_schema["additionalProperties"] is False
    assert file_schema["required"] == ["download_url", "file_id"]
    assert set(file_schema["properties"]) == {"download_url", "file_id", "mime_type", "file_name"}
    for field in file_schema["properties"].values():
        assert field["type"] == "string"
        assert "anyOf" not in field and "default" not in field
    assert tools["disk_upload"].description is not None
    assert "disk_upload_file" in tools["disk_upload"].description
    assert tools["disk_upload"].input_schema["properties"]["overwrite"]["default"] is True


@pytest.mark.parametrize(
    "values", [{"mcp_profile": "mail", "mail_write": True}, {"mcp_profile": "disk"}]
)
async def test_file_tool_absent_from_mail_and_read_only_disk(values) -> None:
    application = create_application(
        Settings(
            mcp_transport="streamable-http",
            mcp_auth_mode="multi-user",
            yandex_auth_mode="multi-user",
            yandex_oauth_client_id="schema-only",
            yandex_oauth_client_secret="schema-only",
            mcp_oauth_callback_url="http://localhost:18000/oauth/yandex/callback",
            **values,
        )
    )
    assert "disk_upload_file" not in {
        tool.name for tool in await application.mcp_server.list_tools()
    }


@pytest.mark.parametrize(
    "values",
    [
        {"download_url": "https://files.example.test/file"},
        {"file_id": "opaque"},
        {"download_url": "https://files.example.test/file", "file_id": 123},
        {
            "download_url": "https://files.example.test/file",
            "file_id": "opaque",
            "path": "/etc/passwd",
        },
    ],
)
def test_openai_file_runtime_contract_is_strict(values) -> None:
    with pytest.raises(ValidationError):
        OpenAIFile.model_validate(values)
