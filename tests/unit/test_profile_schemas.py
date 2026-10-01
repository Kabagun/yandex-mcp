import json
from pathlib import Path

import pytest

from scripts.generate_schema_snapshots import mail_schemas
from yandex_workspace_mcp.config import Settings
from yandex_workspace_mcp.server import create_application


@pytest.mark.asyncio
async def test_mail_public_models_and_mcp_contract_snapshot():
    expected = json.loads(
        Path("tests/snapshots/mail_tool_schemas.json").read_text(encoding="utf-8")
    )
    assert await mail_schemas() == expected


@pytest.mark.asyncio
@pytest.mark.parametrize("profile", ["disk", "mail", "workspace"])
async def test_profile_tool_has_strict_chatgpt_account_schema(profile):
    application = create_application(
        Settings(
            mcp_profile=profile,
            mcp_transport="streamable-http",
            mcp_auth_mode="multi-user",
            yandex_auth_mode="multi-user",
            yandex_oauth_client_id="schema-only",
            yandex_oauth_client_secret="schema-only",
            mcp_oauth_callback_url="http://localhost:18000/oauth/yandex/callback",
        )
    )
    tools = {tool.name: tool for tool in await application.mcp_server.list_tools()}
    tool = tools["get_profile"]
    assert tool.meta == {
        "openai/profile": True,
        "securitySchemes": [{"type": "oauth2", "scopes": []}],
    }
    assert tool.input_schema["properties"] == {}
    assert tool.input_schema["additionalProperties"] is False
    schema = tool.output_schema
    assert schema and schema["type"] == "object" and schema["additionalProperties"] is False
    assert schema["required"] == ["id"]
    assert schema["properties"]["id"]["minLength"] == 1
    assert schema["properties"]["id"]["pattern"] == r"\S"
    assert set(schema["properties"]) == {"id", "name", "email", "nickname"}
    for field in schema["properties"].values():
        assert field["type"] == "string"
        assert "anyOf" not in field and "default" not in field


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "values",
    [
        {"yandex_oauth_token": "static-yandex"},
        {"yandex_oauth_token": "static-yandex", "mcp_auth_token": "static-mcp"},
        {"yandex_auth_mode": "iam", "yandex_iam_token": "iam-token", "yandex_iam_org_id": "org"},
    ],
)
async def test_legacy_authentication_modes_do_not_publish_account_profile(values):
    application = create_application(Settings(**values))
    assert "get_profile" not in {tool.name for tool in await application.mcp_server.list_tools()}
