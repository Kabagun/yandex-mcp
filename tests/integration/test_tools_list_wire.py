"""Exercise SDK result validation on the authenticated HTTP wire, not list_tools alone."""

from typing import Any, cast
from unittest.mock import AsyncMock, call

import httpx
import pytest
from mcp.types import CLIENT_CAPABILITIES_META_KEY, PROTOCOL_VERSION_META_KEY
from mcp_types.version import HANDSHAKE_PROTOCOL_VERSIONS, MODERN_PROTOCOL_VERSIONS

from yandex_workspace_mcp.auth.models import AccessTokenRecord
from yandex_workspace_mcp.config import Settings
from yandex_workspace_mcp.server import ApplicationDependencies, create_application, create_http_app

PROTOCOLS = (*HANDSHAKE_PROTOCOL_VERSIONS, *MODERN_PROTOCOL_VERSIONS)


def _settings(profile: str) -> Settings:
    return Settings(
        mcp_profile=profile,
        mcp_transport="streamable-http",
        mcp_auth_mode="multi-user",
        yandex_auth_mode="multi-user",
        yandex_oauth_client_id="wire-test-client",
        yandex_oauth_client_secret="wire-test-secret",
        mcp_issuer_url="http://localhost:18000",
        mcp_resource_server_url="http://localhost:18000/mcp",
        mcp_oauth_callback_url="http://localhost:18000/oauth/yandex/callback",
        mcp_token_encryption_keys=["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"],
        disk_allowed_roots=["/"],
        wiki_allowed_roots=["/"],
        disk_write=True,
        disk_delete=True,
        wiki_write=profile == "workspace",
        wiki_delete=profile == "workspace",
        mail_write=True,
        mail_delete=True,
    )


@pytest.mark.parametrize("profile", ["disk", "mail", "workspace"])
@pytest.mark.parametrize("protocol", PROTOCOLS)
async def test_authenticated_tools_list_serializes_for_every_supported_protocol(
    profile: str,
    protocol: str,
) -> None:
    clients: list[AsyncMock] = []
    upstream_requests: list[httpx.Request] = []

    def client_factory() -> AsyncMock:
        client = AsyncMock()
        clients.append(client)
        return client

    def reject_upstream(request: httpx.Request) -> httpx.Response:
        upstream_requests.append(request)
        raise AssertionError("Discovery must not contact Yandex")

    application = create_application(
        _settings(profile),
        ApplicationDependencies(
            disk_client_factory=client_factory,
            wiki_client_factory=client_factory,
            mail_client_factory=client_factory,
            signed_client_factory=client_factory,
            oauth_http_client_factory=lambda: httpx.AsyncClient(
                transport=httpx.MockTransport(reject_upstream)
            ),
        ),
    )
    http_app = create_http_app(application)
    assert application.auth_store is not None and application.oauth_provider is not None
    scopes = tuple(application.oauth_provider.valid_scopes)
    await application.auth_store.put_access_token(
        "synthetic-wire-grant",
        AccessTokenRecord(
            client_id="wire-client",
            subject="wire-principal",
            scopes=scopes,
            resource=application.settings.mcp_resource_server_url,
            expires_at=4_000_000_000,
        ),
    )
    headers = {
        "Authorization": "Bearer synthetic-wire-grant",
        "Accept": "application/json, text/event-stream",
    }
    # Modern MCP uses per-request envelopes. Initialize the supported legacy
    # bridge first, then exercise the modern request through the same HTTP app.
    handshake_version = (
        HANDSHAKE_PROTOCOL_VERSIONS[-1] if protocol in MODERN_PROTOCOL_VERSIONS else protocol
    )
    async with (
        cast(Any, http_app).router.lifespan_context(http_app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=http_app),
            base_url="http://localhost:18000",
            headers=headers,
        ) as http,
    ):
        initialized = await http.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": handshake_version,
                    "capabilities": {},
                    "clientInfo": {"name": "wire-regression", "version": "1"},
                },
            },
        )
        assert initialized.status_code == 200
        initialized_body = initialized.json()
        assert "error" not in initialized_body, initialized_body
        assert initialized_body["result"]["protocolVersion"] == handshake_version
        http.headers["MCP-Protocol-Version"] = handshake_version
        notified = await http.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            },
        )
        assert notified.status_code == 202
        params: dict[str, Any] = {}
        if protocol in MODERN_PROTOCOL_VERSIONS:
            http.headers["MCP-Protocol-Version"] = protocol
            http.headers["MCP-Method"] = "tools/list"
            params["_meta"] = {
                PROTOCOL_VERSION_META_KEY: protocol,
                CLIENT_CAPABILITIES_META_KEY: {},
            }
        response = await http.post(
            "/mcp",
            json={
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": params,
            },
        )
        assert response.status_code == 200
        body = response.json()
        assert "error" not in body, body
        assert body["id"] == 2
        if protocol in MODERN_PROTOCOL_VERSIONS:
            assert body["result"]["resultType"] == "complete"
        tools = body["result"]["tools"]
        expected = {tool.name for tool in await application.mcp_server.list_tools()}
        assert {tool["name"] for tool in tools} == expected
        assert tools
        if profile == "mail":
            assert all(tool["name"].startswith("mail_") for tool in tools)
        if profile == "disk":
            assert not any(tool["name"].startswith(("mail_", "wiki_")) for tool in tools)
        for tool in tools:
            assert tool["inputSchema"]["type"] == "object"
            if "outputSchema" in tool:
                assert tool["outputSchema"]["type"] == "object"
        # Recursive schemas must retain their definitions and reference, not be
        # replaced by an unconstrained object just to make serialization pass.
        if (
            protocol in ("2025-06-18", "2025-11-25", *MODERN_PROTOCOL_VERSIONS)
            and profile != "mail"
        ):
            recent = next(tool for tool in tools if tool["name"] == "disk_recent")
            schema = recent["outputSchema"]
            assert schema["$ref"] == "#/$defs/DiskResourcePage"
            assert schema["$defs"]["DiskResourcePage"]["properties"]["items"]["items"] == {
                "$ref": "#/$defs/DiskResource"
            }
            assert schema["$defs"]["DiskResource"]["additionalProperties"] is False
    assert not upstream_requests
    assert all(client.method_calls == [call.close()] for client in clients)
