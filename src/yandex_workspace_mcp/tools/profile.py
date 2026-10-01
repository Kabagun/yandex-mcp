"""Authenticated account discovery for ChatGPT multiple-account connections."""

import json
from collections.abc import Callable
from typing import Annotated, Protocol

from mcp.server.mcpserver.tools import Tool
from mcp.types import CallToolResult, TextContent, ToolAnnotations

from ..auth.models import Principal
from ..models.profile import AccountProfile
from ..services.profile import ProfileService


class ProfileApplication(Protocol):
    @property
    def principal(self) -> Principal: ...

    def require_profile_service(self) -> ProfileService: ...


def create_profile_tool(application_provider: Callable[[], ProfileApplication]) -> Tool:
    """Build the no-argument profile contract for an authenticated OAuth endpoint."""

    async def get_profile() -> Annotated[CallToolResult, AccountProfile]:
        application = application_provider()
        profile = await application.require_profile_service().get_profile(application.principal)
        payload = profile.model_dump(mode="json", exclude_none=True)
        return CallToolResult(
            content=[TextContent(type="text", text=json.dumps(payload, ensure_ascii=False))],
            structured_content=payload,
        )

    tool = Tool.from_function(
        get_profile,
        name="get_profile",
        description="Get the current authenticated Yandex account profile",
        annotations=ToolAnnotations(
            read_only_hint=True,
            destructive_hint=False,
            idempotent_hint=True,
            open_world_hint=False,
        ),
        meta={
            "openai/profile": True,
            "securitySchemes": [{"type": "oauth2", "scopes": []}],
        },
    )
    # The SDK decorator defaults to ignoring extra arguments. Configure this tool's
    # own generated model so discovery and runtime both reject account selectors.
    arguments = tool.fn_metadata.arg_model
    arguments.model_config["extra"] = "forbid"
    arguments.model_rebuild(force=True)
    tool.parameters = arguments.model_json_schema(by_alias=True)
    return tool
