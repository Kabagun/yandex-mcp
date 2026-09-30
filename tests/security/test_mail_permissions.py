from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, patch

import pytest
from mcp.server import MCPServer

from yandex_workspace_mcp.auth.models import Principal, WorkspaceScope
from yandex_workspace_mcp.models.errors import PermissionDenied, UpstreamTimeout
from yandex_workspace_mcp.models.mail import MailMessageRef, MailOutgoingMessage
from yandex_workspace_mcp.services.mail import MailService
from yandex_workspace_mcp.tools.mail import register_mail_tools


def ref() -> MailMessageRef:
    return MailMessageRef(account_id="a" * 64, folder="INBOX", uid=7, uid_validity=123)


def settings(**updates):
    return cast(
        Any,
        SimpleNamespace(
            **(
                {
                    "yandex_mail_enabled": True,
                    "mail_read": True,
                    "mail_write": True,
                    "mail_delete": True,
                }
                | updates
            )
        ),
    )


def application(scopes):
    service = AsyncMock()
    return cast(
        Any,
        SimpleNamespace(
            principal=Principal("current", scopes=frozenset(scopes)),
            require_mail_service=lambda: service,
        ),
    ), service


async def test_registration_gates_hide_disabled_mail_operations() -> None:
    app, _ = application([])
    disabled = MCPServer("mail-disabled")
    register_mail_tools(disabled, app, settings(yandex_mail_enabled=False))
    assert await disabled.list_tools() == []
    read_only = MCPServer("mail-read-only")
    register_mail_tools(read_only, app, settings(mail_write=False, mail_delete=False))
    assert {tool.name for tool in await read_only.list_tools()} == {
        "mail_folders",
        "mail_list",
        "mail_search",
        "mail_read",
        "mail_attachment",
    }
    write_only = MCPServer("mail-write-only")
    register_mail_tools(write_only, app, settings(mail_read=False))
    assert {tool.name for tool in await write_only.list_tools()} == {
        "mail_send",
        "mail_set_read",
        "mail_trash",
    }


async def test_tools_advertise_mail_scopes_and_no_global_deletion() -> None:
    app, _ = application([])
    server = MCPServer("mail-tools")
    register_mail_tools(server, app, settings())
    tools = await server.list_tools()
    assert len(tools) == 10
    for tool in tools:
        assert tool.meta is not None
        assert tool.meta["required_scopes"] in (["mail:read"], ["mail:write"], ["mail:delete"])
        assert "purge" not in tool.name and "expunge" not in tool.name
    outgoing = next(tool for tool in tools if tool.name == "mail_send")
    assert outgoing.annotations is not None
    assert outgoing.annotations.idempotent_hint is False and outgoing.annotations.open_world_hint
    trash = next(tool for tool in tools if tool.name == "mail_trash")
    assert trash.annotations is not None
    assert trash.annotations.destructive_hint is True


@pytest.mark.parametrize(
    "name,arguments,method,scope",
    [
        ("mail_folders", {}, "folders", WorkspaceScope.MAIL_READ),
        ("mail_list", {}, "list_messages", WorkspaceScope.MAIL_READ),
        ("mail_search", {"query": "word"}, "list_messages", WorkspaceScope.MAIL_READ),
        ("mail_read", {"reference": ref()}, "read_message", WorkspaceScope.MAIL_READ),
        (
            "mail_attachment",
            {"reference": ref(), "attachment_id": "1"},
            "read_attachment",
            WorkspaceScope.MAIL_READ,
        ),
        (
            "mail_send",
            {"message": MailOutgoingMessage(to=["to@example.test"])},
            "send",
            WorkspaceScope.MAIL_WRITE,
        ),
        (
            "mail_set_read",
            {"reference": ref(), "is_read": True},
            "set_read",
            WorkspaceScope.MAIL_WRITE,
        ),
        ("mail_trash", {"reference": ref()}, "trash", WorkspaceScope.MAIL_DELETE),
    ],
)
async def test_mail_scope_required_before_service_even_for_disk_admin(
    name, arguments, method, scope
) -> None:
    app, service = application([WorkspaceScope.READ, WorkspaceScope.WRITE, WorkspaceScope.DELETE])
    server = MCPServer("mail-scopes")
    register_mail_tools(server, app, settings())
    tool = server._tool_manager._tools[name]
    with pytest.raises(PermissionDenied):
        await tool.fn(**arguments)
    getattr(service, method).assert_not_awaited()
    app.principal = Principal("current", scopes=frozenset({scope}))
    await tool.fn(**arguments)
    getattr(service, method).assert_awaited_once()


@pytest.mark.parametrize("name", ["mail_reply", "mail_forward"])
async def test_reply_forward_enforce_both_read_and_write_before_service(name) -> None:
    app, service = application([WorkspaceScope.MAIL_WRITE])
    server = MCPServer("mail-reply-scopes")
    register_mail_tools(server, app, settings())
    arguments = {"reference": ref(), "text": "body"}
    if name == "mail_forward":
        arguments["to"] = ["to@example.test"]
    with pytest.raises(PermissionDenied):
        await server._tool_manager._tools[name].fn(**arguments)
    getattr(service, name.removeprefix("mail_")).assert_not_awaited()


@pytest.mark.parametrize(
    "method,args,permissions",
    [
        ("folders", (), {"can_read": False}),
        ("list_messages", (), {"can_read": False}),
        ("read_message", (ref(),), {"can_read": False}),
        ("read_attachment", (ref(), "1"), {"can_read": False}),
        ("send", (MailOutgoingMessage(to=["to@example.test"]),), {"can_write": False}),
        ("reply", (ref(), "body"), {"can_read": False}),
        ("forward", (ref(), ["to@example.test"]), {"can_read": False}),
        ("set_read", (ref(), False), {"can_write": False}),
        ("trash", (ref(),), {"can_delete": False}),
    ],
)
async def test_server_permission_gates_protect_direct_service_calls(
    method, args, permissions
) -> None:
    client = AsyncMock()
    service = MailService(
        client, **({"can_read": True, "can_write": True, "can_delete": True} | permissions)
    )
    with pytest.raises(PermissionDenied):
        await getattr(service, method)(*args)
    getattr(client, method).assert_not_awaited()


async def test_mail_mutation_audit_contains_no_mail_content_or_addresses() -> None:
    client = AsyncMock()
    service = MailService(client, can_write=True, can_delete=True)
    with patch("yandex_workspace_mcp.services.mail.audit_logger.emit") as emit:
        await service.send(
            MailOutgoingMessage(
                to=["private-address@example.test"], subject="private-subject", text="private-body"
            )
        )
        client.trash.side_effect = UpstreamTimeout()
        with pytest.raises(UpstreamTimeout):
            await service.trash(ref())
    events = [call.args[0] for call in emit.call_args_list]
    assert [(event.action, event.outcome) for event in events] == [
        ("mail.send", "success"),
        ("mail.trash", "failure"),
    ]
    assert events[1].destructive and events[0].normalized_locator is None
    assert "private-" not in " ".join(event.model_dump_json() for event in events)
