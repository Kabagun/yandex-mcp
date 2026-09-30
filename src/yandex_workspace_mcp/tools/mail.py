"""MCP Mail tools with explicit registration gates and request scope checks."""

from typing import Annotated, Protocol

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from ..auth.scopes import OperationClass, WorkspacePrincipal, WorkspaceScope, require_scope
from ..config import Settings
from ..models.mail import (
    MailAttachmentContent,
    MailFolderList,
    MailMessage,
    MailMessagePage,
    MailMessageRef,
    MailMutationResult,
    MailOutgoingAttachment,
    MailOutgoingMessage,
    MailSendResult,
)
from ..services.mail import MailService


class MailApplication(Protocol):
    @property
    def principal(self) -> WorkspacePrincipal: ...

    def require_mail_service(self) -> MailService: ...


READ = ToolAnnotations(
    read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False
)
SEND = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True
)
FLAG = ToolAnnotations(
    read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False
)
TRASH = ToolAnnotations(
    read_only_hint=False, destructive_hint=True, idempotent_hint=False, open_world_hint=False
)


def register_mail_tools(mcp: MCPServer, application: MailApplication, settings: Settings) -> None:
    """Register only enabled Mail operations, each enforcing its Mail-specific scope."""
    if not settings.yandex_mail_enabled:
        return
    if settings.mail_read:

        @mcp.tool(
            name="mail_folders",
            description="List current-account Yandex Mail folders",
            annotations=READ,
            meta={"required_scopes": [WorkspaceScope.MAIL_READ.value]},
        )
        async def mail_folders() -> MailFolderList:
            require_scope(application.principal, OperationClass.READ, service="mail")
            return await application.require_mail_service().folders()

        @mcp.tool(
            name="mail_list",
            description="List newest messages in a bounded 1,000-UID window; continue using next_before_uid",
            annotations=READ,
            meta={"required_scopes": [WorkspaceScope.MAIL_READ.value]},
        )
        async def mail_list(
            folder: str = "INBOX",
            limit: Annotated[int, Field(ge=1, le=100)] = 20,
            before_uid: Annotated[int, Field(ge=1, le=4_294_967_295)] | None = None,
        ) -> MailMessagePage:
            require_scope(application.principal, OperationClass.READ, service="mail")
            return await application.require_mail_service().list_messages(
                folder, limit=limit, before_uid=before_uid
            )

        @mcp.tool(
            name="mail_search",
            description="Search message text in a bounded 1,000-UID window; continue using next_before_uid",
            annotations=READ,
            meta={"required_scopes": [WorkspaceScope.MAIL_READ.value]},
        )
        async def mail_search(
            query: Annotated[str, Field(min_length=1, max_length=1000)],
            folder: str = "INBOX",
            limit: Annotated[int, Field(ge=1, le=100)] = 20,
            before_uid: Annotated[int, Field(ge=1, le=4_294_967_295)] | None = None,
        ) -> MailMessagePage:
            require_scope(application.principal, OperationClass.READ, service="mail")
            return await application.require_mail_service().list_messages(
                folder, limit=limit, before_uid=before_uid, query=query
            )

        @mcp.tool(
            name="mail_read",
            description="Read bounded MIME without marking the message read",
            annotations=READ,
            meta={"required_scopes": [WorkspaceScope.MAIL_READ.value]},
        )
        async def mail_read(reference: MailMessageRef) -> MailMessage:
            require_scope(application.principal, OperationClass.READ, service="mail")
            return await application.require_mail_service().read_message(reference)

        @mcp.tool(
            name="mail_attachment",
            description="Read one bounded attachment as base64",
            annotations=READ,
            meta={"required_scopes": [WorkspaceScope.MAIL_READ.value]},
        )
        async def mail_attachment(
            reference: MailMessageRef, attachment_id: str
        ) -> MailAttachmentContent:
            require_scope(application.principal, OperationClass.READ, service="mail")
            return await application.require_mail_service().read_attachment(
                reference, attachment_id
            )

    if settings.mail_write:

        @mcp.tool(
            name="mail_send",
            description="Submit mail once; SMTP acceptance does not confirm delivery or a Sent-folder copy",
            annotations=SEND,
            meta={"required_scopes": [WorkspaceScope.MAIL_WRITE.value]},
        )
        async def mail_send(message: MailOutgoingMessage) -> MailSendResult:
            require_scope(application.principal, OperationClass.WRITE, service="mail")
            return await application.require_mail_service().send(message)

        @mcp.tool(
            name="mail_set_read",
            description="Set one message read or unread",
            annotations=FLAG,
            meta={"required_scopes": [WorkspaceScope.MAIL_WRITE.value]},
        )
        async def mail_set_read(reference: MailMessageRef, is_read: bool) -> MailMutationResult:
            require_scope(application.principal, OperationClass.WRITE, service="mail")
            return await application.require_mail_service().set_read(reference, is_read)

        if settings.mail_read:

            @mcp.tool(
                name="mail_reply",
                description="Reply once using the original Reply-To or From",
                annotations=SEND,
                meta={"required_scopes": [WorkspaceScope.MAIL_WRITE.value]},
            )
            async def mail_reply(
                reference: MailMessageRef,
                text: str,
                reply_all: bool = False,
                attachments: list[MailOutgoingAttachment] | None = None,
            ) -> MailSendResult:
                require_scope(application.principal, OperationClass.WRITE, service="mail")
                require_scope(application.principal, OperationClass.READ, service="mail")
                return await application.require_mail_service().reply(
                    reference, text, reply_all=reply_all, attachments=attachments
                )

            @mcp.tool(
                name="mail_forward",
                description="Forward bounded original content and attachments once",
                annotations=SEND,
                meta={"required_scopes": [WorkspaceScope.MAIL_WRITE.value]},
            )
            async def mail_forward(
                reference: MailMessageRef,
                to: list[str],
                text: str = "",
                cc: list[str] | None = None,
                bcc: list[str] | None = None,
            ) -> MailSendResult:
                require_scope(application.principal, OperationClass.WRITE, service="mail")
                require_scope(application.principal, OperationClass.READ, service="mail")
                return await application.require_mail_service().forward(
                    reference, to, text=text, cc=cc, bcc=bcc
                )

    if settings.mail_delete:

        @mcp.tool(
            name="mail_trash",
            description="Move one message to Trash using safe UID MOVE only",
            annotations=TRASH,
            meta={"required_scopes": [WorkspaceScope.MAIL_DELETE.value]},
        )
        async def mail_trash(reference: MailMessageRef) -> MailMutationResult:
            require_scope(application.principal, OperationClass.DELETE, service="mail")
            return await application.require_mail_service().trash(reference)
