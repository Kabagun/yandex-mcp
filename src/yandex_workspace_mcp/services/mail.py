"""Mail permissions and metadata-only mutation auditing."""

from collections.abc import Awaitable, Callable
from typing import TypeVar

from ..clients.mail import YandexMailClient
from ..models.errors import PermissionDenied, YandexWorkspaceError
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
from ..security.audit import audit_logger

T = TypeVar("T")


class MailService:
    """Enforce server-level permissions independently of MCP scope checks."""

    def __init__(
        self,
        client: YandexMailClient,
        *,
        can_read: bool = True,
        can_write: bool = False,
        can_delete: bool = False,
    ) -> None:
        self.client = client
        self.can_read = can_read
        self.can_write = can_write
        self.can_delete = can_delete

    def _read_gate(self) -> None:
        if not self.can_read:
            raise PermissionDenied()

    async def _mutation(
        self, action: str, allowed: bool, operation: Callable[[], Awaitable[T]]
    ) -> T:
        try:
            if not allowed:
                raise PermissionDenied()
            result = await operation()
        except YandexWorkspaceError:
            audit_logger.log(
                f"mail.{action}", result="failure", error=True, permanently=action == "trash"
            )
            raise
        audit_logger.log(f"mail.{action}", result="success", permanently=action == "trash")
        return result

    async def folders(self) -> MailFolderList:
        """List current-account folders when server read access is enabled."""
        self._read_gate()
        return await self.client.folders()

    async def list_messages(
        self,
        folder: str = "INBOX",
        *,
        limit: int = 20,
        before_uid: int | None = None,
        query: str | None = None,
    ) -> MailMessagePage:
        """Return bounded newest-first summaries, optionally searched by text."""
        self._read_gate()
        return await self.client.list_messages(
            folder, limit=limit, before_uid=before_uid, query=query
        )

    async def read_message(self, reference: MailMessageRef) -> MailMessage:
        """Read account-bound MIME without marking the message as read."""
        self._read_gate()
        return await self.client.read_message(reference)

    async def read_attachment(
        self, reference: MailMessageRef, attachment_id: str
    ) -> MailAttachmentContent:
        """Read one bounded attachment from the referenced current-account message."""
        self._read_gate()
        return await self.client.read_attachment(reference, attachment_id)

    async def send(self, message: MailOutgoingMessage) -> MailSendResult:
        """Submit mail once with write permission; acceptance does not confirm delivery."""
        return await self._mutation("send", self.can_write, lambda: self.client.send(message))

    async def reply(
        self,
        reference: MailMessageRef,
        text: str,
        *,
        reply_all: bool = False,
        attachments: list[MailOutgoingAttachment] | None = None,
    ) -> MailSendResult:
        """Reply with both read and write gates enabled."""
        return await self._mutation(
            "reply",
            self.can_write and self.can_read,
            lambda: self.client.reply(
                reference, text, reply_all=reply_all, attachments=attachments
            ),
        )

    async def forward(
        self,
        reference: MailMessageRef,
        to: list[str],
        *,
        text: str = "",
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
    ) -> MailSendResult:
        """Forward current-account content with both read and write gates enabled."""
        return await self._mutation(
            "forward",
            self.can_write and self.can_read,
            lambda: self.client.forward(reference, to, text=text, cc=cc, bcc=bcc),
        )

    async def set_read(self, reference: MailMessageRef, is_read: bool) -> MailMutationResult:
        """Change only the referenced message's Seen flag with write permission."""
        return await self._mutation(
            "set_read", self.can_write, lambda: self.client.set_read(reference, is_read)
        )

    async def trash(self, reference: MailMessageRef) -> MailMutationResult:
        """Move only the referenced message to Trash with delete permission."""
        return await self._mutation("trash", self.can_delete, lambda: self.client.trash(reference))
