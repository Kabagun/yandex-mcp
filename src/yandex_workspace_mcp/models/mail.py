"""Stable, bounded MCP contracts for native Yandex Mail operations."""

from typing import Literal

from pydantic import Field, field_validator

from .base import PublicModel
from .errors import APIError


def validate_header(value: str, *, max_length: int = 1000) -> str:
    """Reject header control characters rather than allowing MIME header injection."""
    if len(value) > max_length or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("Invalid mail header")
    return value


class MailMessageRef(PublicModel):
    """Account-bound IMAP UID reference; invalid after mailbox UIDVALIDITY changes."""

    account_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    folder: str = Field(min_length=1, max_length=512)
    uid: int = Field(ge=1, le=4_294_967_295)
    uid_validity: int = Field(ge=1, le=4_294_967_295)

    @field_validator("folder")
    @classmethod
    def safe_folder(cls, value: str) -> str:
        return validate_header(value, max_length=512)


class MailFolder(PublicModel):
    """Selectable folder name and server-advertised special-use flags."""

    name: str
    delimiter: str | None = None
    flags: list[str] = Field(default_factory=list)
    selectable: bool = True


class MailFolderList(PublicModel):
    folders: list[MailFolder]


class MailMessageSummary(PublicModel):
    reference: MailMessageRef
    subject: str = ""
    sender: str = ""
    to: list[str] = Field(default_factory=list)
    date: str | None = None
    message_id: str | None = None
    size_bytes: int = Field(ge=0)
    is_read: bool = False


class MailMessagePage(PublicModel):
    """Newest-first results from at most 1,000 UID values per request."""

    messages: list[MailMessageSummary]
    next_before_uid: int | None = None
    scan_start_uid: int = Field(ge=0)
    scan_end_uid: int = Field(ge=0)
    partial_scan: bool = False


class MailAttachment(PublicModel):
    """Opaque part ID scoped to the message reference, without binary content."""

    attachment_id: str
    filename: str | None = None
    content_type: str
    size_bytes: int = Field(ge=0)


class MailMessage(MailMessageSummary):
    cc: list[str] = Field(default_factory=list)
    reply_to: list[str] = Field(default_factory=list)
    text: str | None = None
    html: str | None = None
    attachments: list[MailAttachment] = Field(default_factory=list)


class MailAttachmentContent(MailAttachment):
    content_base64: str


class MailOutgoingAttachment(PublicModel):
    """Base64 file attachment; decoded and aggregate sizes are checked before SMTP."""

    filename: str = Field(min_length=1, max_length=255)
    content_type: str = Field(default="application/octet-stream", max_length=127)
    content_base64: str

    @field_validator("filename", "content_type")
    @classmethod
    def safe_header(cls, value: str) -> str:
        return validate_header(value, max_length=255)


class MailOutgoingMessage(PublicModel):
    """Outgoing message. From is always the current authenticated Yandex account."""

    to: list[str] = Field(min_length=1, max_length=100)
    cc: list[str] = Field(default_factory=list, max_length=100)
    bcc: list[str] = Field(default_factory=list, max_length=100)
    subject: str = Field(default="", max_length=1000)
    text: str = ""
    html: str | None = None
    attachments: list[MailOutgoingAttachment] = Field(default_factory=list, max_length=20)

    @field_validator("subject")
    @classmethod
    def safe_subject(cls, value: str) -> str:
        return validate_header(value)


class MailSendResult(PublicModel):
    """SMTP acceptance is not delivery confirmation; no Sent-folder copy is appended."""

    status: Literal["accepted", "partially_accepted"]
    message_id: str
    accepted_recipients: list[str]
    rejected_recipients: list[str] = Field(default_factory=list)
    delivery_confirmed: bool = False
    sent_copy_saved: bool = False


class MailMutationResult(PublicModel):
    reference: MailMessageRef
    action: Literal["read", "unread", "trash"]
    destination_folder: str | None = None


class MailSubmissionUncertain(APIError):
    """A submission failure after SMTP starts may already have delivered the message."""

    category = "mail_submission_uncertain"

    def __init__(self) -> None:
        super().__init__(
            "Mail submission outcome is unknown. Check the account before sending again."
        )
