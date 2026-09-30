"""Request-local TLS IMAP/SMTP client, with no shared account connections or retries."""

import base64
import binascii
import hashlib
import html
import imaplib
import re
import smtplib
import ssl
import time
from collections.abc import Awaitable, Callable
from email import policy
from email.errors import HeaderParseError
from email.headerregistry import Address
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import formatdate, getaddresses, make_msgid
from functools import partial
from typing import Any, TypeVar

import anyio

from ..auth.models import YandexOAuthCredential
from ..models.errors import (
    APIError,
    AuthenticationError,
    ConfigurationError,
    ContractMismatchError,
    InvalidInput,
    ResourceNotFound,
    RevisionConflict,
    UpstreamTimeout,
    UpstreamUnavailable,
    YandexWorkspaceError,
)
from ..models.mail import (
    MailAttachment,
    MailAttachmentContent,
    MailFolder,
    MailFolderList,
    MailMessage,
    MailMessagePage,
    MailMessageRef,
    MailMessageSummary,
    MailMutationResult,
    MailOutgoingAttachment,
    MailOutgoingMessage,
    MailSendResult,
    MailSubmissionUncertain,
    validate_header,
)

T = TypeVar("T")
CredentialProvider = Callable[[], Awaitable[YandexOAuthCredential]]
_MAX_UID = 4_294_967_295
_SCAN_WINDOW = 1000
_HEADER_BYTES = 64 * 1024
_LIST_PATTERN = re.compile(rb'^\(([^)]*)\) (NIL|"(?:\\.|[^"\\])*") (.+)$')


def _quote(value: bytes) -> bytes:
    if any(char < 32 or char == 127 for char in value):
        raise InvalidInput()
    return b'"' + value.replace(b"\\", b"\\\\").replace(b'"', b'\\"') + b'"'


def _encode_folder(value: str) -> bytes:
    try:
        validate_header(value, max_length=512)
        if not value:
            raise ValueError()
        encoded: list[str] = []
        pending: list[str] = []

        def flush() -> None:
            if pending:
                data = "".join(pending).encode("utf-16-be")
                encoded.append(
                    "&" + base64.b64encode(data).decode().rstrip("=").replace("/", ",") + "-"
                )
                pending.clear()

        for char in value:
            if 32 <= ord(char) <= 126:
                flush()
                encoded.append("&-" if char == "&" else char)
            else:
                pending.append(char)
        flush()
        return _quote("".join(encoded).encode("ascii"))
    except (ValueError, UnicodeError):
        raise InvalidInput() from None


def _unquote(value: bytes) -> bytes:
    if value.startswith(b'"'):
        if not value.endswith(b'"'):
            raise ContractMismatchError()
        return re.sub(rb"\\(.)", rb"\1", value[1:-1])
    return value


def _decode_folder(value: bytes) -> str:
    raw = _unquote(value).decode("ascii")

    def decode(match: re.Match[str]) -> str:
        data = match.group(1)
        if not data:
            return "&"
        data = data.replace(",", "/")
        return base64.b64decode(data + "=" * (-len(data) % 4), validate=True).decode("utf-16-be")

    decoded = re.sub(r"&([^-]*)-", decode, raw)
    validate_header(decoded, max_length=512)
    if not decoded:
        raise ContractMismatchError()
    return decoded


def _address(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 254:
        raise InvalidInput()
    try:
        validate_header(value, max_length=254)
        value.encode("ascii")
        if any(char.isspace() for char in value) or any(char in value for char in "<>(),;\\"):
            raise ValueError()
        parsed = Address(addr_spec=value)
        if not parsed.username or not parsed.domain or "@" not in value:
            raise ValueError()
        return parsed.addr_spec
    except (ValueError, UnicodeError, IndexError, HeaderParseError):
        raise InvalidInput() from None


def _account_id(email: str) -> str:
    return hashlib.sha256(email.casefold().encode("utf-8")).hexdigest()


class _ImapSession:
    def __init__(self, connection: imaplib.IMAP4_SSL, deadline: float) -> None:
        self.connection = connection
        self.deadline = deadline

    def call(self, method: str, *args: Any) -> Any:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise UpstreamTimeout()
        self.connection.sock.settimeout(remaining)
        return getattr(self.connection, method)(*args)


class YandexMailClient:
    """Use current-request credentials and fixed Yandex TLS endpoints only."""

    def __init__(
        self,
        *,
        credential_provider: CredentialProvider,
        max_message_bytes: int = 10 * 1024 * 1024,
        max_attachment_bytes: int = 5 * 1024 * 1024,
        timeout_seconds: float = 30,
    ) -> None:
        if max_message_bytes < 1 or max_attachment_bytes < 1 or timeout_seconds <= 0:
            raise ConfigurationError()
        self._credential_provider = credential_provider
        self.max_message_bytes = max_message_bytes
        self.max_attachment_bytes = max_attachment_bytes
        self.timeout_seconds = timeout_seconds

    async def close(self) -> None:
        """No pooled connections exist; each operation closes its own transport."""

    async def _credential(self) -> YandexOAuthCredential:
        try:
            credential = await self._credential_provider()
            if not isinstance(credential, YandexOAuthCredential):
                raise TypeError()
            _address(credential.email or "")
            if (
                not credential.token
                or len(credential.token) > 8192
                or any(ord(char) <= 32 or ord(char) >= 127 for char in credential.token)
            ):
                raise ValueError()
            return credential
        except Exception:  # noqa: BLE001 -- credential errors must not expose provider responses.
            raise AuthenticationError() from None

    async def _run(self, action: Callable[[], T]) -> T:
        try:
            return await anyio.to_thread.run_sync(action)
        except YandexWorkspaceError as exc:
            raise exc from None
        except TimeoutError:
            raise UpstreamTimeout() from None
        except (imaplib.IMAP4.abort, OSError, smtplib.SMTPServerDisconnected):
            raise UpstreamUnavailable() from None
        except (imaplib.IMAP4.error, smtplib.SMTPException):
            raise APIError() from None
        except (ValueError, TypeError, UnicodeError, binascii.Error, RecursionError):
            raise ContractMismatchError() from None

    def _imap(
        self, credential: YandexOAuthCredential, action: Callable[[_ImapSession, str], T]
    ) -> T:
        deadline = time.monotonic() + self.timeout_seconds
        connection = imaplib.IMAP4_SSL(
            "imap.yandex.ru",
            993,
            ssl_context=ssl.create_default_context(),
            timeout=self.timeout_seconds,
        )
        session = _ImapSession(connection, deadline)
        email = credential.email or ""
        authentication = f"user={email}\x01auth=Bearer {credential.token}\x01\x01".encode()
        try:
            try:
                session.call(
                    "authenticate",
                    "XOAUTH2",
                    lambda challenge: authentication if not challenge else b"",
                )
            except imaplib.IMAP4.error:
                raise AuthenticationError() from None
            return action(session, email)
        finally:
            # IMAP CLOSE and EXPUNGE are deliberately never called, including cleanup.
            try:
                connection.shutdown()
            except OSError:
                pass

    @staticmethod
    def _ok(response: Any) -> list[Any]:
        status, data = response
        if status != "OK":
            raise APIError()
        if not isinstance(data, list):
            raise ContractMismatchError()
        return data

    @staticmethod
    def _number(session: _ImapSession, name: str) -> int:
        _, values = session.connection.response(name)
        if not values or not isinstance(values[0], bytes) or not values[0].isdigit():
            raise ContractMismatchError()
        value = int(values[0])
        if not 1 <= value <= _MAX_UID:
            raise ContractMismatchError()
        return value

    def _select(
        self,
        session: _ImapSession,
        folder: str,
        email: str,
        reference: MailMessageRef | None = None,
        *,
        readonly: bool = True,
    ) -> tuple[int, int]:
        mailbox = _encode_folder(folder)
        if reference is not None and reference.account_id != _account_id(email):
            raise ResourceNotFound()
        status, _ = session.call("select", mailbox, readonly)
        if status != "OK":
            raise ResourceNotFound()
        validity = self._number(session, "UIDVALIDITY")
        if reference is not None and reference.uid_validity != validity:
            raise RevisionConflict()
        return validity, self._number(session, "UIDNEXT")

    def _folders(self, session: _ImapSession) -> MailFolderList:
        rows = self._ok(session.call("list", '""', '"*"'))
        if len(rows) > 1000:
            raise ContractMismatchError()
        folders: list[MailFolder] = []
        for row in rows:
            if isinstance(row, tuple) and len(row) == 2:
                prefix, literal = row
                if not isinstance(prefix, bytes) or not isinstance(literal, bytes):
                    raise ContractMismatchError()
                row = re.sub(rb"\{\d+\}$", b"", prefix) + literal
            if not isinstance(row, bytes):
                raise ContractMismatchError()
            match = _LIST_PATTERN.fullmatch(row)
            if match is None:
                raise ContractMismatchError()
            flags = match.group(1).decode("ascii").split()
            delimiter = (
                None if match.group(2) == b"NIL" else _unquote(match.group(2)).decode("ascii")
            )
            folders.append(
                MailFolder(
                    name=_decode_folder(match.group(3)),
                    delimiter=delimiter,
                    flags=flags,
                    selectable="\\noselect" not in {flag.lower() for flag in flags},
                )
            )
        return MailFolderList(folders=folders)

    async def folders(self) -> MailFolderList:
        """List at most 1,000 account-local folders, decoding IMAP modified UTF-7."""
        credential = await self._credential()
        return await self._run(
            partial(self._imap, credential, lambda session, email: self._folders(session))
        )

    @staticmethod
    def _metadata(session: _ImapSession, uid: int) -> tuple[int, bool]:
        rows = YandexMailClient._ok(
            session.call("uid", "FETCH", str(uid), "(UID RFC822.SIZE FLAGS)")
        )
        if not rows or rows == [None]:
            raise ResourceNotFound()
        data = b" ".join(row for row in rows if isinstance(row, bytes))
        matched_uid = re.search(rb"\bUID (\d+)\b", data)
        size = re.search(rb"\bRFC822.SIZE (\d+)\b", data)
        flags = re.search(rb"\bFLAGS \(([^)]*)\)", data)
        if matched_uid is None or int(matched_uid.group(1)) != uid or size is None or flags is None:
            raise ContractMismatchError()
        return int(size.group(1)), b"\\Seen" in flags.group(1).split()

    @staticmethod
    def _fetch_bytes(session: _ImapSession, uid: int, section: str, cap: int) -> bytes:
        rows = YandexMailClient._ok(
            session.call(
                "uid",
                "FETCH",
                str(uid),
                f"(UID BODY.PEEK[{section}]<0.{cap + 1}>)",
            )
        )
        literals = [row for row in rows if isinstance(row, tuple) and len(row) == 2]
        if not literals:
            raise ResourceNotFound()
        if len(literals) != 1:
            raise ContractMismatchError()
        metadata, data = literals[0]
        matched_uid = (
            re.search(rb"\bUID (\d+)\b", metadata) if isinstance(metadata, bytes) else None
        )
        if matched_uid is None or int(matched_uid.group(1)) != uid or not isinstance(data, bytes):
            raise ContractMismatchError()
        if len(data) > cap:
            raise InvalidInput("Mail content exceeds the configured size limit.")
        return data

    @staticmethod
    def _addresses(message: Message, header: str) -> list[str]:
        return [address for _, address in getaddresses(message.get_all(header, [])) if address]

    def _summary(
        self, message: Message, reference: MailMessageRef, size: int, is_read: bool
    ) -> MailMessageSummary:
        return MailMessageSummary(
            reference=reference,
            subject=str(message.get("Subject", "")),
            sender=str(message.get("From", "")),
            to=self._addresses(message, "To"),
            date=str(message["Date"]) if message["Date"] else None,
            message_id=str(message["Message-ID"]) if message["Message-ID"] else None,
            size_bytes=size,
            is_read=is_read,
        )

    async def list_messages(
        self,
        folder: str = "INBOX",
        *,
        limit: int = 20,
        before_uid: int | None = None,
        query: str | None = None,
    ) -> MailMessagePage:
        """List/search newest-first within 1,000 UID values; continue with next_before_uid."""
        _encode_folder(folder)
        if not 1 <= limit <= 100 or (before_uid is not None and not 1 <= before_uid <= _MAX_UID):
            raise InvalidInput()
        if query is not None:
            try:
                validate_header(query, max_length=1000)
                if not query:
                    raise ValueError()
            except ValueError:
                raise InvalidInput() from None
        credential = await self._credential()

        def action(session: _ImapSession, email: str) -> MailMessagePage:
            validity, uid_next = self._select(session, folder, email)
            end = min(uid_next - 1, before_uid if before_uid is not None else uid_next - 1)
            if end < 1:
                return MailMessagePage(messages=[], scan_start_uid=0, scan_end_uid=0)
            start = max(1, end - _SCAN_WINDOW + 1)
            criteria: list[str | bytes] = ["UID", f"{start}:{end}"]
            if query is not None:
                criteria += ["TEXT", _quote(query.encode("utf-8"))]
            rows = self._ok(session.call("uid", "SEARCH", "CHARSET", "UTF-8", *criteria))
            if len(rows) != 1 or not isinstance(rows[0], bytes):
                raise ContractMismatchError()
            values = rows[0].split()
            if len(values) > _SCAN_WINDOW or any(not value.isdigit() for value in values):
                raise ContractMismatchError()
            uids = sorted({int(value) for value in values}, reverse=True)
            if any(not start <= uid <= end for uid in uids):
                raise ContractMismatchError()
            messages = []
            for uid in uids[:limit]:
                try:
                    size, is_read = self._metadata(session, uid)
                    headers = self._fetch_bytes(
                        session,
                        uid,
                        "HEADER.FIELDS (FROM TO SUBJECT DATE MESSAGE-ID)",
                        _HEADER_BYTES,
                    )
                    reference = MailMessageRef(
                        account_id=_account_id(email), folder=folder, uid=uid, uid_validity=validity
                    )
                    messages.append(
                        self._summary(
                            BytesParser(policy=policy.default).parsebytes(headers),
                            reference,
                            size,
                            is_read,
                        )
                    )
                except ResourceNotFound:
                    continue  # A concurrent mailbox operation removed this UID.
            next_uid = uids[limit - 1] - 1 if len(uids) > limit else start - 1
            return MailMessagePage(
                messages=messages,
                next_before_uid=next_uid or None,
                scan_start_uid=start,
                scan_end_uid=end,
                partial_scan=start > 1 or len(uids) > limit,
            )

        return await self._run(partial(self._imap, credential, action))

    def _read(
        self, session: _ImapSession, email: str, reference: MailMessageRef
    ) -> tuple[MailMessage, Message, dict[str, tuple[MailAttachment, bytes]]]:
        self._select(session, reference.folder, email, reference)
        size, is_read = self._metadata(session, reference.uid)
        if size > self.max_message_bytes:
            raise InvalidInput("Mail content exceeds the configured size limit.")
        raw = self._fetch_bytes(session, reference.uid, "", self.max_message_bytes)
        if len(raw) != size:
            raise ContractMismatchError()
        parsed = BytesParser(policy=policy.default).parsebytes(raw)
        attachments: dict[str, tuple[MailAttachment, bytes]] = {}
        texts: list[str] = []
        htmls: list[str] = []
        decoded_total = 0
        pending: list[Message] = [parsed]
        index = 0
        while pending:
            part = pending.pop(0)
            index += 1
            if index > 200:
                raise InvalidInput("Mail has too many MIME parts.")
            filename = part.get_filename()
            content_type = part.get_content_type()
            attached = (
                filename is not None
                or part.get_content_disposition() == "attachment"
                or content_type == "message/rfc822"
            )
            if part.is_multipart():
                children = part.get_payload()
                if not isinstance(children, list):
                    raise ContractMismatchError()
                messages = [child for child in children if isinstance(child, Message)]
                if len(messages) != len(children):
                    raise ContractMismatchError()
                if not attached:
                    pending[0:0] = messages
                    continue
                # Encapsulated messages stay opaque; their body is not the parent body.
                payload = b"\r\n".join(child.as_bytes(policy=policy.SMTP) for child in messages)
            else:
                decoded = part.get_payload(decode=True)
                if decoded is not None and not isinstance(decoded, bytes):
                    raise ContractMismatchError()
                payload = decoded or b""
            decoded_total += len(payload)
            if decoded_total > self.max_message_bytes:
                raise InvalidInput("Mail content exceeds the configured size limit.")
            if attached:
                attachment = MailAttachment(
                    attachment_id=str(index),
                    filename=filename,
                    content_type=content_type,
                    size_bytes=len(payload),
                )
                attachments[str(index)] = (attachment, payload)
            elif content_type in {"text/plain", "text/html"}:
                charset = part.get_content_charset() or "utf-8"
                try:
                    text = payload.decode(charset, errors="replace")
                except LookupError:
                    text = payload.decode("utf-8", errors="replace")
                (texts if content_type == "text/plain" else htmls).append(text)
        summary = self._summary(parsed, reference, size, is_read)
        message = MailMessage(
            **summary.model_dump(),
            cc=self._addresses(parsed, "Cc"),
            reply_to=self._addresses(parsed, "Reply-To"),
            text="\n".join(texts) or None,
            html="\n".join(htmls) or None,
            attachments=[item[0] for item in attachments.values()],
        )
        return message, parsed, attachments

    async def read_message(self, reference: MailMessageRef) -> MailMessage:
        """Read bounded MIME with BODY.PEEK, leaving the Seen flag unchanged."""
        credential = await self._credential()
        return await self._run(
            partial(
                self._imap,
                credential,
                lambda session, email: self._read(session, email, reference)[0],
            )
        )

    async def read_attachment(
        self, reference: MailMessageRef, attachment_id: str
    ) -> MailAttachmentContent:
        """Return one decoded attachment as base64, subject to both size caps."""
        if not re.fullmatch(r"[1-9]\d{0,2}", attachment_id):
            raise InvalidInput()
        credential = await self._credential()

        def action(session: _ImapSession, email: str) -> MailAttachmentContent:
            _, _, attachments = self._read(session, email, reference)
            if attachment_id not in attachments:
                raise ResourceNotFound()
            attachment, payload = attachments[attachment_id]
            if len(payload) > self.max_attachment_bytes:
                raise InvalidInput("Mail attachment exceeds the configured size limit.")
            return MailAttachmentContent(
                **attachment.model_dump(), content_base64=base64.b64encode(payload).decode("ascii")
            )

        return await self._run(partial(self._imap, credential, action))

    def _outgoing(
        self, email: str, message: MailOutgoingMessage, *, reply_id: str | None = None
    ) -> tuple[bytes, list[str], str]:
        try:
            validate_header(message.subject)
            if len(message.to) + len(message.cc) + len(message.bcc) > 100 or not message.to:
                raise ValueError()
            if len(message.attachments) > 20:
                raise ValueError()
            recipients = list(
                dict.fromkeys(_address(value) for value in message.to + message.cc + message.bcc)
            )
            if len(message.text.encode("utf-8")) > self.max_message_bytes:
                raise ValueError()
            if (
                message.html is not None
                and len(message.html.encode("utf-8")) > self.max_message_bytes
            ):
                raise ValueError()
            outgoing = EmailMessage(policy=policy.SMTP)
            outgoing["From"] = _address(email)
            outgoing["To"] = ", ".join(message.to)
            if message.cc:
                outgoing["Cc"] = ", ".join(message.cc)
            outgoing["Subject"] = message.subject
            outgoing["Date"] = formatdate(usegmt=True)
            message_id = make_msgid(domain=email.rsplit("@", 1)[1])
            outgoing["Message-ID"] = message_id
            if reply_id is not None:
                validate_header(reply_id)
                if not re.fullmatch(r"<[^<>\s]+@[^<>\s]+>", reply_id):
                    raise ValueError()
                outgoing["In-Reply-To"] = reply_id
                outgoing["References"] = reply_id
            outgoing.set_content(message.text)
            if message.html is not None:
                outgoing.add_alternative(message.html, subtype="html")
            total = 0
            for attachment in message.attachments:
                validate_header(attachment.filename, max_length=255)
                if not attachment.filename or not re.fullmatch(
                    r"[a-zA-Z0-9!#$&^_.+-]+/[a-zA-Z0-9!#$&^_.+-]+", attachment.content_type
                ):
                    raise ValueError()
                if len(attachment.content_base64) > 4 * ((self.max_attachment_bytes + 2) // 3):
                    raise ValueError()
                data = base64.b64decode(attachment.content_base64, validate=True)
                total += len(data)
                if len(data) > self.max_attachment_bytes or total > self.max_message_bytes:
                    raise ValueError()
                main, sub = attachment.content_type.split("/", 1)
                if attachment.content_type.lower() == "message/rfc822":
                    outgoing.add_attachment(
                        BytesParser(policy=policy.default).parsebytes(data),
                        subtype="rfc822",
                        filename=attachment.filename,
                    )
                else:
                    outgoing.add_attachment(
                        data, maintype=main, subtype=sub, filename=attachment.filename
                    )
            raw = outgoing.as_bytes()
            if len(raw) > self.max_message_bytes:
                raise ValueError()
            return raw, recipients, message_id
        except (ValueError, UnicodeError, binascii.Error):
            raise InvalidInput(
                "Outgoing mail is invalid or exceeds a configured size limit."
            ) from None

    def _smtp(
        self,
        credential: YandexOAuthCredential,
        message: MailOutgoingMessage,
        *,
        reply_id: str | None = None,
    ) -> MailSendResult:
        email = credential.email or ""
        raw, recipients, message_id = self._outgoing(email, message, reply_id=reply_id)
        deadline = time.monotonic() + self.timeout_seconds
        connection = smtplib.SMTP_SSL(
            "smtp.yandex.ru",
            465,
            context=ssl.create_default_context(),
            timeout=self.timeout_seconds,
        )
        try:
            connection.ehlo()
            if "XOAUTH2" not in connection.esmtp_features.get("auth", "").upper().split():
                raise AuthenticationError()
            authentication = f"user={email}\x01auth=Bearer {credential.token}\x01\x01"
            try:
                connection.auth(
                    "XOAUTH2", lambda challenge=None: authentication if challenge is None else ""
                )
            except smtplib.SMTPException:
                raise AuthenticationError() from None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise UpstreamTimeout()
            if connection.sock is None:
                raise UpstreamUnavailable()
            connection.sock.settimeout(remaining)
            try:
                refused = connection.sendmail(email, recipients, raw)
            except smtplib.SMTPRecipientsRefused:
                raise InvalidInput("SMTP rejected all recipients.") from None
            except (TimeoutError, OSError, smtplib.SMTPServerDisconnected):
                raise MailSubmissionUncertain() from None
            rejected = [address for address in recipients if address in refused]
            accepted = [address for address in recipients if address not in refused]
            if not accepted:
                raise InvalidInput("SMTP rejected all recipients.")
            return MailSendResult(
                status="partially_accepted" if rejected else "accepted",
                message_id=message_id,
                accepted_recipients=accepted,
                rejected_recipients=rejected,
            )
        finally:
            connection.close()

    async def send(self, message: MailOutgoingMessage) -> MailSendResult:
        """Submit once; report SMTP acceptance, not delivery, and do not append a Sent copy."""
        credential = await self._credential()
        return await self._run(partial(self._smtp, credential, message))

    async def reply(
        self,
        reference: MailMessageRef,
        text: str,
        *,
        reply_all: bool = False,
        attachments: list[MailOutgoingAttachment] | None = None,
    ) -> MailSendResult:
        """Reply using the original Reply-To/From and account-local threading metadata."""
        credential = await self._credential()

        def action() -> MailSendResult:
            message, parsed, _ = self._imap(
                credential, lambda session, email: self._read(session, email, reference)
            )
            addresses = message.reply_to or self._addresses(parsed, "From")
            if reply_all:
                addresses += message.to + message.cc
            email = credential.email or ""
            recipients = list(
                dict.fromkeys(
                    address for address in addresses if address.casefold() != email.casefold()
                )
            )
            if not recipients:
                raise InvalidInput()
            subject = (
                message.subject
                if message.subject.lower().startswith("re:")
                else "Re: " + message.subject
            )
            outgoing = MailOutgoingMessage(
                to=recipients, subject=subject, text=text, attachments=attachments or []
            )
            return self._smtp(credential, outgoing, reply_id=message.message_id)

        return await self._run(action)

    async def forward(
        self,
        reference: MailMessageRef,
        to: list[str],
        *,
        text: str = "",
        cc: list[str] | None = None,
        bcc: list[str] | None = None,
    ) -> MailSendResult:
        """Forward the bounded original body and attachments through one SMTP submission."""
        credential = await self._credential()

        def action() -> MailSendResult:
            message, _, files = self._imap(
                credential, lambda session, email: self._read(session, email, reference)
            )
            forwarded = []
            for attachment, payload in files.values():
                if len(payload) > self.max_attachment_bytes:
                    raise InvalidInput("Mail attachment exceeds the configured size limit.")
                forwarded.append(
                    MailOutgoingAttachment(
                        filename=attachment.filename or "attachment",
                        content_type=attachment.content_type,
                        content_base64=base64.b64encode(payload).decode(),
                    )
                )
            subject = (
                message.subject
                if message.subject.lower().startswith("fwd:")
                else "Fwd: " + message.subject
            )
            quoted = f"{text}\n\n--- Forwarded message ---\nFrom: {message.sender}\nSubject: {message.subject}\n\n{message.text or ''}"
            html_body = None
            if message.html is not None:
                prefix = f"{text}\n\n--- Forwarded message ---\nFrom: {message.sender}\nSubject: {message.subject}"
                html_body = "<pre>" + html.escape(prefix) + "</pre>\n" + message.html
            outgoing = MailOutgoingMessage(
                to=to,
                cc=cc or [],
                bcc=bcc or [],
                subject=subject,
                text=quoted,
                html=html_body,
                attachments=forwarded,
            )
            return self._smtp(credential, outgoing)

        return await self._run(action)

    async def set_read(self, reference: MailMessageRef, is_read: bool) -> MailMutationResult:
        """Set only the named UID's Seen flag, after checking its account and UIDVALIDITY."""
        credential = await self._credential()

        def action(session: _ImapSession, email: str) -> MailMutationResult:
            self._select(session, reference.folder, email, reference, readonly=False)
            self._metadata(session, reference.uid)
            self._ok(
                session.call(
                    "uid",
                    "STORE",
                    str(reference.uid),
                    "+FLAGS.SILENT" if is_read else "-FLAGS.SILENT",
                    "(\\Seen)",
                )
            )
            return MailMutationResult(reference=reference, action="read" if is_read else "unread")

        return await self._run(partial(self._imap, credential, action))

    async def trash(self, reference: MailMessageRef) -> MailMutationResult:
        """Move one UID to the server's Trash; never fall back to DELETE or EXPUNGE."""
        credential = await self._credential()

        def action(session: _ImapSession, email: str) -> MailMutationResult:
            self._select(session, reference.folder, email, reference, readonly=False)
            capability_rows = self._ok(session.call("capability"))
            if any(not isinstance(value, bytes) for value in capability_rows):
                raise ContractMismatchError()
            capabilities = {item.upper() for value in capability_rows for item in value.split()}
            if b"MOVE" not in capabilities:
                raise APIError("Safe UID MOVE is unavailable; no mail was changed.")
            folders = self._folders(session).folders
            choices = [
                folder.name
                for folder in folders
                if folder.selectable and "\\trash" in {flag.lower() for flag in folder.flags}
            ]
            if len(choices) != 1:
                raise APIError("A unique Trash folder is unavailable; no mail was changed.")
            destination = choices[0]
            if destination == reference.folder:
                raise InvalidInput("The message is already in Trash.")
            self._metadata(session, reference.uid)
            self._ok(session.call("uid", "MOVE", str(reference.uid), _encode_folder(destination)))
            return MailMutationResult(
                reference=reference, action="trash", destination_folder=destination
            )

        return await self._run(partial(self._imap, credential, action))
