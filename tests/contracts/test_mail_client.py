"""Mail protocol checks use in-memory fakes only; no real mailbox is contacted."""

from __future__ import annotations

import asyncio
import base64
import builtins
import hashlib
import imaplib
import smtplib
from contextvars import ContextVar
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from typing import Any
from unittest.mock import Mock

import pytest

from yandex_workspace_mcp.auth.models import YandexOAuthCredential
from yandex_workspace_mcp.clients.mail import YandexMailClient, _encode_folder
from yandex_workspace_mcp.models.errors import (
    APIError,
    AuthenticationError,
    ContractMismatchError,
    InvalidInput,
    ResourceNotFound,
    RevisionConflict,
    UpstreamTimeout,
    UpstreamUnavailable,
)
from yandex_workspace_mcp.models.mail import (
    MailMessageRef,
    MailOutgoingAttachment,
    MailOutgoingMessage,
    MailSubmissionUncertain,
)


def reference(email: str = "owner@yandex.ru", **updates: Any) -> MailMessageRef:
    values = {
        "account_id": hashlib.sha256(email.casefold().encode()).hexdigest(),
        "folder": "INBOX",
        "uid": 7,
        "uid_validity": 123,
    }
    return MailMessageRef.model_validate(values | updates)


def raw_message() -> bytes:
    message = EmailMessage(policy=policy.SMTP)
    message["From"] = "sender@example.test"
    message["To"] = "owner@yandex.ru"
    message["Cc"] = "copied@example.test"
    message["Reply-To"] = "reply@example.test"
    message["Subject"] = "Письмо"
    message["Message-ID"] = "<original@example.test>"
    message.set_content("message body")
    message.add_alternative("<p>message body</p>", subtype="html")
    message.add_attachment(
        b"attachment bytes", maintype="application", subtype="octet-stream", filename="file.bin"
    )
    return message.as_bytes()


class FakeImap:
    def __init__(self, raw: bytes | None = None) -> None:
        self.raw = raw if raw is not None else raw_message()
        self.sock = Mock()
        self.capabilities = (b"IMAP4rev1", b"MOVE", b"AUTH=XOAUTH2")
        self.post_auth_capabilities: tuple[bytes, ...] | None = None
        self.calls: list[tuple[Any, ...]] = []
        self.validity = 123
        self.uid_next = 8
        self.uid_values = [7]
        self.declared_size = len(self.raw)
        self.auth_error: Exception | None = None
        self.uid_error: Exception | None = None
        self.list_rows: list[Any] = [
            b'(\\HasNoChildren) "/" "INBOX"',
            b'(\\Trash \\HasNoChildren) "/" "Trash"',
        ]

    def authenticate(self, mechanism: str, callback: Any) -> tuple[str, list[bytes]]:
        self.calls.append(("authenticate", mechanism, callback(b""), callback(b"challenge")))
        if self.auth_error:
            raise self.auth_error
        return "OK", [b"authenticated"]

    def select(self, folder: bytes, readonly: bool) -> tuple[str, list[bytes]]:
        self.calls.append(("select", folder, readonly))
        return "OK", [b"1"]

    def response(self, name: str) -> tuple[str, list[bytes]]:
        return name, [str(self.validity if name == "UIDVALIDITY" else self.uid_next).encode()]

    def list(self, *args: Any) -> tuple[str, list[Any]]:
        self.calls.append(("list", *args))
        return "OK", self.list_rows

    def capability(self) -> tuple[str, builtins.list[bytes]]:
        self.calls.append(("capability",))
        return "OK", [b" ".join(self.post_auth_capabilities or self.capabilities)]

    def uid(self, *args: Any) -> tuple[str, builtins.list[Any]]:
        self.calls.append(("uid", *args))
        if self.uid_error:
            raise self.uid_error
        if args[0] == "SEARCH":
            start, end = map(int, str(args[4]).split(":"))
            return "OK", [
                b" ".join(str(uid).encode() for uid in self.uid_values if start <= uid <= end)
            ]
        if args[0] == "FETCH":
            uid = int(args[1])
            if uid not in self.uid_values:
                return "OK", [None]
            if "RFC822.SIZE" in args[2]:
                return "OK", [
                    f"1 (UID {uid} RFC822.SIZE {self.declared_size} FLAGS (\\Seen))".encode()
                ]
            raw = (
                self.raw.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
                if "HEADER.FIELDS" in args[2]
                else self.raw
            )
            return "OK", [(f"1 (UID {uid} BODY[] {{{len(raw)}}}".encode(), raw), b")"]
        return "OK", [b"changed"]

    def shutdown(self) -> None:
        self.calls.append(("shutdown",))


class FakeSmtp:
    def __init__(self) -> None:
        self.sock = Mock()
        self.esmtp_features = {"auth": "PLAIN XOAUTH2"}
        self.calls: list[tuple[Any, ...]] = []
        self.refused: dict[str, Any] = {}
        self.auth_error: Exception | None = None
        self.send_error: Exception | None = None

    def ehlo(self) -> tuple[int, bytes]:
        self.calls.append(("ehlo",))
        return 250, b"hello"

    def auth(self, mechanism: str, callback: Any) -> None:
        self.calls.append(("auth", mechanism, callback(), callback(b"challenge")))
        if self.auth_error:
            raise self.auth_error

    def sendmail(self, *args: Any) -> dict[str, Any]:
        self.calls.append(("sendmail", *args))
        if self.send_error:
            raise self.send_error
        return self.refused

    def close(self) -> None:
        self.calls.append(("close",))


@pytest.fixture
def transports(monkeypatch):
    imap = FakeImap()
    smtp = FakeSmtp()
    imap_factory = Mock(return_value=imap)
    smtp_factory = Mock(return_value=smtp)
    monkeypatch.setattr(imaplib, "IMAP4_SSL", imap_factory)
    monkeypatch.setattr(smtplib, "SMTP_SSL", smtp_factory)
    return imap, smtp, imap_factory, smtp_factory


def client(**kwargs: Any) -> YandexMailClient:
    async def provider() -> YandexOAuthCredential:
        return YandexOAuthCredential("private-token", email="owner@yandex.ru")

    return YandexMailClient(credential_provider=provider, **kwargs)


async def test_folders_decode_unicode_quoting_and_literal_names(transports) -> None:
    imap, _, factory, _ = transports
    folder = 'Почта " \\ &'
    encoded = _encode_folder(folder)
    imap.list_rows = [b'(\\HasNoChildren) "/" ' + encoded, (b"(\\Noselect) NIL {6}", b"Parent")]
    folders = await client().folders()
    assert folders.folders[0].name == folder
    assert folders.folders[0].delimiter == "/"
    assert folders.folders[1].selectable is False
    assert factory.call_args.args == ("imap.yandex.ru", 993)
    assert factory.call_args.kwargs["ssl_context"].check_hostname
    assert imap.calls[0] == (
        "authenticate",
        "XOAUTH2",
        b"user=owner@yandex.ru\x01auth=Bearer private-token\x01\x01",
        b"",
    )
    assert imap.calls[-1] == ("shutdown",)


async def test_list_search_bounded_uid_window_and_continuation(transports) -> None:
    imap, _, _, _ = transports
    imap.uid_next = 5000
    imap.uid_values = [4999, 4998, 4997]
    result = await client().list_messages('Привет "\\', limit=2, query='текст "\\')
    assert [item.reference.uid for item in result.messages] == [4999, 4998]
    assert (result.scan_start_uid, result.scan_end_uid) == (4000, 4999)
    assert result.next_before_uid == 4997 and result.partial_scan
    assert imap.calls[1] == ("select", _encode_folder('Привет "\\'), True)
    search = next(call for call in imap.calls if call[:2] == ("uid", "SEARCH"))
    assert search[2:6] == ("CHARSET", "UTF-8", "UID", "4000:4999")
    assert search[6] == "TEXT" and search[7].startswith(b'"')
    assert all(
        "BODY.PEEK" in call[3]
        for call in imap.calls
        if call[:2] == ("uid", "FETCH") and "RFC822.SIZE" not in call[3]
    )


async def test_read_and_attachment_use_size_prefetch_and_do_not_mark_seen(transports) -> None:
    imap, _, _, _ = transports
    mail = client()
    message = await mail.read_message(reference())
    assert "message body" in (message.text or "") and message.subject == "Письмо"
    assert message.html == "<p>message body</p>\r\n"
    assert len(message.attachments) == 1
    attachment = await mail.read_attachment(reference(), message.attachments[0].attachment_id)
    assert base64.b64decode(attachment.content_base64) == b"attachment bytes"
    fetches = [call for call in imap.calls if call[:2] == ("uid", "FETCH")]
    assert fetches[0][3] == "(UID RFC822.SIZE FLAGS)"
    assert fetches[1][3] == f"(UID BODY.PEEK[]<0.{mail.max_message_bytes + 1}>)"
    assert not any(call[:2] == ("uid", "STORE") for call in imap.calls)


@pytest.mark.parametrize("operation", ["read_message", "trash", "set_read"])
async def test_stale_uidvalidity_blocks_content_and_mutations(transports, operation) -> None:
    imap, _, _, _ = transports
    args = (
        (reference(uid_validity=999), False)
        if operation == "set_read"
        else (reference(uid_validity=999),)
    )
    with pytest.raises(RevisionConflict):
        await getattr(client(), operation)(*args)
    assert not any(call[0] == "uid" for call in imap.calls)


async def test_foreign_account_reference_rejected_before_select(transports) -> None:
    imap, _, _, _ = transports
    with pytest.raises(ResourceNotFound):
        await client().read_message(reference("other@yandex.ru"))
    assert not any(call[0] == "select" for call in imap.calls)


async def test_missing_uid_is_not_found(transports) -> None:
    imap, _, _, _ = transports
    imap.uid_values = []
    with pytest.raises(ResourceNotFound):
        await client().read_message(reference())


async def test_mime_size_is_checked_before_body_fetch(transports) -> None:
    imap, _, _, _ = transports
    with pytest.raises(InvalidInput):
        await client(max_message_bytes=100).read_message(reference())
    assert len([call for call in imap.calls if call[:2] == ("uid", "FETCH")]) == 1


async def test_server_underreported_size_does_not_bypass_body_cap(transports) -> None:
    imap, _, _, _ = transports
    imap.declared_size = 10
    with pytest.raises(InvalidInput):
        await client(max_message_bytes=100).read_message(reference())


async def test_mismatched_body_size_is_contract_error(transports) -> None:
    imap, _, _, _ = transports
    imap.declared_size += 1
    with pytest.raises(ContractMismatchError):
        await client().read_message(reference())


async def test_attachment_decode_cap(transports) -> None:
    mail = client(max_attachment_bytes=2)
    message = await mail.read_message(reference())
    with pytest.raises(InvalidInput):
        await mail.read_attachment(reference(), message.attachments[0].attachment_id)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"folder": "INBOX\r\nUID MOVE 1 Trash"},
        {"query": "x\r\nLOGOUT"},
        {"query": "x\x00"},
        {"limit": 101},
        {"before_uid": 0},
    ],
)
async def test_imap_injection_and_unbounded_inputs_rejected_before_connect(
    transports, kwargs
) -> None:
    _, _, factory, _ = transports
    with pytest.raises(InvalidInput):
        await client().list_messages(**kwargs)
    factory.assert_not_called()


async def test_two_concurrent_users_get_distinct_connections_and_credentials(monkeypatch) -> None:
    account: ContextVar[str] = ContextVar("test_mail_account")
    connections: list[FakeImap] = []

    def make_connection(*args, **kwargs):
        connection = FakeImap()
        connections.append(connection)
        return connection

    monkeypatch.setattr(imaplib, "IMAP4_SSL", make_connection)

    async def provider() -> YandexOAuthCredential:
        await asyncio.sleep(0)
        email = account.get()
        return YandexOAuthCredential("token-" + email, email=email)

    mail = YandexMailClient(credential_provider=provider)

    async def read(email):
        marker = account.set(email)
        try:
            return await mail.read_message(reference(email))
        finally:
            account.reset(marker)

    results = await asyncio.gather(read("first@yandex.ru"), read("second@yandex.ru"))
    assert len(connections) == 2 and connections[0] is not connections[1]
    auths = {connection.calls[0][2] for connection in connections}
    assert auths == {
        f"user={email}\x01auth=Bearer token-{email}\x01\x01".encode()
        for email in ("first@yandex.ru", "second@yandex.ru")
    }
    assert results[0].reference.account_id != results[1].reference.account_id


@pytest.mark.parametrize(
    "failure,error",
    [
        (imaplib.IMAP4.error("private-token message body"), APIError),
        (imaplib.IMAP4.abort("private-token message body"), UpstreamUnavailable),
        (TimeoutError("private-token message body"), UpstreamTimeout),
    ],
)
async def test_protocol_failures_are_redacted(transports, failure, error, capsys) -> None:
    imap, _, _, _ = transports
    imap.uid_error = failure
    with pytest.raises(error) as captured:
        await client().read_message(reference())
    assert "private-token" not in str(captured.value) and "message body" not in str(captured.value)
    assert captured.value.__suppress_context__
    assert "private-token" not in capsys.readouterr().err


async def test_auth_failures_and_missing_email_fail_closed(transports) -> None:
    imap, _, factory, _ = transports
    imap.auth_error = imaplib.IMAP4.error("private-token secret response")
    with pytest.raises(AuthenticationError) as captured:
        await client().folders()
    assert "private-token" not in str(captured.value)
    factory.reset_mock()

    async def provider():
        return YandexOAuthCredential("private-token")

    with pytest.raises(AuthenticationError):
        await YandexMailClient(credential_provider=provider).folders()
    factory.assert_not_called()


async def test_trash_uses_only_one_uid_move_without_global_expunge(transports) -> None:
    imap, _, _, _ = transports
    result = await client().trash(reference())
    assert result.destination_folder == "Trash"
    assert ("uid", "MOVE", "7", b'"Trash"') in imap.calls
    assert not any(
        call[0].upper() in {"CLOSE", "EXPUNGE"}
        or (call[0] == "uid" and call[1] in {"STORE", "EXPUNGE", "COPY"})
        for call in imap.calls
    )


async def test_trash_without_move_does_not_change_flags_or_copy(transports) -> None:
    imap, _, _, _ = transports
    imap.capabilities = (b"IMAP4rev1",)
    with pytest.raises(APIError, match="no mail was changed"):
        await client().trash(reference())
    assert not any(call[0] == "uid" for call in imap.calls)


async def test_trash_refreshes_post_authentication_move_capability(transports) -> None:
    imap, _, _, _ = transports
    imap.capabilities = (b"IMAP4rev1", b"AUTH=XOAUTH2")
    imap.post_auth_capabilities = (b"IMAP4rev1", b"MOVE")
    await client().trash(reference())
    assert ("capability",) in imap.calls
    assert ("uid", "MOVE", "7", b'"Trash"') in imap.calls


async def test_trash_without_unique_server_special_use_folder_fails_closed(transports) -> None:
    imap, _, _, _ = transports
    imap.list_rows = [b'(\\HasNoChildren) "/" "Trash"']
    with pytest.raises(APIError, match="no mail was changed"):
        await client().trash(reference())
    assert not any(call[:2] == ("uid", "MOVE") for call in imap.calls)


async def test_set_read_targets_only_one_uid(transports) -> None:
    imap, _, _, _ = transports
    result = await client().set_read(reference(), False)
    assert result.action == "unread"
    assert ("uid", "STORE", "7", "-FLAGS.SILENT", "(\\Seen)") in imap.calls


async def test_smtp_fixed_tls_from_bcc_and_partial_acceptance(transports) -> None:
    _, smtp, _, factory = transports
    smtp.refused = {"refused@example.test": (550, b"private-token rejection")}
    result = await client().send(
        MailOutgoingMessage(
            to=["to@example.test", "refused@example.test"],
            bcc=["blind@example.test"],
            subject="Тема",
            text="body",
        )
    )
    assert result.status == "partially_accepted"
    assert result.accepted_recipients == ["to@example.test", "blind@example.test"]
    assert result.rejected_recipients == ["refused@example.test"]
    assert not result.delivery_confirmed and not result.sent_copy_saved
    assert factory.call_args.args == ("smtp.yandex.ru", 465)
    assert factory.call_args.kwargs["context"].check_hostname
    sent = next(call for call in smtp.calls if call[0] == "sendmail")
    parsed = BytesParser(policy=policy.default).parsebytes(sent[3])
    assert sent[1] == "owner@yandex.ru" and parsed["From"] == "owner@yandex.ru"
    assert parsed["Date"] is not None
    assert parsed["Bcc"] is None and "blind@example.test" not in sent[3].decode()
    assert smtp.calls[-1] == ("close",)


@pytest.mark.parametrize(
    "failure,error",
    [
        (TimeoutError("private-token body"), MailSubmissionUncertain),
        (smtplib.SMTPServerDisconnected("private-token body"), MailSubmissionUncertain),
        (smtplib.SMTPDataError(550, b"private-token body"), APIError),
        (smtplib.SMTPRecipientsRefused({"to@example.test": (550, b"private-token")}), InvalidInput),
    ],
)
async def test_smtp_failures_do_not_retry_or_expose_protocol_details(
    transports, failure, error
) -> None:
    _, smtp, _, _ = transports
    smtp.send_error = failure
    with pytest.raises(error) as captured:
        await client().send(MailOutgoingMessage(to=["to@example.test"], text="body"))
    assert "private-token" not in str(captured.value) and not captured.value.retryable
    assert len([call for call in smtp.calls if call[0] == "sendmail"]) == 1


@pytest.mark.parametrize(
    "message",
    [
        MailOutgoingMessage(to=["to@example.test\r\nBcc: x@example.test"]),
        MailOutgoingMessage(to=["Name <to@example.test>"]),
        MailOutgoingMessage(
            to=["to@example.test"],
            attachments=[MailOutgoingAttachment(filename="x", content_base64="%%%%")],
        ),
        MailOutgoingMessage(
            to=["to@example.test"],
            attachments=[
                MailOutgoingAttachment(
                    filename="x", content_base64=base64.b64encode(b"too large").decode()
                )
            ],
        ),
        MailOutgoingMessage(to=["to@example.test"], text="x" * 2000),
    ],
)
async def test_outgoing_injection_and_size_caps_reject_before_smtp(transports, message) -> None:
    _, _, _, factory = transports
    with pytest.raises(InvalidInput):
        await client(max_attachment_bytes=2, max_message_bytes=1000).send(message)
    factory.assert_not_called()


async def test_reply_and_forward_threading_and_credential_resolution_once(transports) -> None:
    _, smtp, _, _ = transports
    calls = 0

    async def provider():
        nonlocal calls
        calls += 1
        return YandexOAuthCredential("private-token", email="owner@yandex.ru")

    mail = YandexMailClient(credential_provider=provider)
    await mail.reply(reference(), "reply body", reply_all=True)
    assert calls == 1
    sent = next(call for call in smtp.calls if call[0] == "sendmail")
    parsed = BytesParser(policy=policy.default).parsebytes(sent[3])
    assert sent[2] == ["reply@example.test", "copied@example.test"]
    assert parsed["In-Reply-To"] == "<original@example.test>"
    assert parsed["References"] == "<original@example.test>"
    await mail.forward(reference(), ["forward@example.test"], text="forward intro <private>")
    assert calls == 2
    parsed = BytesParser(policy=policy.default).parsebytes(
        [call for call in smtp.calls if call[0] == "sendmail"][-1][3]
    )
    plain_body = parsed.get_body(preferencelist=("plain",))
    html_body = parsed.get_body(preferencelist=("html",))
    assert plain_body is not None and html_body is not None
    assert "forward intro" in plain_body.get_content()
    assert "forward intro &lt;private&gt;" in html_body.get_content()
    assert [part.get_filename() for part in parsed.iter_attachments()] == ["file.bin"]


async def test_smtp_auth_failure_is_redacted_and_never_sends(transports) -> None:
    _, smtp, _, _ = transports
    smtp.auth_error = smtplib.SMTPAuthenticationError(535, b"private-token response")
    with pytest.raises(AuthenticationError) as captured:
        await client().send(MailOutgoingMessage(to=["to@example.test"]))
    assert "private-token" not in str(captured.value)
    assert not any(call[0] == "sendmail" for call in smtp.calls)


async def test_attached_message_stays_opaque_when_read_and_forwarded(transports) -> None:
    imap, smtp, _, _ = transports
    nested = EmailMessage(policy=policy.SMTP)
    nested["From"] = "nested@example.test"
    nested["Subject"] = "Nested mail"
    nested.set_content("nested secret body")
    parent = EmailMessage(policy=policy.SMTP)
    parent["From"] = "sender@example.test"
    parent["Subject"] = "Parent mail"
    parent.set_content("parent body")
    parent.add_attachment(nested, subtype="rfc822", filename="original.eml")
    imap.raw = parent.as_bytes()
    imap.declared_size = len(imap.raw)
    mail = client()
    message = await mail.read_message(reference())
    assert message.text is not None
    assert "parent body" in message.text and "nested secret" not in message.text
    assert len(message.attachments) == 1
    metadata = message.attachments[0]
    assert metadata.filename == "original.eml" and metadata.content_type == "message/rfc822"
    attachment = await mail.read_attachment(reference(), metadata.attachment_id)
    assert b"nested secret body" in base64.b64decode(attachment.content_base64)
    await mail.forward(reference(), ["forward@example.test"], text="intro")
    sent = next(call for call in smtp.calls if call[0] == "sendmail")
    forwarded = BytesParser(policy=policy.default).parsebytes(sent[3])
    plain_body = forwarded.get_body(preferencelist=("plain",))
    assert plain_body is not None
    assert "nested secret" not in plain_body.get_content()
    attached = list(forwarded.iter_attachments())
    assert attached[0].get_content_type() == "message/rfc822"
    payload = attached[0].get_payload()
    assert isinstance(payload, list) and isinstance(payload[0], EmailMessage)
    assert "nested secret body" in payload[0].get_content()
