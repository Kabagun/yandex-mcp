import pytest
from pydantic import ValidationError

from yandex_workspace_mcp.models.mail import (
    MailMessageRef,
    MailOutgoingAttachment,
    MailOutgoingMessage,
    MailSendResult,
)


@pytest.mark.parametrize(
    "updates",
    [
        {"uid": 0},
        {"uid_validity": 0},
        {"account_id": "token"},
        {"folder": "INBOX\nLOGOUT"},
        {"uid": True},
        {"uid": 2**32},
        {"extra": "forbidden"},
    ],
)
def test_message_reference_is_strict_bounded_and_header_safe(updates) -> None:
    values = {"account_id": "a" * 64, "folder": "INBOX", "uid": 1, "uid_validity": 1}
    with pytest.raises(ValidationError):
        MailMessageRef(**(values | updates))


@pytest.mark.parametrize("subject", ["hello\r\nBcc: injected@example.test", "x\x00", "x\x7f"])
def test_outgoing_subject_rejects_header_injection(subject) -> None:
    with pytest.raises(ValidationError):
        MailOutgoingMessage(to=["to@example.test"], subject=subject)


@pytest.mark.parametrize(
    "values",
    [
        {"filename": "file\r\nheader", "content_base64": ""},
        {"filename": "file", "content_type": "text/plain\nheader", "content_base64": ""},
    ],
)
def test_attachment_headers_reject_injection(values) -> None:
    with pytest.raises(ValidationError):
        MailOutgoingAttachment(**values)


def test_send_result_distinguishes_acceptance_from_delivery_and_sent_copy() -> None:
    result = MailSendResult(
        status="accepted",
        message_id="<example@example.test>",
        accepted_recipients=["to@example.test"],
    )
    assert result.delivery_confirmed is False and result.sent_copy_saved is False
