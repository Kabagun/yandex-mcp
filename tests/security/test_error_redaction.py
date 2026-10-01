from yandex_workspace_mcp.logging import setup_logging
from yandex_workspace_mcp.models.errors import (
    AuthenticationError,
    redact_sensitive,
    to_safe_error,
)


def test_safe_error_never_exposes_exception_chain_or_tokens() -> None:
    token = "ya29.super-secret-token-value"
    try:
        try:
            raise RuntimeError(
                f"Authorization: Bearer {token}; https://host/path?token={token}#fragment"
            )
        except RuntimeError as cause:
            raise AuthenticationError(f"OAuth {token}") from cause
    except AuthenticationError as exc:
        safe = to_safe_error(
            exc,
            correlation_id="corr-1",
            method_category="wiki.read",
            normalized_locator="/Team/Page",
        )

    serialized = safe.model_dump_json()
    assert token not in serialized
    assert "Authorization" not in serialized
    assert "fragment" not in serialized
    assert safe.category == "authentication_error"
    assert safe.correlation_id == "corr-1"


def test_recursive_redaction_removes_headers_bodies_and_url_secrets() -> None:
    value = {
        "Authorization": "Bearer secret",
        "cookie": "session=secret",
        "response_body": "private content",
        "file_id": "opaque-private-file",
        "download_url": "https://files.example.test/private-capability?sig=private",
        "nested": {
            "url": "https://user:pass@example.com/path?token=secret#fragment",
            "safe": "kept",
        },
    }

    redacted = redact_sensitive(value)

    assert redacted["Authorization"] == "[REDACTED]"
    assert redacted["cookie"] == "[REDACTED]"
    assert redacted["response_body"] == "[REDACTED]"
    assert redacted["file_id"] == "[REDACTED]"
    assert redacted["download_url"] == "[REDACTED]"
    assert redacted["nested"]["url"] == "https://example.com/path"
    assert redacted["nested"]["safe"] == "kept"


def test_auth_codes_redis_urls_and_nested_secret_keys_are_redacted() -> None:
    value = {
        "authorization_code": "raw-code",
        "yandex_refresh_token": "refresh-secret",
        "redis": "redis://user:password@redis.internal/0",
        "message": "state=csrf-secret code_verifier=pkce-secret Cookie: sid=session-secret",
        "callback": "https://mcp.example/callback?code=raw-code&state=csrf-secret",
    }

    serialized = repr(redact_sensitive(value))
    for secret in (
        "raw-code",
        "refresh-secret",
        "password",
        "csrf-secret",
        "pkce-secret",
        "session-secret",
    ):
        assert secret not in serialized


def test_stdlib_http_logs_redact_signed_queries_recovery_paths_and_exception_text(
    capsys,
) -> None:
    import logging

    setup_logging("INFO")
    logger = logging.getLogger("probe")
    try:
        raise RuntimeError(
            "https://wiki.yandex.ru/recovery_tokens/recovery-secret/recover?state=csrf-secret"
        )
    except RuntimeError:
        logger.exception(
            "HTTP Request: GET https://downloader.disk.yandex.net/file?signature=TOPSECRET"
        )

    output = capsys.readouterr().err
    for secret in ("TOPSECRET", "recovery-secret", "csrf-secret"):
        assert secret not in output
    assert "[REDACTED]" in output
