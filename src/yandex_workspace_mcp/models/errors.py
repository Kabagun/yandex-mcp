import re
import urllib.parse
from typing import Any

from .base import PublicModel


class MCPError(Exception):
    """Base exception for MCP-facing failures."""

    def __init__(self, message: str, code: int = -32000, data: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.data = data or {}


class UnsupportedProtocolVersionError(MCPError):
    def __init__(self, message: str):
        super().__init__(message, code=-32022)


class HeaderMismatchError(MCPError):
    pass


class YandexWorkspaceError(MCPError):
    category = "workspace_error"
    retryable = False

    def __init__(self, message: str | None = None):
        safe_message = message or _PUBLIC_MESSAGES[self.category]
        super().__init__(
            safe_message,
            data={"code": self.category, "retryable": self.retryable},
        )


class ConfigurationError(YandexWorkspaceError):
    category = "configuration_error"


class InvalidInput(YandexWorkspaceError, ValueError):
    category = "invalid_input"


class AuthenticationError(YandexWorkspaceError):
    category = "authentication_error"


class PermissionDenied(YandexWorkspaceError):
    category = "permission_denied"


class InvalidPath(YandexWorkspaceError):
    category = "invalid_path"


class ResourceNotFound(YandexWorkspaceError):
    category = "resource_not_found"


class RevisionConflict(YandexWorkspaceError):
    category = "conflict"


class RateLimitExceeded(YandexWorkspaceError):
    category = "rate_limited"
    retryable = True


class UpstreamUnavailable(YandexWorkspaceError):
    category = "upstream_unavailable"
    retryable = True


class UpstreamTimeout(YandexWorkspaceError):
    category = "upstream_timeout"


class ContractMismatchError(YandexWorkspaceError):
    category = "contract_mismatch"


class APIError(YandexWorkspaceError):
    category = "upstream_error"


_PUBLIC_MESSAGES = {
    "workspace_error": "Workspace operation failed.",
    "configuration_error": "Server configuration is invalid.",
    "invalid_input": "Input is invalid.",
    "authentication_error": "Invalid or missing authentication.",
    "permission_denied": "Permission denied for this operation.",
    "invalid_path": "Invalid or unauthorized path.",
    "resource_not_found": "Resource not found.",
    "conflict": "The resource changed or is locked.",
    "rate_limited": "Rate limit exceeded. Try again later.",
    "upstream_unavailable": "Yandex API is unavailable.",
    "upstream_timeout": "Yandex API timed out.",
    "contract_mismatch": "Yandex API response did not match the expected contract.",
    "upstream_error": "Yandex API returned an error.",
    "mail_submission_uncertain": (
        "Mail submission outcome is unknown. Check the account before sending again."
    ),
}

_SENSITIVE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "token",
    "access_token",
    "refresh_token",
    "client_secret",
    "response_body",
    "request_body",
    "body",
    "content",
    "public_key",
    "authorization_code",
    "code_verifier",
    "signed_url",
    "public_url",
    "redis_url",
    "state",
    "nonce",
}
_BEARER_PATTERN = re.compile(r"(?i)\b(?:bearer|oauth)\s+[A-Za-z0-9._~+/-]+")
_INLINE_SECRET_PATTERN = re.compile(
    r"(?i)\b(access_token|refresh_token|client_secret|authorization_code|code_verifier|state|signature)"
    r"=([^\s&;]+)"
)
_COOKIE_PATTERN = re.compile(r"(?i)\b(?:cookie|set-cookie):\s*[^\r\n;]+")
_URL_PATTERN = re.compile(r"(?i)https?://[^\s\"']+")
_RECOVERY_PATH_PATTERN = re.compile(r"(?i)(/recovery_tokens/)[^/?#]+")


class SafeError(PublicModel):
    category: str
    message: str
    retryable: bool
    correlation_id: str
    method_category: str | None = None
    normalized_locator: str | None = None


def _redact_url(value: str) -> str:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return "[REDACTED]"
    if parsed.scheme in {"redis", "rediss"}:
        return f"{parsed.scheme}://[REDACTED]"
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return value
    host = parsed.hostname
    try:
        if parsed.port is not None:
            host = f"{host}:{parsed.port}"
    except ValueError:
        return "[REDACTED]"
    safe_path = _RECOVERY_PATH_PATTERN.sub(r"\1[REDACTED]", parsed.path)
    return urllib.parse.urlunsplit((parsed.scheme, host, safe_path, "", ""))


def _is_sensitive_key(key: Any) -> bool:
    normalized = str(key).casefold().replace("-", "_")
    return normalized in _SENSITIVE_KEYS or normalized.endswith(("_token", "_secret", "_cookie"))


def redact_sensitive(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: ("[REDACTED]" if _is_sensitive_key(key) else redact_sensitive(item))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive(item) for item in value)
    if isinstance(value, str):
        if value.startswith(("http://", "https://", "redis://", "rediss://")):
            return _redact_url(value)
        redacted = _URL_PATTERN.sub(lambda match: _redact_url(match.group(0)), value)
        redacted = _RECOVERY_PATH_PATTERN.sub(r"\1[REDACTED]", redacted)
        redacted = _BEARER_PATTERN.sub("[REDACTED]", redacted)
        redacted = _INLINE_SECRET_PATTERN.sub(r"\1=[REDACTED]", redacted)
        return _COOKIE_PATTERN.sub("cookie: [REDACTED]", redacted)
    return value


def to_safe_error(
    error: BaseException,
    *,
    correlation_id: str,
    method_category: str | None = None,
    normalized_locator: str | None = None,
) -> SafeError:
    if isinstance(error, YandexWorkspaceError):
        category = error.category
        retryable = error.retryable
    else:
        category = "upstream_error"
        retryable = False
    return SafeError(
        category=category,
        message=_PUBLIC_MESSAGES.get(category, _PUBLIC_MESSAGES["workspace_error"]),
        retryable=retryable,
        correlation_id=correlation_id,
        method_category=method_category,
        normalized_locator=(
            redact_sensitive(normalized_locator) if normalized_locator is not None else None
        ),
    )
