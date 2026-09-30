import base64
import hashlib
import hmac
import ipaddress
import os
from enum import StrEnum
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class McpAuthMode(StrEnum):
    LOCAL = "local"
    STATIC = "static"
    MULTI_USER = "multi-user"


class YandexAuthMode(StrEnum):
    OAUTH = "oauth"
    IAM = "iam"
    MULTI_USER = "multi-user"


class AuthStoreBackend(StrEnum):
    MEMORY = "memory"
    REDIS = "redis"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
        frozen=True,
    )

    # Transports
    mcp_profile: Literal["workspace", "disk", "mail"] = "workspace"
    mcp_transport: str = Field(
        default="stdio", description="MCP transport to use: 'stdio' or 'streamable-http'"
    )
    mcp_host: str = Field(default="127.0.0.1", description="HTTP host for Streamable HTTP")
    mcp_port: int = Field(default=8000, validation_alias="MCP_PORT")
    mcp_auth_token: SecretStr | None = Field(default=None, validation_alias="MCP_AUTH_TOKEN")
    mcp_auth_mode: McpAuthMode = Field(default=McpAuthMode.LOCAL)
    mcp_static_scopes: list[str] = Field(default_factory=list)
    mcp_cursor_keys: list[SecretStr] = Field(
        default_factory=list, validation_alias="MCP_CURSOR_KEYS"
    )
    mcp_token_encryption_keys: list[SecretStr] = Field(
        default_factory=list, validation_alias="MCP_TOKEN_ENCRYPTION_KEYS"
    )
    mcp_issuer_url: str = Field(default="http://localhost:8000", validation_alias="MCP_ISSUER_URL")
    mcp_resource_server_url: str = Field(
        default="http://localhost:8000", validation_alias="MCP_RESOURCE_SERVER_URL"
    )
    mcp_oauth_callback_url: str | None = None
    mcp_allowed_hosts: list[str] = Field(default_factory=list)
    mcp_allowed_origins: list[str] = Field(default_factory=list)
    mcp_trusted_proxy_cidrs: list[str] = Field(default_factory=list)
    mcp_max_request_body_bytes: int = Field(default=2 * 1024 * 1024, ge=1)
    mcp_client_registration_cap: int = Field(default=100, ge=1, le=10_000)
    mcp_client_secret_expiry_seconds: int = Field(default=30 * 24 * 3600, ge=60)

    # OAuth state/token persistence. Redis remains an optional dependency.
    auth_store_backend: AuthStoreBackend = AuthStoreBackend.MEMORY
    redis_url: SecretStr | None = None

    # Yandex Workspace Config
    yandex_disk_enabled: bool = Field(default=True)
    yandex_wiki_enabled: bool = Field(default=True)
    yandex_mail_enabled: bool = Field(default=False)

    yandex_oauth_token: SecretStr | None = Field(
        default=None, description="Global Yandex OAuth Token for local execution mode"
    )
    yandex_auth_mode: YandexAuthMode = YandexAuthMode.OAUTH
    yandex_iam_token: SecretStr | None = None
    yandex_iam_org_id: str | None = None
    yandex_oauth_client_id: str | None = None
    yandex_oauth_client_secret: SecretStr | None = None
    yandex_wiki_org_id: str | None = Field(
        default=None, description="Yandex Wiki Organization ID (X-Org-Id or X-Cloud-Org-Id)"
    )
    yandex_wiki_is_cloud_org: bool = Field(
        default=False, description="Set to True if using Yandex Cloud Organization"
    )

    # Permissions
    disk_read: bool = Field(default=True)
    disk_write: bool = Field(default=False)
    disk_delete: bool = Field(default=False)

    wiki_read: bool = Field(default=True)
    wiki_write: bool = Field(default=False)
    wiki_delete: bool = Field(default=False)

    mail_read: bool = True
    mail_write: bool = False
    mail_delete: bool = False
    mail_max_message_bytes: int = Field(default=10 * 1024 * 1024, ge=1024, le=50 * 1024 * 1024)
    mail_max_attachment_bytes: int = Field(default=5 * 1024 * 1024, ge=1, le=25 * 1024 * 1024)
    mail_timeout_seconds: int = Field(default=30, ge=1, le=120)

    # Allowed Roots
    disk_allowed_roots: list[str] = Field(default_factory=list)
    wiki_allowed_roots: list[str] = Field(default_factory=list)
    wiki_upload_allowed_dirs: list[str] = Field(
        default_factory=list, validation_alias="WIKI_UPLOAD_ALLOWED_DIRS"
    )
    disk_upload_allowed_dirs: list[str] = Field(
        default_factory=list, validation_alias="DISK_UPLOAD_ALLOWED_DIRS"
    )
    disk_upload_url_allowed_hosts: list[str] = Field(
        default_factory=list, validation_alias="DISK_UPLOAD_URL_ALLOWED_HOSTS"
    )
    disk_allowed_public_keys: list[str] = Field(
        default_factory=list, validation_alias="DISK_ALLOWED_PUBLIC_KEYS"
    )
    disk_allow_global_destructive: bool = Field(
        default=False, validation_alias="DISK_ALLOW_GLOBAL_DESTRUCTIVE"
    )

    # Limits
    max_search_results: int = Field(default=50)
    max_upload_size_mb: int = Field(default=100)
    max_download_size_mb: int = Field(default=100)
    max_inline_text_size_kb: int = Field(default=512)
    wiki_max_attachment_bytes: int = Field(
        default=100 * 1024 * 1024, validation_alias="WIKI_MAX_ATTACHMENT_BYTES"
    )
    disk_max_upload_bytes: int = Field(
        default=100 * 1024 * 1024,
        ge=1,
        validation_alias="DISK_MAX_UPLOAD_BYTES",
    )
    disk_upload_job_capacity: int = Field(
        default=100,
        ge=1,
        le=10_000,
        validation_alias="DISK_UPLOAD_JOB_CAPACITY",
    )
    disk_upload_job_ttl_seconds: int = Field(
        default=3600,
        ge=1,
        le=86_400,
        validation_alias="DISK_UPLOAD_JOB_TTL_SECONDS",
    )

    @field_validator(
        "disk_allowed_roots",
        "wiki_allowed_roots",
        "wiki_upload_allowed_dirs",
        "disk_upload_allowed_dirs",
        "disk_upload_url_allowed_hosts",
        "disk_allowed_public_keys",
        "mcp_static_scopes",
        "mcp_allowed_hosts",
        "mcp_allowed_origins",
        "mcp_trusted_proxy_cidrs",
        mode="before",
    )
    @classmethod
    def parse_roots(cls, val: Any) -> list[str]:
        if isinstance(val, str):
            # Parse from comma separated string
            return [x.strip() for x in val.split(",") if x.strip()]
        if isinstance(val, list):
            return val
        return []

    @field_validator("mcp_cursor_keys", "mcp_token_encryption_keys", mode="before")
    @classmethod
    def parse_secret_list(cls, val: Any) -> list[str]:
        if isinstance(val, str):
            return [item.strip() for item in val.split(",") if item.strip()]
        if isinstance(val, list):
            return val
        return []

    @field_validator("mcp_allowed_hosts")
    @classmethod
    def validate_allowed_hosts(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for raw in values:
            value = raw.strip().lower().rstrip(".")
            if not value or "*" in value or "://" in value or "/" in value:
                raise ValueError("MCP allowed hosts must be exact host names without wildcards")
            normalized.append(value)
        return normalized

    @field_validator("mcp_allowed_origins")
    @classmethod
    def validate_allowed_origins(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for raw in values:
            value = raw.strip()
            parsed = urlsplit(value)
            if (
                not value
                or "*" in value
                or parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError("MCP allowed origins must be exact HTTP(S) origins")
            normalized.append(value.rstrip("/"))
        return normalized

    @field_validator("mcp_trusted_proxy_cidrs")
    @classmethod
    def validate_proxy_cidrs(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            try:
                normalized.append(str(ipaddress.ip_network(value, strict=False)))
            except ValueError as exc:
                raise ValueError("MCP trusted proxy CIDRs must be valid IP networks") from exc
        return normalized

    @field_validator("mcp_static_scopes")
    @classmethod
    def validate_static_scopes(cls, values: list[str]) -> list[str]:
        allowed = {
            "workspace:read",
            "workspace:write",
            "workspace:delete",
            "mail:read",
            "mail:write",
            "mail:delete",
        }
        if any(value not in allowed for value in values):
            raise ValueError("MCP static scopes contain an unknown workspace scope")
        return list(dict.fromkeys(values))

    @model_validator(mode="after")
    def validate_recovery_encryption_keys(self) -> "Settings":
        if self.mcp_profile != "workspace":
            expected = {
                "yandex_disk_enabled": self.mcp_profile == "disk",
                "yandex_wiki_enabled": False,
                "yandex_mail_enabled": self.mcp_profile == "mail",
            }
            for name, enabled in expected.items():
                if name in self.model_fields_set and getattr(self, name) != enabled:
                    raise ValueError(f"{name} conflicts with the selected MCP profile")
                object.__setattr__(self, name, enabled)
        elif self.yandex_mail_enabled:
            raise ValueError("Mail requires its own MCP_PROFILE=mail process")
        if self.yandex_mail_enabled and self.yandex_auth_mode is not YandexAuthMode.MULTI_USER:
            raise ValueError("Mail requires per-user OAuth authentication")
        if self.disk_allow_global_destructive:
            raise ValueError("Global trash purge is not supported")
        namespace = "mail:" if self.mcp_profile == "mail" else "workspace:"
        if any(not scope.startswith(namespace) for scope in self.mcp_static_scopes):
            raise ValueError("MCP static scopes must belong to the selected profile")
        keys = [item.get_secret_value() for item in self.mcp_token_encryption_keys]
        for value in keys:
            try:
                decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
            except (ValueError, TypeError) as exc:
                raise ValueError("MCP token encryption key is not valid base64url") from exc
            if len(decoded) < 32:
                raise ValueError("MCP token encryption keys must decode to at least 32 bytes")
        if self.mcp_transport == "streamable-http" and self.wiki_delete and not keys:
            raise ValueError("Remote Wiki recovery requires MCP_TOKEN_ENCRYPTION_KEYS")
        if self.yandex_auth_mode is YandexAuthMode.IAM:
            if self.yandex_oauth_token is not None:
                raise ValueError("Yandex OAuth and IAM credentials are mutually exclusive")
            if self.yandex_iam_token is None or not self.yandex_iam_org_id:
                raise ValueError("Yandex IAM mode requires a token and organization")
        elif self.yandex_iam_token is not None or self.yandex_iam_org_id is not None:
            raise ValueError("Yandex OAuth and IAM credentials are mutually exclusive")

        if self.yandex_auth_mode is YandexAuthMode.MULTI_USER:
            if self.yandex_oauth_token is not None or self.yandex_iam_token is not None:
                raise ValueError("Multi-user mode cannot use static downstream credentials")
            if not (
                self.yandex_oauth_client_id
                and self.yandex_oauth_client_secret
                and self.mcp_oauth_callback_url
            ):
                raise ValueError(
                    "Multi-user mode requires Yandex OAuth client credentials and callback URL"
                )
            if self.mcp_auth_mode is not McpAuthMode.MULTI_USER:
                raise ValueError("Yandex multi-user mode requires MCP multi-user authentication")

        if self.mcp_auth_token and self.mcp_auth_mode is McpAuthMode.LOCAL:
            object.__setattr__(self, "mcp_auth_mode", McpAuthMode.STATIC)
        if self.mcp_auth_mode is McpAuthMode.STATIC and not self.mcp_auth_token:
            raise ValueError("Static MCP authentication requires MCP_AUTH_TOKEN")
        if self.mcp_auth_mode is McpAuthMode.MULTI_USER:
            if self.mcp_transport != "streamable-http":
                raise ValueError("MCP multi-user authentication requires Streamable HTTP")
            if self.yandex_auth_mode is not YandexAuthMode.MULTI_USER:
                raise ValueError("MCP multi-user authentication requires Yandex multi-user mode")
            if self.mcp_auth_token:
                raise ValueError("Static and multi-user MCP authentication are mutually exclusive")

        if self.mcp_auth_token:
            mcp_token = self.mcp_auth_token.get_secret_value()
            upstream_tokens = [
                token.get_secret_value()
                for token in (self.yandex_oauth_token, self.yandex_iam_token)
                if token is not None
            ]
            if any(hmac.compare_digest(mcp_token, token) for token in upstream_tokens):
                raise ValueError("MCP and upstream Yandex credentials must be distinct")

        if self.auth_store_backend is AuthStoreBackend.REDIS and self.redis_url is None:
            raise ValueError("Redis auth storage requires REDIS_URL")

        remote = self.mcp_transport == "streamable-http" and not self._is_loopback_host(
            self.mcp_host
        )
        if remote:
            if self.mcp_auth_mode is McpAuthMode.LOCAL:
                raise ValueError("Non-loopback Streamable HTTP requires MCP authentication")
            if not self.mcp_allowed_hosts or not self.mcp_allowed_origins:
                raise ValueError("Non-loopback Streamable HTTP requires allowed hosts and origins")
            if not self.mcp_cursor_keys:
                raise ValueError("Non-loopback Streamable HTTP requires MCP_CURSOR_KEYS")
            for field_name, value in (
                ("issuer", self.mcp_issuer_url),
                ("resource", self.mcp_resource_server_url),
            ):
                if urlsplit(value).scheme != "https":
                    raise ValueError(f"Non-loopback MCP {field_name} URL must use HTTPS")
            if (
                self.mcp_oauth_callback_url
                and urlsplit(self.mcp_oauth_callback_url).scheme != "https"
            ):
                raise ValueError("Non-loopback MCP OAuth callback URL must use HTTPS")
            if self.mcp_auth_mode is McpAuthMode.MULTI_USER:
                if self.auth_store_backend is not AuthStoreBackend.REDIS:
                    raise ValueError("Production multi-user mode requires Redis auth storage")
                if not keys:
                    raise ValueError("Production multi-user mode requires token encryption keys")
        return self

    def __init__(self, **values: Any) -> None:
        self._reject_unknown_project_environment()
        super().__init__(**values)

    @classmethod
    def _reject_unknown_project_environment(cls) -> None:
        known = {name.upper() for name in cls.model_fields}
        for field in cls.model_fields.values():
            if isinstance(field.validation_alias, str):
                known.add(field.validation_alias.upper())
        prefixes = ("MCP_", "YANDEX_", "DISK_", "WIKI_", "MAIL_")
        unknown = sorted(
            key for key in os.environ if key.startswith(prefixes) and key.upper() not in known
        )
        if unknown:
            message = f"Unknown project environment setting(s): {', '.join(unknown)}"
            raise ValidationError.from_exception_data(
                cls.__name__,
                [
                    {
                        "type": "value_error",
                        "loc": ("environment",),
                        "input": unknown,
                        "ctx": {"error": ValueError(message)},
                    }
                ],
            )

    @staticmethod
    def _is_loopback_host(host: str) -> bool:
        normalized = host.strip().lower().strip("[]")
        if normalized == "localhost":
            return True
        try:
            return ipaddress.ip_address(normalized).is_loopback
        except ValueError:
            return False

    @property
    def auth_storage_prefix(self) -> str:
        """Isolate every Redis record by service profile and public OAuth issuer."""
        if self.mcp_profile == "workspace":
            return "ywmcp:auth:v1"
        issuer_hash = hashlib.sha256(self.mcp_issuer_url.rstrip("/").encode()).hexdigest()[:24]
        return f"ywmcp:{self.mcp_profile}:{issuer_hash}:auth:v1"


def get_settings() -> Settings:
    return Settings()
