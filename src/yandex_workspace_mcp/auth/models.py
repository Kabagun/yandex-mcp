from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict


class WorkspaceScope(StrEnum):
    READ = "workspace:read"
    WRITE = "workspace:write"
    DELETE = "workspace:delete"
    MAIL_READ = "mail:read"
    MAIL_WRITE = "mail:write"
    MAIL_DELETE = "mail:delete"


@dataclass(frozen=True, slots=True)
class Principal:
    principal_id: str
    scopes: frozenset[WorkspaceScope] = field(default_factory=frozenset)
    client_id: str | None = None


@dataclass(frozen=True, slots=True)
class RequestAuthorization:
    principal: Principal
    token_id: str | None = None


@dataclass(frozen=True, slots=True)
class YandexOAuthCredential:
    token: str = field(repr=False)
    organization_id: str | None = None
    cloud_organization: bool = False
    email: str | None = field(default=None, repr=False)

    def request_credentials(self):
        from .credentials import oauth_request_credentials

        return oauth_request_credentials(self)


@dataclass(frozen=True, slots=True)
class YandexIAMCredential:
    token: str = field(repr=False)
    organization_id: str = ""

    def request_credentials(self):
        from .credentials import iam_request_credentials

        return iam_request_credentials(self)


class OAuthToken(BaseModel):
    model_config = ConfigDict(extra="ignore")

    access_token: str


class AuthContext(BaseModel):
    model_config = ConfigDict(extra="ignore")

    token: OAuthToken
    wiki_org_id: str | None = None


class AuthRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class OAuthClientRecord(AuthRecord):
    client_id: str
    client_secret: str | None = None
    redirect_uris: tuple[str, ...]
    allowed_scopes: tuple[str, ...] = ()
    client_secret_expires_at: float | None = None
    registration_source: str = "unknown"
    expires_at: float | None = None
    metadata: dict[str, Any] = {}


class OAuthStateRecord(AuthRecord):
    client_id: str
    redirect_uri: str
    scopes: tuple[str, ...]
    code_challenge: str
    resource: str | None
    expires_at: float
    subject: str | None = None
    nonce: str | None = None
    client_state: str | None = None
    redirect_uri_provided_explicitly: bool = True
    upstream_code_verifier: str | None = None


class AuthorizationCodeRecord(AuthRecord):
    client_id: str
    redirect_uri: str
    scopes: tuple[str, ...]
    code_challenge: str
    resource: str | None
    subject: str
    expires_at: float
    redirect_uri_provided_explicitly: bool = True


class AccessTokenRecord(AuthRecord):
    client_id: str
    scopes: tuple[str, ...]
    subject: str
    resource: str | None
    expires_at: float | None = None
    refresh_token: str | None = None


class RefreshTokenRecord(AuthRecord):
    client_id: str
    scopes: tuple[str, ...]
    subject: str
    expires_at: float | None = None
    access_token: str | None = None


class DownstreamCredentialRecord(AuthRecord):
    principal_id: str
    access_token: str
    refresh_token: str | None = None
    expires_at: float | None = None
    access_expires_at: float | None = None
    organization_id: str | None = None
    cloud_organization: bool = False
    yandex_subject: str | None = None
    email: str | None = None


class RecoveryHandleRecord(AuthRecord):
    principal_id: str
    upstream_token: str
    normalized_locator: str
    expires_at: float
