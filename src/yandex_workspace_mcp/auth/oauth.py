import base64
import contextvars
import hashlib
import hmac
import secrets
import time
import urllib.parse
from collections.abc import Callable, Generator, Sequence

import httpx
from httpx import Auth, Request, Response
from mcp.server.auth.handlers.revoke import RevocationHandler
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    RegistrationError,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull
from mcp.shared.auth import OAuthToken as McpOAuthToken
from pydantic import AnyUrl
from starlette.requests import Request as StarletteRequest
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse
from starlette.types import Message

from yandex_workspace_mcp.auth.models import (
    AccessTokenRecord,
    AuthContext,
    AuthorizationCodeRecord,
    DownstreamCredentialRecord,
    OAuthClientRecord,
    OAuthStateRecord,
    RefreshTokenRecord,
)
from yandex_workspace_mcp.auth.scopes import expand_scope_values
from yandex_workspace_mcp.auth.stores import TokenStore, TokenStoreMiss

registration_source_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "oauth_registration_source", default="unknown"
)


class CompatibleRevocationHandler(RevocationHandler):
    """Normalize the SDK 2.0 optional-secret field for public RFC 7009 clients.

    Authentication, token ownership and revocation still use the SDK handler.
    An empty field never bypasses authentication for confidential clients.
    """

    async def handle(self, request: StarletteRequest):
        if request.headers.get("content-type", "").split(";")[0] != (
            "application/x-www-form-urlencoded"
        ):
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        body = bytearray()
        async for chunk in request.stream():
            body.extend(chunk)
            if len(body) > 16_384:
                return JSONResponse({"error": "invalid_request"}, status_code=413)
        try:
            fields = urllib.parse.parse_qsl(body.decode("utf-8"), keep_blank_values=True)
        except UnicodeError:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        if not any(key == "client_secret" for key, _ in fields):
            fields.append(("client_secret", ""))
        normalized = urllib.parse.urlencode(fields).encode()
        scope = dict(request.scope)
        scope["headers"] = [
            (key, value) for key, value in request.scope["headers"] if key != b"content-length"
        ] + [(b"content-length", str(len(normalized)).encode())]

        async def receive() -> Message:
            return {"type": "http.request", "body": normalized, "more_body": False}

        return await super().handle(StarletteRequest(scope, receive=receive))


class DiskAuth(Auth):
    def __init__(self, auth_context: AuthContext):
        self.auth_context = auth_context

    def auth_flow(self, request: Request) -> Generator[Request, Response, None]:
        request.headers["Authorization"] = f"OAuth {self.auth_context.token.access_token}"
        yield request


class WikiAuth(Auth):
    def __init__(self, auth_context: AuthContext):
        self.auth_context = auth_context

    def auth_flow(self, request: Request) -> Generator[Request, Response, None]:
        request.headers["Authorization"] = f"OAuth {self.auth_context.token.access_token}"
        if self.auth_context.wiki_org_id:
            request.headers["X-Org-Id"] = self.auth_context.wiki_org_id
        yield request


class YandexMcpOAuthProvider(
    OAuthAuthorizationServerProvider[AuthorizationCode, RefreshToken, AccessToken]
):
    """MCP authorization server backed by a separate Yandex OAuth grant."""

    def __init__(
        self,
        *,
        store: TokenStore,
        issuer_url: str,
        resource_server_url: str,
        yandex_client_id: str,
        yandex_callback_url: str,
        valid_scopes: Sequence[str],
        upstream_scopes: Sequence[str] = (),
        clock: Callable[[], float] = time.time,
        random_token: Callable[[int], str] = secrets.token_urlsafe,
        state_ttl_seconds: int = 600,
        code_ttl_seconds: int = 300,
        access_ttl_seconds: int = 3600,
        refresh_ttl_seconds: int = 30 * 24 * 3600,
        client_secret_expiry_seconds: int = 30 * 24 * 3600,
    ) -> None:
        self.store = store
        self.issuer_url = issuer_url.rstrip("/")
        self.resource_server_url = resource_server_url.rstrip("/")
        self.yandex_client_id = yandex_client_id
        self.yandex_callback_url = yandex_callback_url
        self.valid_scopes = tuple(valid_scopes)
        self.upstream_scopes = tuple(upstream_scopes)
        self._clock = clock
        self._random_token = random_token
        self._state_ttl = state_ttl_seconds
        self._code_ttl = code_ttl_seconds
        self._access_ttl = access_ttl_seconds
        self._refresh_ttl = refresh_ttl_seconds
        self._client_secret_expiry = client_secret_expiry_seconds

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        try:
            record = await self.store.get_client(client_id)
        except TokenStoreMiss:
            return None
        if record.client_secret_expires_at and record.client_secret_expires_at <= self._clock():
            return None
        try:
            return OAuthClientInformationFull.model_validate(record.metadata)
        except (ValueError, TypeError):
            return None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        redirect_uris = tuple(str(value) for value in client_info.redirect_uris or [])
        if not redirect_uris:
            raise RegistrationError(
                error="invalid_redirect_uri",
                error_description="At least one redirect URI is required",
            )
        for redirect_uri in redirect_uris:
            self._validate_redirect_uri(redirect_uri)

        raw_scopes = tuple((client_info.scope or "").split())
        requested_scopes = expand_scope_values(raw_scopes)
        if not set(raw_scopes).issubset(self.valid_scopes):
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="Client requested an unsupported scope",
            )
        if not set(requested_scopes).issubset(self.valid_scopes):
            raise RegistrationError(
                error="invalid_client_metadata",
                error_description="Client requested an unsupported scope",
            )
        expires_at: float | None = None
        metadata = client_info.model_dump(mode="json")
        metadata["scope"] = " ".join(requested_scopes)
        if client_info.client_secret:
            expires_at = self._clock() + self._client_secret_expiry
            metadata["client_secret_expires_at"] = int(expires_at)
        record = OAuthClientRecord(
            client_id=client_info.client_id,
            client_secret=client_info.client_secret,
            redirect_uris=redirect_uris,
            allowed_scopes=requested_scopes,
            client_secret_expires_at=expires_at,
            expires_at=expires_at,
            registration_source=registration_source_var.get(),
            metadata=metadata,
        )
        await self.store.put_client(record)

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        registered = await self.get_client(client.client_id)
        if registered is None:
            raise AuthorizeError(error="unauthorized_client")
        redirect_uri = str(params.redirect_uri)
        if redirect_uri not in {str(value) for value in registered.redirect_uris or []}:
            raise AuthorizeError(error="invalid_request", error_description="Invalid redirect URI")
        requested = tuple(params.scopes or (registered.scope or "").split())
        scopes = expand_scope_values(requested)
        if not set(requested).issubset(self.valid_scopes):
            raise AuthorizeError(error="invalid_scope")
        allowed = set((registered.scope or "").split()).intersection(self.valid_scopes)
        if not set(scopes).issubset(allowed):
            raise AuthorizeError(error="invalid_scope")
        resource = params.resource.rstrip("/") if params.resource else self.resource_server_url
        if not hmac.compare_digest(resource, self.resource_server_url):
            raise AuthorizeError(error="invalid_target")

        state = self._random_token(32)
        upstream_verifier = self._random_token(48)
        upstream_challenge = self._pkce_challenge(upstream_verifier)
        await self.store.put_state(
            state,
            OAuthStateRecord(
                client_id=registered.client_id,
                redirect_uri=redirect_uri,
                scopes=scopes,
                code_challenge=params.code_challenge,
                resource=resource,
                expires_at=self._clock() + self._state_ttl,
                nonce=self._random_token(24),
                client_state=params.state,
                redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
                upstream_code_verifier=upstream_verifier,
            ),
        )
        query = urllib.parse.urlencode(
            {
                "response_type": "code",
                "client_id": self.yandex_client_id,
                "redirect_uri": self.yandex_callback_url,
                "state": state,
                "code_challenge": upstream_challenge,
                "code_challenge_method": "S256",
                **({"scope": " ".join(self.upstream_scopes)} if self.upstream_scopes else {}),
            }
        )
        return f"https://oauth.yandex.ru/authorize?{query}"

    async def complete_authorization(self, state: str, yandex_subject: str) -> str:
        try:
            record = await self.store.consume_state(state)
        except TokenStoreMiss as exc:
            raise AuthorizeError(
                error="access_denied", error_description="Invalid OAuth state"
            ) from exc
        return await self.complete_authorization_record(record, yandex_subject)

    async def consume_pending_authorization(self, state: str) -> OAuthStateRecord:
        try:
            return await self.store.consume_state(state)
        except TokenStoreMiss as exc:
            raise AuthorizeError(
                error="access_denied", error_description="Invalid OAuth state"
            ) from exc

    async def complete_authorization_record(
        self, record: OAuthStateRecord, yandex_subject: str
    ) -> str:
        code = self._random_token(32)
        principal_id = self.principal_id(record.client_id, yandex_subject)
        await self.store.put_authorization_code(
            code,
            AuthorizationCodeRecord(
                client_id=record.client_id,
                redirect_uri=record.redirect_uri,
                scopes=record.scopes,
                code_challenge=record.code_challenge,
                resource=record.resource,
                subject=principal_id,
                expires_at=self._clock() + self._code_ttl,
                redirect_uri_provided_explicitly=record.redirect_uri_provided_explicitly,
            ),
        )
        query: dict[str, str] = {"code": code}
        if record.client_state is not None:
            query["state"] = record.client_state
        return self._append_query(record.redirect_uri, query)

    def authorization_error_redirect(self, record: OAuthStateRecord) -> str:
        query = {"error": "access_denied"}
        if record.client_state is not None:
            query["state"] = record.client_state
        return self._append_query(record.redirect_uri, query)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        try:
            record = await self.store.get_authorization_code(authorization_code)
            if not hmac.compare_digest(record.client_id, client.client_id):
                return None
        except TokenStoreMiss:
            return None
        return AuthorizationCode(
            code=authorization_code,
            scopes=list(record.scopes),
            expires_at=record.expires_at,
            client_id=record.client_id,
            code_challenge=record.code_challenge,
            redirect_uri=AnyUrl(record.redirect_uri),
            redirect_uri_provided_explicitly=record.redirect_uri_provided_explicitly,
            resource=record.resource,
            subject=record.subject,
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> McpOAuthToken:
        if not hmac.compare_digest(client.client_id, authorization_code.client_id):
            raise TokenError(error="invalid_grant")
        try:
            record = await self.store.consume_authorization_code(authorization_code.code)
        except TokenStoreMiss as exc:
            raise TokenError(error="invalid_grant") from exc
        if (
            not hmac.compare_digest(record.client_id, authorization_code.client_id)
            or not hmac.compare_digest(record.code_challenge, authorization_code.code_challenge)
            or record.redirect_uri != str(authorization_code.redirect_uri)
            or record.scopes != tuple(authorization_code.scopes)
            or record.resource != authorization_code.resource
            or record.subject != authorization_code.subject
        ):
            raise TokenError(error="invalid_grant")
        return await self._issue_token_pair(
            client_id=client.client_id,
            scopes=list(record.scopes),
            subject=record.subject,
            resource=record.resource,
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        try:
            record = await self.store.get_refresh_token(refresh_token)
        except TokenStoreMiss:
            return None
        if not hmac.compare_digest(record.client_id, client.client_id):
            return None
        return RefreshToken(
            token=refresh_token,
            client_id=record.client_id,
            scopes=list(record.scopes),
            expires_at=int(record.expires_at) if record.expires_at is not None else None,
            subject=record.subject,
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> McpOAuthToken:
        if not hmac.compare_digest(client.client_id, refresh_token.client_id):
            raise TokenError(error="invalid_grant")
        effective_scopes = list(expand_scope_values(tuple(scopes)))
        if not set(scopes).issubset(self.valid_scopes) or not set(effective_scopes).issubset(
            refresh_token.scopes
        ):
            raise TokenError(error="invalid_scope")

        access_value = self._random_token(32)
        refresh_value = self._random_token(32)
        access_expiry = self._clock() + self._access_ttl
        refresh_expiry = self._clock() + self._refresh_ttl
        new_refresh = RefreshTokenRecord(
            client_id=client.client_id,
            scopes=tuple(effective_scopes),
            subject=refresh_token.subject or client.client_id,
            expires_at=refresh_expiry,
            access_token=access_value,
        )
        new_access = AccessTokenRecord(
            client_id=client.client_id,
            scopes=tuple(effective_scopes),
            subject=refresh_token.subject or client.client_id,
            resource=self.resource_server_url,
            expires_at=access_expiry,
            refresh_token=refresh_value,
        )
        try:
            await self.store.rotate_token_pair(
                old_refresh_token=refresh_token.token,
                new_refresh_token=refresh_value,
                new_refresh_record=new_refresh,
                new_access_token=access_value,
                new_access_record=new_access,
            )
        except TokenStoreMiss as exc:
            raise TokenError(error="invalid_grant") from exc
        return McpOAuthToken(
            access_token=access_value,
            refresh_token=refresh_value,
            expires_in=self._access_ttl,
            scope=" ".join(effective_scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        try:
            record = await self.store.get_access_token(token)
        except TokenStoreMiss:
            return None
        if record.resource != self.resource_server_url:
            return None
        if not set(record.scopes).issubset(self.valid_scopes):
            return None
        return AccessToken(
            token=token,
            client_id=record.client_id,
            scopes=list(record.scopes),
            expires_at=int(record.expires_at) if record.expires_at is not None else None,
            resource=record.resource,
            subject=record.subject,
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        try:
            if isinstance(token, AccessToken):
                access_record = await self.store.get_access_token(token.token)
                await self.store.revoke_token_pair(
                    access_token=token.token, refresh_token=access_record.refresh_token
                )
                await self.store.delete_downstream(access_record.subject)
            else:
                refresh_record = await self.store.get_refresh_token(token.token)
                await self.store.revoke_token_pair(
                    access_token=refresh_record.access_token, refresh_token=token.token
                )
                await self.store.delete_downstream(refresh_record.subject)
        except TokenStoreMiss:
            return

    async def _issue_token_pair(
        self, *, client_id: str, scopes: list[str], subject: str, resource: str | None
    ) -> McpOAuthToken:
        access_value = self._random_token(32)
        refresh_value = self._random_token(32)
        access_expiry = self._clock() + self._access_ttl
        refresh_expiry = self._clock() + self._refresh_ttl
        access_record = AccessTokenRecord(
            client_id=client_id,
            scopes=tuple(scopes),
            subject=subject,
            resource=resource,
            expires_at=access_expiry,
            refresh_token=refresh_value,
        )
        refresh_record = RefreshTokenRecord(
            client_id=client_id,
            scopes=tuple(scopes),
            subject=subject,
            expires_at=refresh_expiry,
            access_token=access_value,
        )
        await self.store.put_token_pair(
            access_token=access_value,
            access_record=access_record,
            refresh_token=refresh_value,
            refresh_record=refresh_record,
        )
        return McpOAuthToken(
            access_token=access_value,
            refresh_token=refresh_value,
            expires_in=self._access_ttl,
            scope=" ".join(scopes),
        )

    def principal_id(self, client_id: str, yandex_subject: str) -> str:
        digest = hashlib.sha256(
            f"{self.issuer_url}\0{client_id}\0{yandex_subject}".encode()
        ).digest()[:24]
        return "yandex:" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    @staticmethod
    def _pkce_challenge(verifier: str) -> str:
        digest = hashlib.sha256(verifier.encode()).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()

    @staticmethod
    def _append_query(url: str, values: dict[str, str]) -> str:
        parsed = urllib.parse.urlsplit(url)
        existing = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        query = urllib.parse.urlencode([*existing, *values.items()])
        return urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))

    @staticmethod
    def _validate_redirect_uri(value: str) -> None:
        parsed = urllib.parse.urlsplit(value)
        hostname = (parsed.hostname or "").lower()
        loopback = hostname in {"localhost", "127.0.0.1", "::1"}
        if (
            not hostname
            or "*" in value
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or (parsed.scheme != "https" and not (parsed.scheme == "http" and loopback))
        ):
            raise RegistrationError(
                error="invalid_redirect_uri", error_description="Unsafe redirect URI"
            )


class YandexOAuthCallback:
    def __init__(
        self,
        *,
        provider: YandexMcpOAuthProvider,
        store: TokenStore,
        yandex_client_id: str,
        yandex_client_secret: str,
        callback_url: str,
        organization_id: str | None = None,
        cloud_organization: bool = False,
        require_email: bool = False,
        client: httpx.AsyncClient | None = None,
        clock: Callable[[], float] = time.time,
        downstream_ttl_seconds: int = 30 * 24 * 3600,
    ) -> None:
        self.provider = provider
        self.store = store
        self.yandex_client_id = yandex_client_id
        self._yandex_client_secret = yandex_client_secret
        self.callback_url = callback_url
        self.organization_id = organization_id
        self.cloud_organization = cloud_organization
        self.require_email = require_email
        self.client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(10.0, connect=5.0), follow_redirects=False
        )
        self._clock = clock
        self._downstream_ttl = downstream_ttl_seconds
        self._closed = False

    async def handle(self, request: StarletteRequest) -> RedirectResponse | PlainTextResponse:
        state = request.query_params.get("state")
        code = request.query_params.get("code")
        if not state or len(state) > 512:
            return self._failure()
        try:
            pending = await self.provider.consume_pending_authorization(state)
        except AuthorizeError:
            return self._failure()

        if request.query_params.get("error") or not code or len(code) > 2048:
            return self._redirect(self.provider.authorization_error_redirect(pending))
        try:
            token_response = await self.client.post(
                "https://oauth.yandex.ru/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "client_id": self.yandex_client_id,
                    "client_secret": self._yandex_client_secret,
                    "redirect_uri": self.callback_url,
                    "code_verifier": pending.upstream_code_verifier or "",
                },
                headers={"Accept": "application/json"},
            )
            token_response.raise_for_status()
            token_payload = token_response.json()
            access_token = token_payload.get("access_token")
            refresh_token = token_payload.get("refresh_token")
            expires_in = token_payload.get("expires_in", 3600)
            if not isinstance(access_token, str) or not access_token:
                raise ValueError("missing access token")
            if refresh_token is not None and not isinstance(refresh_token, str):
                raise ValueError("invalid refresh token")
            if not isinstance(expires_in, int | float) or expires_in <= 0:
                raise ValueError("invalid expiry")

            account_response = await self.client.get(
                "https://login.yandex.ru/info",
                params={"format": "json"},
                headers={
                    "Accept": "application/json",
                    "Authorization": f"OAuth {access_token}",
                },
            )
            account_response.raise_for_status()
            account_payload = account_response.json()
            yandex_subject = account_payload.get("id")
            if not isinstance(yandex_subject, str) or not (1 <= len(yandex_subject) <= 256):
                raise ValueError("missing account subject")
            email = account_payload.get("default_email") if self.require_email else None
            if self.require_email and (
                not isinstance(email, str)
                or not (3 <= len(email) <= 254)
                or email.count("@") != 1
                or any(character.isspace() or ord(character) < 32 for character in email)
            ):
                raise ValueError("missing account email")
        except (httpx.HTTPError, ValueError, TypeError):
            return self._redirect(self.provider.authorization_error_redirect(pending))

        principal_id = self.provider.principal_id(pending.client_id, yandex_subject)
        await self.store.put_downstream(
            principal_id,
            DownstreamCredentialRecord(
                principal_id=principal_id,
                access_token=access_token,
                refresh_token=refresh_token,
                expires_at=self._clock() + self._downstream_ttl,
                access_expires_at=self._clock() + float(expires_in),
                organization_id=self.organization_id,
                cloud_organization=self.cloud_organization,
                yandex_subject=yandex_subject,
                email=email,
            ),
        )
        location = await self.provider.complete_authorization_record(pending, yandex_subject)
        return self._redirect(location)

    @staticmethod
    def _failure() -> PlainTextResponse:
        return PlainTextResponse(
            "OAuth authorization failed",
            status_code=400,
            headers={"Cache-Control": "no-store"},
        )

    @staticmethod
    def _redirect(location: str) -> RedirectResponse:
        return RedirectResponse(location, headers={"Cache-Control": "no-store"})

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self.client.aclose()
