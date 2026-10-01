import base64
import contextlib
import hmac
import secrets
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from mcp.server import MCPServer
from mcp.server.auth.middleware.client_auth import ClientAuthenticator
from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.routes import cors_middleware
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions, RevocationOptions
from mcp.server.transport_security import TransportSecuritySettings
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route
from starlette.types import ASGIApp

from . import __version__
from .auth.credentials import StaticCredentialProvider, StoredCredentialProvider
from .auth.models import YandexIAMCredential, YandexOAuthCredential
from .auth.oauth import CompatibleRevocationHandler, YandexMcpOAuthProvider, YandexOAuthCallback
from .auth.recovery import (
    InMemoryRecoveryTokenStore,
    RecoveryTokenStore,
    SharedRecoveryTokenStore,
)
from .auth.redis_store import RedisTokenStore
from .auth.scopes import (
    WorkspacePrincipal,
    current_principal,
    effective_static_scopes,
    scopes_for_permissions,
)
from .auth.stores import InMemoryTokenStore
from .clients.base import RequestCredentials
from .clients.disk import YandexDiskClient
from .clients.files import PublicFileTransferClient
from .clients.mail import YandexMailClient
from .clients.signed import SignedTransferClient
from .clients.wiki import YandexWikiClient
from .config import AuthStoreBackend, McpAuthMode, Settings, YandexAuthMode, get_settings
from .jobs.uploads import UploadJobStore
from .models.errors import ConfigurationError
from .policies.cursors import CursorCodec, CursorKeyRing
from .security.audit import AuditContextMiddleware
from .security.transport import RegistrationSourceMiddleware, TrustedProxyHeadersMiddleware
from .services.disk import DiskService
from .services.mail import MailService
from .services.profile import ProfileService
from .services.wiki import WikiService
from .services.workspace import WorkspaceService
from .tools import register_common_tools, register_disk_tools, register_wiki_tools
from .tools.mail import register_mail_tools
from .tools.profile import create_profile_tool


class StaticTokenVerifier(TokenVerifier):
    def __init__(self, expected_token: str, scopes: list[str] | None = None):
        self.expected_token = expected_token
        self.scopes = scopes or []

    async def verify_token(self, token: str) -> AccessToken | None:
        if hmac.compare_digest(token, self.expected_token):
            return AccessToken(token=token, client_id="static-client", scopes=self.scopes)
        return None


ClientFactory = Callable[[], Any]
ServiceFactory = Callable[..., tuple[Any, Any, Any]]


@dataclass(frozen=True, slots=True)
class ApplicationDependencies:
    disk_client_factory: ClientFactory | None = None
    wiki_client_factory: ClientFactory | None = None
    cursor_keys: tuple[bytes, ...] | None = None
    recovery_keys: tuple[bytes, ...] | None = None
    signed_client_factory: ClientFactory | None = None
    service_factory: ServiceFactory | None = None
    auth_store_factory: ClientFactory | None = None
    oauth_http_client_factory: ClientFactory | None = None
    mail_client_factory: ClientFactory | None = None
    file_source_client_factory: ClientFactory | None = None


@dataclass(slots=True)
class ApplicationState:
    disk_client: Any | None
    wiki_client: Any | None
    disk_service: Any | None
    wiki_service: Any | None
    workspace_service: Any
    cursor_codec: CursorCodec
    recovery_store: RecoveryTokenStore | None
    signed_client: Any | None
    upload_job_store: UploadJobStore | None
    auth_store: Any | None
    oauth_provider: YandexMcpOAuthProvider | None
    oauth_callback: YandexOAuthCallback | None
    mail_client: Any | None = None
    mail_service: MailService | None = None
    profile_service: ProfileService | None = None
    file_source_client: Any | None = None


class Application:
    def __init__(
        self,
        settings: Settings,
        dependencies: ApplicationDependencies,
        mcp_server: MCPServer,
        auth_store: Any | None = None,
        oauth_provider: YandexMcpOAuthProvider | None = None,
    ) -> None:
        self.settings = settings
        self._settings_snapshot = settings.model_copy(deep=True)
        self.dependencies = dependencies
        self.mcp_server = mcp_server
        self.auth_store = auth_store
        self.oauth_provider = oauth_provider
        self.oauth_callback: YandexOAuthCallback | None = None
        self._credential_provider: Any | None = None
        self.state: ApplicationState | None = None
        self._opened_resources: list[Any] = []
        self._closed = False
        self._local_principal = WorkspacePrincipal(
            principal_id="trusted-local",
            scopes=_permission_scopes(settings),
        )

    @property
    def principal(self) -> WorkspacePrincipal:
        return current_principal(
            self._local_principal,
            require_authenticated=(
                self.settings.mcp_transport == "streamable-http"
                and self.settings.mcp_auth_mode is not McpAuthMode.LOCAL
            ),
        )

    @contextlib.asynccontextmanager
    async def lifespan(self) -> AsyncIterator[ApplicationState]:
        state = await self.open()
        try:
            yield state
        finally:
            await self.close()

    async def open(self) -> ApplicationState:
        if self.state is not None:
            return self.state
        if self._closed:
            raise ConfigurationError("Application cannot reopen after shutdown.")
        token = (
            self.settings.yandex_oauth_token.get_secret_value()
            if self.settings.yandex_oauth_token
            else None
        )
        static_credential_present = token or self.settings.yandex_iam_token is not None
        if (
            (
                self.settings.yandex_disk_enabled
                or self.settings.yandex_wiki_enabled
                or self.settings.yandex_mail_enabled
            )
            and self.settings.yandex_auth_mode is not YandexAuthMode.MULTI_USER
            and not static_credential_present
        ):
            raise ConfigurationError("A Yandex credential is required.")
        try:
            profile_service = None
            if self.auth_store is not None:
                if self.oauth_provider is None:
                    raise ConfigurationError("OAuth provider is not configured.")
                open_store = getattr(self.auth_store, "open", None)
                if open_store is not None:
                    await open_store()
                self._opened_resources.append(self.auth_store)
                callback_client = (
                    self.dependencies.oauth_http_client_factory()
                    if self.dependencies.oauth_http_client_factory
                    else None
                )
                self.oauth_callback = YandexOAuthCallback(
                    provider=self.oauth_provider,
                    store=self.auth_store,
                    yandex_client_id=self.settings.yandex_oauth_client_id or "",
                    yandex_client_secret=(
                        self.settings.yandex_oauth_client_secret.get_secret_value()
                        if self.settings.yandex_oauth_client_secret
                        else ""
                    ),
                    callback_url=self.settings.mcp_oauth_callback_url or "",
                    organization_id=self.settings.yandex_wiki_org_id,
                    cloud_organization=self.settings.yandex_wiki_is_cloud_org,
                    client=callback_client,
                    require_email=self.settings.yandex_mail_enabled,
                )
                self._opened_resources.append(self.oauth_callback)
                self._credential_provider = StoredCredentialProvider(
                    self.auth_store,
                    yandex_client_id=self.settings.yandex_oauth_client_id or "",
                    yandex_client_secret=(
                        self.settings.yandex_oauth_client_secret.get_secret_value()
                        if self.settings.yandex_oauth_client_secret
                        else ""
                    ),
                    client=self.oauth_callback.client,
                )
                profile_service = ProfileService(
                    self._credential_provider, self.oauth_callback.client
                )
            elif self.settings.yandex_auth_mode is YandexAuthMode.IAM:
                iam_token = self.settings.yandex_iam_token
                self._credential_provider = StaticCredentialProvider(
                    YandexIAMCredential(
                        iam_token.get_secret_value() if iam_token else "",
                        organization_id=self.settings.yandex_iam_org_id or "",
                    )
                )
            elif token:
                self._credential_provider = StaticCredentialProvider(
                    YandexOAuthCredential(
                        token,
                        organization_id=self.settings.yandex_wiki_org_id,
                        cloud_organization=self.settings.yandex_wiki_is_cloud_org,
                    )
                )

            disk_client = None
            if self.settings.yandex_disk_enabled:
                disk_factory = self.dependencies.disk_client_factory or (
                    lambda: YandexDiskClient(
                        credential_provider=lambda: self._request_credentials(
                            include_organization=False
                        )
                    )
                )
                disk_client = disk_factory()
                self._opened_resources.append(disk_client)
            wiki_client = None
            if self.settings.yandex_wiki_enabled:
                wiki_factory = self.dependencies.wiki_client_factory or (
                    lambda: YandexWikiClient(
                        credential_provider=lambda: self._request_credentials(
                            include_organization=True
                        ),
                    )
                )
                wiki_client = wiki_factory()
                self._opened_resources.append(wiki_client)

            mail_client = None
            mail_service = None
            if self.settings.yandex_mail_enabled:
                mail_factory = self.dependencies.mail_client_factory or (
                    lambda: YandexMailClient(
                        credential_provider=self._mail_credentials,
                        max_message_bytes=self.settings.mail_max_message_bytes,
                        max_attachment_bytes=self.settings.mail_max_attachment_bytes,
                        timeout_seconds=self.settings.mail_timeout_seconds,
                    )
                )
                mail_client = mail_factory()
                self._opened_resources.append(mail_client)
                mail_service = MailService(
                    mail_client,
                    can_read=self.settings.mail_read,
                    can_write=self.settings.mail_write,
                    can_delete=self.settings.mail_delete,
                )

            cursor_codec = self._cursor_codec()
            recovery_store = self._recovery_store()
            if recovery_store is not None:
                self._opened_resources.append(recovery_store)
            signed_client = None
            trusted_local_upload = self.settings.mcp_transport == "stdio" and (
                (bool(self.settings.wiki_upload_allowed_dirs) and self.settings.wiki_write)
                or (bool(self.settings.disk_upload_allowed_dirs) and self.settings.disk_write)
            )
            if trusted_local_upload or (
                self.settings.yandex_disk_enabled
                and (self.settings.disk_read or self.settings.disk_write)
            ):
                signed_factory = self.dependencies.signed_client_factory or SignedTransferClient
                signed_client = signed_factory()
                self._opened_resources.append(signed_client)
            file_source_client = None
            if self.settings.yandex_disk_enabled and self.settings.disk_write:
                file_source_factory = (
                    self.dependencies.file_source_client_factory or PublicFileTransferClient
                )
                file_source_client = file_source_factory()
                self._opened_resources.append(file_source_client)
            upload_job_store = None
            if (
                self.settings.mcp_transport == "stdio"
                and self.settings.disk_write
                and self.settings.disk_upload_allowed_dirs
            ):
                upload_job_store = UploadJobStore(
                    capacity=self.settings.disk_upload_job_capacity,
                    ttl_seconds=self.settings.disk_upload_job_ttl_seconds,
                    cursor_codec=cursor_codec,
                )
                self._opened_resources.append(upload_job_store)
            if self.dependencies.service_factory:
                disk_service, wiki_service, workspace_service = self.dependencies.service_factory(
                    disk_client=disk_client,
                    wiki_client=wiki_client,
                    cursor_codec=cursor_codec,
                    settings=self.settings,
                )
            else:
                disk_service = (
                    DiskService(
                        disk_client,
                        self.settings.disk_allowed_roots,
                        self.settings.disk_read,
                        self.settings.disk_write,
                        self.settings.disk_delete,
                        cursor_codec=cursor_codec,
                        upload_allowed_dirs=self.settings.disk_upload_allowed_dirs,
                        max_upload_bytes=self.settings.disk_max_upload_bytes,
                        signed_client=signed_client,
                        file_source_client=file_source_client,
                        upload_url_allowed_hosts=self.settings.disk_upload_url_allowed_hosts,
                        allowed_public_keys=self.settings.disk_allowed_public_keys,
                        allow_global_destructive=self.settings.disk_allow_global_destructive,
                        upload_job_store=upload_job_store,
                        max_inline_text_bytes=self.settings.max_inline_text_size_kb * 1024,
                    )
                    if disk_client
                    else None
                )
                wiki_service = (
                    WikiService(
                        wiki_client,
                        self.settings.wiki_allowed_roots,
                        self.settings.wiki_read,
                        self.settings.wiki_write,
                        self.settings.wiki_delete,
                        recovery_store=recovery_store,
                        upload_allowed_dirs=self.settings.wiki_upload_allowed_dirs,
                        max_attachment_bytes=self.settings.wiki_max_attachment_bytes,
                        signed_client=signed_client,
                    )
                    if wiki_client
                    else None
                )
                workspace_service = WorkspaceService(
                    disk_service,
                    wiki_service,
                    cursor_codec=cursor_codec,
                )
            self.state = ApplicationState(
                disk_client=disk_client,
                wiki_client=wiki_client,
                disk_service=disk_service,
                wiki_service=wiki_service,
                workspace_service=workspace_service,
                cursor_codec=cursor_codec,
                recovery_store=recovery_store,
                signed_client=signed_client,
                upload_job_store=upload_job_store,
                auth_store=self.auth_store,
                oauth_provider=self.oauth_provider,
                oauth_callback=self.oauth_callback,
                mail_client=mail_client,
                mail_service=mail_service,
                profile_service=profile_service,
                file_source_client=file_source_client,
            )
            return self.state
        except BaseException:
            await self._close_resources()
            self._closed = True
            raise

    async def _request_credentials(self, *, include_organization: bool) -> RequestCredentials:
        if self._credential_provider is None:
            raise ConfigurationError("A Yandex credential provider is not active.")
        credential = await self._credential_provider.resolve(self.principal)
        selected = credential.request_credentials()
        return RequestCredentials(
            token=selected.token,
            scheme=selected.scheme,
            headers=selected.headers if include_organization else {},
        )

    async def _mail_credentials(self) -> YandexOAuthCredential:
        if self._credential_provider is None:
            raise ConfigurationError("A Yandex credential provider is not active.")
        credential = await self._credential_provider.resolve(self.principal)
        if not isinstance(credential, YandexOAuthCredential) or not credential.email:
            raise ConfigurationError("Mail requires an authorized account email.")
        return credential

    def require_mail_service(self) -> MailService:
        """Return the lifespan-owned Mail service for this isolated profile."""
        if not self.state or not self.state.mail_service:
            raise ConfigurationError("Mail service is not active.")
        return self.state.mail_service

    def require_profile_service(self) -> ProfileService:
        """Return authenticated account discovery for the active OAuth lifespan."""
        if not self.state or not self.state.profile_service:
            raise ConfigurationError("Authenticated profile service is not active.")
        return self.state.profile_service

    def _cursor_codec(self) -> CursorCodec:
        if self.dependencies.cursor_keys:
            return CursorCodec(self.dependencies.cursor_keys)
        configured = [value.get_secret_value() for value in self.settings.mcp_cursor_keys]
        remote = (
            self.settings.mcp_transport == "streamable-http"
            and self.settings.mcp_host not in {"127.0.0.1", "::1", "localhost"}
        )
        return CursorCodec(CursorKeyRing.from_config(configured, remote=remote).keys)

    def _recovery_store(self) -> RecoveryTokenStore | None:
        if not self.settings.yandex_wiki_enabled or not self.settings.wiki_delete:
            return None
        if self.auth_store is not None:
            return SharedRecoveryTokenStore(self.auth_store)
        if self.dependencies.recovery_keys:
            keys = self.dependencies.recovery_keys
        else:
            configured = [
                value.get_secret_value() for value in self.settings.mcp_token_encryption_keys
            ]
            keys = tuple(
                base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)) for value in configured
            )
            if not keys:
                keys = (secrets.token_bytes(32),)
        return InMemoryRecoveryTokenStore(keys)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        await self._close_resources()
        self.state = None

    async def _close_resources(self) -> None:
        while self._opened_resources:
            resource = self._opened_resources.pop()
            close = getattr(resource, "close", None)
            if close:
                await close()

    def require_workspace_service(self) -> WorkspaceService:
        if not self.state:
            raise ConfigurationError("Application lifespan is not active.")
        return self.state.workspace_service

    def require_disk_service(self) -> DiskService:
        if not self.state or not self.state.disk_service:
            raise ConfigurationError("Disk service is not active.")
        return self.state.disk_service

    def require_wiki_service(self) -> WikiService:
        if not self.state or not self.state.wiki_service:
            raise ConfigurationError("Wiki service is not active.")
        return self.state.wiki_service

    def require_oauth_callback(self) -> YandexOAuthCallback:
        if not self.oauth_callback:
            raise ConfigurationError("OAuth callback is not active.")
        return self.oauth_callback


def _permission_scopes(settings: Settings):
    if settings.yandex_mail_enabled:
        return scopes_for_permissions(
            can_read=settings.mail_read,
            can_write=settings.mail_write,
            can_delete=settings.mail_delete,
            service="mail",
        )
    return scopes_for_permissions(
        can_read=(settings.yandex_disk_enabled and settings.disk_read)
        or (settings.yandex_wiki_enabled and settings.wiki_read),
        can_write=(settings.yandex_disk_enabled and settings.disk_write)
        or (settings.yandex_wiki_enabled and settings.wiki_write),
        can_delete=(settings.yandex_disk_enabled and settings.disk_delete)
        or (settings.yandex_wiki_enabled and settings.wiki_delete),
    )


def create_application(
    settings: Settings,
    dependencies: ApplicationDependencies | None = None,
) -> Application:
    # Detach server construction from caller-owned mutable containers and revalidate once.
    settings = Settings(**settings.model_dump())
    dependencies = dependencies or ApplicationDependencies()
    application: Application

    auth_store = None
    oauth_provider = None
    if settings.mcp_auth_mode is McpAuthMode.MULTI_USER:
        keys = _token_encryption_keys(settings)
        if dependencies.auth_store_factory:
            auth_store = dependencies.auth_store_factory()
        elif settings.auth_store_backend is AuthStoreBackend.REDIS:
            redis_url = settings.redis_url.get_secret_value() if settings.redis_url else None
            auth_store = RedisTokenStore(
                keys,
                url=redis_url,
                prefix=settings.auth_storage_prefix,
                registration_cap=settings.mcp_client_registration_cap,
            )
        else:
            auth_store = InMemoryTokenStore(
                keys,
                registration_cap=settings.mcp_client_registration_cap,
            )
        permission_scopes = _permission_scopes(settings)
        oauth_provider = YandexMcpOAuthProvider(
            store=auth_store,
            issuer_url=settings.mcp_issuer_url,
            resource_server_url=settings.mcp_resource_server_url,
            yandex_client_id=settings.yandex_oauth_client_id or "",
            yandex_callback_url=settings.mcp_oauth_callback_url or "",
            valid_scopes=sorted(scope.value for scope in permission_scopes),
            upstream_scopes=(
                ("login:email", "mail:imap_full", "mail:smtp")
                if settings.yandex_mail_enabled
                else ()
            ),
            client_secret_expiry_seconds=settings.mcp_client_secret_expiry_seconds,
        )

    @contextlib.asynccontextmanager
    async def mcp_lifespan(_server: MCPServer) -> AsyncIterator[ApplicationState]:
        async with application.lifespan() as state:
            yield state

    token_verifier = None
    auth_settings = None
    if settings.mcp_auth_mode is McpAuthMode.STATIC and settings.mcp_auth_token:
        permission_ceiling = _permission_scopes(settings)
        principal_scopes = effective_static_scopes(
            settings.mcp_static_scopes,
            permission_ceiling,
        )
        token_verifier = StaticTokenVerifier(
            settings.mcp_auth_token.get_secret_value(),
            scopes=[scope.value for scope in principal_scopes],
        )
        auth_settings = AuthSettings(
            issuer_url=AnyHttpUrl(settings.mcp_issuer_url),
            resource_server_url=AnyHttpUrl(settings.mcp_resource_server_url),
            required_scopes=[],
        )
    elif settings.mcp_auth_mode is McpAuthMode.MULTI_USER:
        auth_settings = AuthSettings(
            issuer_url=AnyHttpUrl(settings.mcp_issuer_url),
            resource_server_url=AnyHttpUrl(settings.mcp_resource_server_url),
            required_scopes=[],
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=list(oauth_provider.valid_scopes) if oauth_provider else [],
                default_scopes=list(oauth_provider.valid_scopes) if oauth_provider else [],
                client_secret_expiry_seconds=settings.mcp_client_secret_expiry_seconds,
            ),
            revocation_options=RevocationOptions(enabled=True),
        )
    mcp = MCPServer(
        name=f"yandex-{settings.mcp_profile}-mcp",
        version=__version__,
        auth=auth_settings,
        auth_server_provider=oauth_provider,
        token_verifier=token_verifier,
        lifespan=mcp_lifespan,
        tools=[create_profile_tool(lambda: application)] if oauth_provider is not None else None,
    )
    application = Application(
        settings,
        dependencies,
        mcp,
        auth_store=auth_store,
        oauth_provider=oauth_provider,
    )
    mcp.middleware.append(AuditContextMiddleware(lambda: application.principal.principal_id))
    if oauth_provider is not None:
        callback_path = urlsplit(settings.mcp_oauth_callback_url or "").path

        @mcp.custom_route(callback_path, methods=["GET"], include_in_schema=False)
        async def yandex_oauth_callback(request: Request) -> Response:
            return await application.require_oauth_callback().handle(request)

    @mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
    async def healthz(_request: Request) -> Response:
        return JSONResponse({"status": "ok"}, headers={"Cache-Control": "no-store"})

    if settings.mcp_profile != "mail":
        register_common_tools(mcp, application)
    register_disk_tools(mcp, application, settings)
    register_wiki_tools(mcp, application, settings)
    register_mail_tools(mcp, application, settings)
    return application


def _token_encryption_keys(settings: Settings) -> tuple[bytes, ...]:
    configured = [value.get_secret_value() for value in settings.mcp_token_encryption_keys]
    if not configured:
        return (secrets.token_bytes(32),)
    return tuple(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)) for value in configured)


def transport_security_settings(settings: Settings) -> TransportSecuritySettings:
    if settings.mcp_allowed_hosts:
        allowed_hosts = list(settings.mcp_allowed_hosts)
    else:
        allowed_hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    if settings.mcp_allowed_origins:
        allowed_origins = list(settings.mcp_allowed_origins)
    else:
        allowed_origins = [
            "http://127.0.0.1:*",
            "http://localhost:*",
            "http://[::1]:*",
        ]
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )


def create_http_app(application: Application) -> ASGIApp:
    settings = application.settings
    if settings.model_dump() != application._settings_snapshot.model_dump():
        raise ConfigurationError("Application settings changed after server construction.")
    if settings.mcp_transport != "streamable-http":
        raise ConfigurationError("HTTP application requires Streamable HTTP settings.")
    try:
        # Defend against callers mutating a Settings instance after initial validation.
        Settings(**settings.model_dump())
    except Exception as exc:
        raise ConfigurationError("HTTP application settings failed validation.") from exc
    http_app = application.mcp_server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        max_request_body_size=settings.mcp_max_request_body_bytes,
        transport_security=transport_security_settings(settings),
        host=settings.mcp_host,
    )
    if application.oauth_provider is not None:
        handler = CompatibleRevocationHandler(
            application.oauth_provider, ClientAuthenticator(application.oauth_provider)
        )
        for index, route in enumerate(http_app.routes):
            if isinstance(route, Route) and route.path == "/revoke":
                http_app.routes[index] = Route(
                    "/revoke",
                    endpoint=cors_middleware(handler.handle, ["POST", "OPTIONS"]),
                    methods=["POST", "OPTIONS"],
                )
                break
        else:
            raise ConfigurationError("OAuth revocation route is missing.")
    app: ASGIApp = RegistrationSourceMiddleware(http_app)
    if settings.mcp_trusted_proxy_cidrs:
        app = TrustedProxyHeadersMiddleware(app, settings.mcp_trusted_proxy_cidrs)
    return app


application = create_application(get_settings())
mcp_server = application.mcp_server
