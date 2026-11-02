import math
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

import anyio
import httpx
import structlog

from ..clients.base import RequestCredentials
from ..models.errors import (
    AuthenticationError,
    ConfigurationError,
    ContractMismatchError,
    RateLimitExceeded,
    UpstreamTimeout,
    UpstreamUnavailable,
    YandexWorkspaceError,
)
from .models import (
    DownstreamCredentialRecord,
    Principal,
    YandexIAMCredential,
    YandexOAuthCredential,
)
from .stores import TokenStore, TokenStoreMiss

YandexCredential = YandexOAuthCredential | YandexIAMCredential
logger = structlog.get_logger()
_MAX_REFRESH_INTERVAL = 60 * 24 * 3600


def next_refresh_time(now: float, access_expires_at: float | None) -> float:
    """Schedule provider renewal before expiry and at least once every sixty days."""
    if access_expires_at is None:
        return now + _MAX_REFRESH_INTERVAL
    lifetime = access_expires_at - now
    margin = min(300.0, max(1.0, lifetime / 10))
    return max(now + 1, min(access_expires_at - margin, now + _MAX_REFRESH_INTERVAL))


def _organization_headers(
    organization_id: str | None, *, cloud_organization: bool
) -> Mapping[str, str]:
    if not organization_id:
        return {}
    name = "X-Cloud-Org-Id" if cloud_organization else "X-Org-Id"
    return {name: organization_id}


def oauth_request_credentials(credential: YandexOAuthCredential) -> RequestCredentials:
    return RequestCredentials(
        token=credential.token,
        scheme="OAuth",
        headers=_organization_headers(
            credential.organization_id,
            cloud_organization=credential.cloud_organization,
        ),
    )


def iam_request_credentials(credential: YandexIAMCredential) -> RequestCredentials:
    if not credential.organization_id:
        raise AuthenticationError()
    return RequestCredentials(
        token=credential.token,
        scheme="Bearer",
        headers=_organization_headers(
            credential.organization_id,
            cloud_organization=True,
        ),
    )


class CredentialProvider(Protocol):
    async def resolve(self, principal: Principal) -> YandexCredential: ...


@dataclass(frozen=True, slots=True)
class StaticCredentialProvider:
    credential: YandexCredential

    async def resolve(self, principal: Principal) -> YandexCredential:
        del principal
        return self.credential


class StoredCredentialProvider:
    def __init__(
        self,
        store: TokenStore,
        *,
        yandex_client_id: str,
        yandex_client_secret: str,
        client: httpx.AsyncClient,
        clock: Callable[[], float] = time.time,
        credential_ttl_seconds: int = 0,
    ) -> None:
        self.store = store
        self.yandex_client_id = yandex_client_id
        self._yandex_client_secret = yandex_client_secret
        self.client = client
        self._clock = clock
        self._credential_ttl = credential_ttl_seconds
        self._locks_guard = anyio.Lock()
        self._locks: dict[str, anyio.Lock] = {}

    async def resolve(self, principal: Principal) -> YandexCredential:
        record = await self.resolve_record(principal)
        return YandexOAuthCredential(
            record.access_token,
            organization_id=record.organization_id,
            cloud_organization=record.cloud_organization,
            email=record.email,
        )

    async def resolve_record(self, principal: Principal) -> DownstreamCredentialRecord:
        """Resolve one request's account identity and credentials, refreshing when needed."""
        try:
            record = await self.store.get_downstream(principal.principal_id)
        except TokenStoreMiss as exc:
            raise AuthenticationError() from exc
        if record.refresh_token and record.refresh_after is None:
            enrolled = record.model_copy(
                update={
                    "expires_at": (
                        self._clock() + self._credential_ttl if self._credential_ttl else None
                    ),
                    "refresh_after": next_refresh_time(self._clock(), record.access_expires_at),
                }
            )
            if await self.store.replace_downstream(principal.principal_id, record, enrolled):
                record = enrolled
            else:
                try:
                    record = await self.store.get_downstream(principal.principal_id)
                except TokenStoreMiss:
                    raise AuthenticationError() from None
        if record.access_expires_at is not None and record.access_expires_at <= self._clock() + 30:
            record = await self._refresh(principal.principal_id)
        return record

    async def refresh_due(self) -> int:
        """Renew a bounded batch of claimed grants without depending on user traffic."""
        refreshed = 0
        for principal_id in await self.store.list_due_downstream(limit=100):
            try:
                await self._refresh(principal_id, force=True)
            except YandexWorkspaceError:
                # The store claim leases failures for a later retry. Definitive
                # revocation removes the grant and its schedule in _refresh.
                continue
            refreshed += 1
        return refreshed

    async def maintain(self) -> None:
        """Keep encrypted grants renewed; cancellation is owned by the app lifespan."""
        while True:
            try:
                await self.refresh_due()
            except Exception:  # noqa: BLE001 -- isolate store outages from the service lifespan
                logger.warning("oauth.maintenance_unavailable")
            await anyio.sleep(60)

    async def _refresh(
        self, principal_id: str, *, force: bool = False
    ) -> DownstreamCredentialRecord:
        lock = await self._principal_lock(principal_id)
        async with lock:
            try:
                current = await self.store.get_downstream(principal_id)
            except TokenStoreMiss as exc:
                raise AuthenticationError() from exc
            if force:
                if current.refresh_after is not None and current.refresh_after > self._clock():
                    return current
            elif (
                current.access_expires_at is None or current.access_expires_at > self._clock() + 30
            ):
                return current
            if not current.refresh_token:
                if not await self.store.delete_downstream_if_current(principal_id, current):
                    try:
                        return await self.store.get_downstream(principal_id)
                    except TokenStoreMiss:
                        raise AuthenticationError() from None
                raise AuthenticationError()
            try:
                response = await self.client.post(
                    "https://oauth.yandex.ru/token",
                    data={
                        "grant_type": "refresh_token",
                        "refresh_token": current.refresh_token,
                        "client_id": self.yandex_client_id,
                        "client_secret": self._yandex_client_secret,
                    },
                    headers={"Accept": "application/json"},
                )
            except httpx.TimeoutException:
                logger.warning("oauth.refresh", outcome="timeout")
                raise UpstreamTimeout() from None
            except httpx.HTTPError:
                logger.warning("oauth.refresh", outcome="unavailable")
                raise UpstreamUnavailable() from None
            try:
                payload = response.json()
            except (ValueError, TypeError):
                if 200 <= response.status_code < 300:
                    raise ContractMismatchError() from None
                payload = {}
            if not isinstance(payload, dict):
                if 200 <= response.status_code < 300:
                    raise ContractMismatchError()
                payload = {}
            if not 200 <= response.status_code < 300:
                error = payload.get("error")
                if not isinstance(error, str):
                    error = None
                if response.status_code in {400, 401} and error == "invalid_grant":
                    if not await self.store.delete_downstream_if_current(principal_id, current):
                        try:
                            return await self.store.get_downstream(principal_id)
                        except TokenStoreMiss:
                            raise AuthenticationError() from None
                    logger.info("oauth.refresh", outcome="revoked")
                    raise AuthenticationError()
                if error in {"invalid_client", "unauthorized_client"}:
                    raise ConfigurationError()
                if response.status_code == 429:
                    raise RateLimitExceeded()
                raise UpstreamUnavailable()
            try:
                access_token = payload.get("access_token")
                refresh_token = payload.get("refresh_token", current.refresh_token)
                expires_in = payload.get("expires_in", 3600)
                if (
                    not isinstance(access_token, str)
                    or not access_token
                    or not isinstance(refresh_token, str)
                    or not refresh_token
                    or not isinstance(expires_in, int | float)
                    or isinstance(expires_in, bool)
                    or not math.isfinite(expires_in)
                    or expires_in <= 0
                ):
                    raise ValueError("invalid refresh response")
            except (ValueError, TypeError):
                raise ContractMismatchError() from None
            updated = current.model_copy(
                update={
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "access_expires_at": self._clock() + float(expires_in),
                    "expires_at": (
                        self._clock() + self._credential_ttl if self._credential_ttl else None
                    ),
                    "refresh_after": next_refresh_time(
                        self._clock(), self._clock() + float(expires_in)
                    ),
                }
            )
            if not await self.store.replace_downstream(principal_id, current, updated):
                try:
                    return await self.store.get_downstream(principal_id)
                except TokenStoreMiss:
                    raise AuthenticationError() from None
            logger.info("oauth.refresh", outcome="renewed")
            return updated

    async def _principal_lock(self, principal_id: str) -> anyio.Lock:
        async with self._locks_guard:
            return self._locks.setdefault(principal_id, anyio.Lock())
