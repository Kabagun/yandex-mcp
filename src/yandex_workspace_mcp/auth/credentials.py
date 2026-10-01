import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Protocol

import anyio
import httpx

from ..clients.base import RequestCredentials
from ..models.errors import AuthenticationError
from .models import (
    DownstreamCredentialRecord,
    Principal,
    YandexIAMCredential,
    YandexOAuthCredential,
)
from .stores import TokenStore, TokenStoreMiss

YandexCredential = YandexOAuthCredential | YandexIAMCredential


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
    ) -> None:
        self.store = store
        self.yandex_client_id = yandex_client_id
        self._yandex_client_secret = yandex_client_secret
        self.client = client
        self._clock = clock
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
        if record.access_expires_at is not None and record.access_expires_at <= self._clock() + 30:
            record = await self._refresh(principal.principal_id)
        return record

    async def _refresh(self, principal_id: str) -> DownstreamCredentialRecord:
        lock = await self._principal_lock(principal_id)
        async with lock:
            try:
                current = await self.store.get_downstream(principal_id)
            except TokenStoreMiss as exc:
                raise AuthenticationError() from exc
            if current.access_expires_at is None or current.access_expires_at > self._clock() + 30:
                return current
            if not current.refresh_token:
                await self.store.delete_downstream(principal_id)
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
                response.raise_for_status()
                payload = response.json()
                access_token = payload.get("access_token")
                refresh_token = payload.get("refresh_token", current.refresh_token)
                expires_in = payload.get("expires_in", 3600)
                if (
                    not isinstance(access_token, str)
                    or not access_token
                    or not isinstance(refresh_token, str)
                    or not refresh_token
                    or not isinstance(expires_in, int | float)
                    or expires_in <= 0
                ):
                    raise ValueError("invalid refresh response")
            except (httpx.HTTPError, ValueError, TypeError) as exc:
                await self.store.delete_downstream(principal_id)
                raise AuthenticationError() from exc
            updated = current.model_copy(
                update={
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "access_expires_at": self._clock() + float(expires_in),
                }
            )
            await self.store.put_downstream(principal_id, updated)
            return updated

    async def _principal_lock(self, principal_id: str) -> anyio.Lock:
        async with self._locks_guard:
            return self._locks.setdefault(principal_id, anyio.Lock())
