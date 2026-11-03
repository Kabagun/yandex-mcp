import random
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Literal

import anyio
import httpx

from ..models.errors import (
    AuthenticationError,
    InvalidInput,
    PermissionDenied,
    RateLimitExceeded,
    ResourceNotFound,
    RevisionConflict,
    UpstreamTimeout,
    UpstreamUnavailable,
)


class RequestSemantics(StrEnum):
    SAFE_READ = "safe_read"
    LOGICAL_READ = "logical_read"
    MUTATION = "mutation"
    SIGNED_UPLOAD = "signed_upload"


@dataclass(frozen=True, slots=True)
class RequestCredentials:
    token: str
    scheme: Literal["OAuth", "Bearer"] = "OAuth"
    headers: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "headers", MappingProxyType(dict(self.headers)))

    @property
    def authorization(self) -> str:
        return f"{self.scheme} {self.token}"


class BaseYandexClient:
    def __init__(
        self,
        token: str | None = None,
        base_url: str = "",
        headers: dict[str, str] | None = None,
        *,
        client: httpx.AsyncClient | None = None,
        sleeper: Callable[[float], Awaitable[None]] = anyio.sleep,
        jitter: Callable[[float, float], float] = random.uniform,
        clock: Callable[[], float] = time.monotonic,
        credential_provider: Callable[[], Awaitable[RequestCredentials]] | None = None,
    ) -> None:
        self.base_url = base_url
        self._default_credentials = (
            RequestCredentials(token=token, headers=headers or {}) if token else None
        )
        self.client = client or httpx.AsyncClient(
            base_url=base_url,
            headers={"Accept": "application/json"},
            timeout=httpx.Timeout(10.0, connect=5.0),
            follow_redirects=False,
        )
        self._sleeper = sleeper
        self._jitter = jitter
        self._clock = clock
        self._credential_provider = credential_provider
        self._closed = False

    async def _request(
        self,
        method: str,
        path: str,
        retries: int | None = None,
        *,
        semantics: RequestSemantics | None = None,
        credentials: RequestCredentials | None = None,
        operation_timeout: float = 30.0,
        translate_errors: bool = True,
        **kwargs: Any,
    ) -> httpx.Response:
        semantics = semantics or self._default_semantics(method)
        safe = semantics in {
            RequestSemantics.SAFE_READ,
            RequestSemantics.LOGICAL_READ,
        }
        max_attempts = min(3, retries or 3) if safe else 1
        started_at = self._clock()
        request_headers = dict(kwargs.pop("headers", {}) or {})
        selected_credentials = credentials or self._default_credentials
        if selected_credentials is None and self._credential_provider is not None:
            remaining = operation_timeout - (self._clock() - started_at)
            if remaining <= 0:
                raise UpstreamTimeout()
            try:
                with anyio.fail_after(remaining) as credential_scope:
                    selected_credentials = await self._credential_provider()
            except TimeoutError:
                if not credential_scope.cancelled_caught:
                    raise
                raise UpstreamTimeout() from None
        if selected_credentials:
            request_headers.update(selected_credentials.headers)
            request_headers["Authorization"] = selected_credentials.authorization

        last_transport_error: httpx.TransportError | None = None
        for attempt in range(max_attempts):
            remaining = operation_timeout - (self._clock() - started_at)
            if remaining <= 0:
                raise UpstreamTimeout()
            try:
                # HTTPX's inactivity timeouts do not bound a slowly streaming body.
                with anyio.fail_after(remaining) as request_scope:
                    response = await self.client.request(
                        method,
                        path,
                        headers=request_headers or None,
                        **kwargs,
                    )
            except TimeoutError:
                if not request_scope.cancelled_caught:
                    raise
                raise UpstreamTimeout() from None
            except httpx.TransportError as exc:
                last_transport_error = exc
                if not safe or attempt == max_attempts - 1:
                    raise self._transport_error(exc) from None
                await self._wait_before_retry(
                    attempt=attempt,
                    started_at=started_at,
                    operation_timeout=operation_timeout,
                )
                continue

            if response.status_code in {429, 502, 503, 504} and safe and attempt < max_attempts - 1:
                await self._wait_before_retry(
                    attempt=attempt,
                    started_at=started_at,
                    operation_timeout=operation_timeout,
                    retry_after=response.headers.get("Retry-After"),
                )
                continue
            if translate_errors:
                self._raise_for_status(response)
            return response

        if isinstance(last_transport_error, httpx.TimeoutException):
            raise UpstreamTimeout()
        raise UpstreamUnavailable()

    @staticmethod
    def _default_semantics(method: str) -> RequestSemantics:
        return (
            RequestSemantics.SAFE_READ
            if method.upper() in {"GET", "HEAD"}
            else RequestSemantics.MUTATION
        )

    async def _wait_before_retry(
        self,
        *,
        attempt: int,
        started_at: float,
        operation_timeout: float,
        retry_after: str | None = None,
    ) -> None:
        delay: float
        if retry_after is not None:
            try:
                delay = min(3.0, max(0.0, float(retry_after)))
            except ValueError:
                delay = self._jitter(0.0, min(3.0, 0.5 * (2**attempt)))
        else:
            delay = self._jitter(0.0, min(3.0, 0.5 * (2**attempt)))
        remaining = operation_timeout - (self._clock() - started_at)
        if delay >= remaining:
            raise UpstreamTimeout()
        try:
            with anyio.fail_after(remaining) as backoff_scope:
                await self._sleeper(delay)
        except TimeoutError:
            if not backoff_scope.cancelled_caught:
                raise
            raise UpstreamTimeout() from None

    @staticmethod
    def _transport_error(error: httpx.TransportError) -> UpstreamUnavailable | UpstreamTimeout:
        if isinstance(error, httpx.TimeoutException):
            return UpstreamTimeout()
        return UpstreamUnavailable()

    @staticmethod
    def _raise_for_status(response: httpx.Response) -> None:
        status = response.status_code
        if status < 400:
            return
        if status == 400:
            raise InvalidInput()
        if status == 401:
            raise AuthenticationError()
        if status == 403:
            raise PermissionDenied()
        if status == 404:
            raise ResourceNotFound()
        if status == 409:
            raise RevisionConflict()
        if status == 408:
            raise UpstreamTimeout()
        if status == 429:
            raise RateLimitExceeded()
        if status >= 500:
            raise UpstreamUnavailable()
        raise InvalidInput()

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            await self.client.aclose()
