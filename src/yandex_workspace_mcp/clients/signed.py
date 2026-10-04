import ipaddress
import socket
import ssl
import urllib.parse
from collections.abc import AsyncIterator, Awaitable, Callable, Iterable
from contextlib import asynccontextmanager
from typing import Any, Protocol, cast

import anyio
import httpcore
import httpx

from ..models.errors import InvalidInput, PermissionDenied, UpstreamUnavailable
from ..policies.local_files import AllowedLocalFile

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str], Awaitable[set[IPAddress]]]
SocketOption = (
    tuple[int, int, int] | tuple[int, int, bytes | bytearray] | tuple[int, int, None, int]
)
_DEFAULT_ALLOWED_HOSTS = ("downloader.disk.yandex.ru",)


class _NetworkBackend(Protocol):
    async def connect_tcp(self, host: str, port: int, **kwargs: Any) -> Any: ...


def _canonical_ip(address: IPAddress) -> IPAddress:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped
    return address


class _PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Connect the reviewed hostname to one already-resolved address."""

    def __init__(
        self,
        *,
        hostname: str,
        addresses: set[IPAddress],
        delegate: _NetworkBackend | None = None,
    ) -> None:
        self.hostname = hostname.casefold().rstrip(".")
        self.addresses = {_canonical_ip(address) for address in addresses}
        self.delegate = delegate or httpcore.AnyIOBackend()

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        if host.casefold().rstrip(".") != self.hostname or port != 443 or not self.addresses:
            raise PermissionDenied()
        selected = min(self.addresses, key=lambda value: (value.version, int(value)))
        stream = await self.delegate.connect_tcp(
            str(selected),
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )
        peer = stream.get_extra_info("server_addr")
        try:
            connected = _canonical_ip(ipaddress.ip_address(peer[0]))
        except (ValueError, TypeError, IndexError) as exc:
            await stream.aclose()
            raise PermissionDenied() from exc
        if connected not in self.addresses or not _is_public(connected):
            await stream.aclose()
            raise PermissionDenied()
        return cast(httpcore.AsyncNetworkStream, stream)

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise PermissionDenied()

    async def sleep(self, seconds: float) -> None:
        await anyio.sleep(seconds)


class _PinnedAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    def __init__(self, *, hostname: str, addresses: set[IPAddress]) -> None:
        super().__init__(trust_env=False, http1=True, http2=False, retries=0)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl.create_default_context(),
            max_connections=1,
            max_keepalive_connections=1,
            http1=True,
            http2=False,
            retries=0,
            network_backend=_PinnedNetworkBackend(
                hostname=hostname,
                addresses=addresses,
            ),
        )


def validate_signed_url(
    url: str,
    *,
    allowed_suffixes: tuple[str, ...] = ("yandex.net",),
    allowed_hosts: tuple[str, ...] = _DEFAULT_ALLOWED_HOSTS,
) -> str:
    """Accept HTTPS signed links under approved suffixes or at exact approved hosts."""
    if not isinstance(url, str) or not url:
        raise InvalidInput()
    parsed = urllib.parse.urlsplit(url)
    try:
        port = parsed.port
        if parsed.hostname is not None:
            ipaddress.ip_address(parsed.hostname)
            literal = True
        else:
            literal = False
    except ValueError:
        literal = False
        port = parsed.port
    host = (parsed.hostname or "").casefold().rstrip(".")
    suffixes = tuple(value.casefold().lstrip(".").rstrip(".") for value in allowed_suffixes)
    suffix_match = any(host == suffix or host.endswith(f".{suffix}") for suffix in suffixes)
    host_match = host in {value.casefold().rstrip(".") for value in allowed_hosts}
    if (
        parsed.scheme != "https"
        or not host
        or not (suffix_match or host_match)
        or literal
        or port not in {None, 443}
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise InvalidInput()
    return url


def _is_public(address: IPAddress) -> bool:
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return address.ipv4_mapped.is_global
    return address.is_global


async def _default_resolver(host: str) -> set[IPAddress]:
    def resolve() -> set[IPAddress]:
        return {
            ipaddress.ip_address(item[4][0])
            for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        }

    try:
        return await anyio.to_thread.run_sync(resolve)
    except OSError as exc:
        raise UpstreamUnavailable() from exc


class SignedTransferClient:
    def __init__(
        self,
        *,
        client: httpx.AsyncClient | None = None,
        resolver: Resolver = _default_resolver,
        allowed_suffixes: tuple[str, ...] = ("yandex.net",),
        allowed_hosts: tuple[str, ...] = _DEFAULT_ALLOWED_HOSTS,
        chunk_size: int = 1024 * 1024,
        max_response_bytes: int = 64 * 1024,
    ) -> None:
        self.client = client
        self.resolver = resolver
        self.allowed_suffixes = allowed_suffixes
        self.allowed_hosts = allowed_hosts
        self.chunk_size = chunk_size
        self.max_response_bytes = max_response_bytes
        self._closed = False

    @asynccontextmanager
    async def _client_for(
        self,
        url: str,
        addresses: set[IPAddress],
    ) -> AsyncIterator[httpx.AsyncClient]:
        if self.client is not None:
            yield self.client
            return
        hostname = urllib.parse.urlsplit(url).hostname
        if hostname is None:
            raise InvalidInput()
        async with httpx.AsyncClient(
            transport=_PinnedAsyncHTTPTransport(hostname=hostname, addresses=addresses),
            timeout=httpx.Timeout(30.0, connect=5.0),
            follow_redirects=False,
            headers={"Accept": "application/json"},
            trust_env=False,
        ) as client:
            yield client

    async def validate(self, url: str) -> tuple[str, set[IPAddress]]:
        validated = validate_signed_url(
            url, allowed_suffixes=self.allowed_suffixes, allowed_hosts=self.allowed_hosts
        )
        host = urllib.parse.urlsplit(validated).hostname
        if host is None:
            raise InvalidInput()
        addresses = await self.resolver(host)
        if not addresses or any(not _is_public(address) for address in addresses):
            raise PermissionDenied()
        return validated, addresses

    async def upload(self, url: str, opened: AllowedLocalFile) -> None:
        validated, addresses = await self.validate(url)
        opened.verify_identity()
        opened.seek(0)

        async def content() -> AsyncIterator[bytes]:
            while chunk := opened.read(self.chunk_size):
                yield chunk

        async with self._client_for(validated, addresses) as client:
            request = client.build_request(
                "PUT",
                validated,
                content=content(),
                headers={"Content-Type": "application/octet-stream"},
            )
            self._strip_credentials(request)
            response = await client.send(request, stream=True)
            await self._validate_upload_response(response, addresses)

    async def upload_bytes(self, url: str, content: bytes) -> None:
        validated, addresses = await self.validate(url)
        async with self._client_for(validated, addresses) as client:
            request = client.build_request(
                "PUT",
                validated,
                content=content,
                headers={"Content-Type": "application/octet-stream"},
            )
            self._strip_credentials(request)
            response = await client.send(request, stream=True)
            await self._validate_upload_response(response, addresses)

    async def _validate_upload_response(
        self, response: httpx.Response, addresses: set[IPAddress]
    ) -> None:
        try:
            if 300 <= response.status_code < 400:
                raise PermissionDenied()
            self._validate_peer(response, addresses)
            if response.status_code < 200 or response.status_code >= 300:
                raise UpstreamUnavailable()
            declared = response.headers.get("Content-Length")
            if declared is not None:
                try:
                    if int(declared) > self.max_response_bytes:
                        raise PermissionDenied()
                except ValueError as exc:
                    raise PermissionDenied() from exc
            received = 0
            async for chunk in response.aiter_bytes(self.chunk_size):
                received += len(chunk)
                if received > self.max_response_bytes:
                    raise PermissionDenied()
        finally:
            await response.aclose()

    async def download(self, url: str, *, max_bytes: int) -> bytes:
        if max_bytes < 0:
            raise InvalidInput()
        validated, addresses = await self.validate(url)
        async with self._client_for(validated, addresses) as client:
            request = client.build_request("GET", validated)
            self._strip_credentials(request)
            response = await client.send(request, stream=True)
            try:
                if 300 <= response.status_code < 400:
                    raise PermissionDenied()
                self._validate_peer(response, addresses)
                if response.status_code < 200 or response.status_code >= 300:
                    raise UpstreamUnavailable()
                declared = response.headers.get("Content-Length")
                if declared is not None:
                    try:
                        if int(declared) > max_bytes:
                            raise PermissionDenied()
                    except ValueError as exc:
                        raise PermissionDenied() from exc
                content = bytearray()
                async for chunk in response.aiter_bytes(self.chunk_size):
                    content.extend(chunk)
                    if len(content) > max_bytes:
                        raise PermissionDenied()
                return bytes(content)
            finally:
                await response.aclose()

    @staticmethod
    def _strip_credentials(request: httpx.Request) -> None:
        for header in ("Authorization", "Cookie", "Proxy-Authorization"):
            if header in request.headers:
                del request.headers[header]

    @staticmethod
    def _validate_peer(response: httpx.Response, expected: set[IPAddress]) -> None:
        stream = response.extensions.get("network_stream")
        peer = stream.get_extra_info("server_addr") if stream is not None else None
        if not peer or not isinstance(peer, tuple) or not peer:
            raise PermissionDenied()
        try:
            address = ipaddress.ip_address(peer[0])
        except ValueError as exc:
            raise PermissionDenied() from exc
        if address not in expected or not _is_public(address):
            raise PermissionDenied()

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            if self.client is not None:
                await self.client.aclose()
