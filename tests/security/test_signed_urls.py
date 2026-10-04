import asyncio
import ipaddress
from collections.abc import AsyncIterator

import httpx
import pytest

from yandex_workspace_mcp.clients.disk import validate_yandex_signed_url
from yandex_workspace_mcp.clients.signed import (
    SignedTransferClient,
    _PinnedNetworkBackend,
    validate_signed_url,
)
from yandex_workspace_mcp.models.errors import InvalidInput, PermissionDenied, UpstreamUnavailable


class _PeerStream:
    def __init__(self, peer: str) -> None:
        self.peer = peer

    def get_extra_info(self, name: str):
        return (self.peer, 443) if name == "server_addr" else None


class _BodyStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes], *, cancel: bool = False) -> None:
        self.chunks = chunks
        self.cancel = cancel
        self.closed = False
        self.read_count = 0

    async def __aiter__(self) -> AsyncIterator[bytes]:
        for chunk in self.chunks:
            self.read_count += 1
            yield chunk
        if self.cancel:
            raise asyncio.CancelledError

    async def aclose(self) -> None:
        self.closed = True


async def _public(_host: str):
    return {ipaddress.ip_address("8.8.8.8")}


@pytest.mark.parametrize(
    "host",
    [
        "downloader.disk.yandex.net",
        "downloader.disk.yandex.ru",
        "DOWNLOADER.DISK.YANDEX.RU",
        "downloader.disk.yandex.ru.",
        "storage.yandex.net",
    ],
)
def test_signed_url_accepts_official_download_hosts(host: str) -> None:
    url = f"https://{host}/file?signature=test-only"
    assert validate_signed_url(url) == url
    validate_yandex_signed_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://downloader.disk.yandex.net/file",
        "https://user:pass@downloader.disk.yandex.net/file",
        "https://downloader.disk.yandex.net:444/file",
        "https://127.0.0.1/file",
        "https://[::ffff:127.0.0.1]/file",
        "https://downloader.disk.yandex.net/file#fragment",
        "https://downloader.disk.yandex.net.evil.test/file",
        "http://downloader.disk.yandex.ru/file",
        "https://user:pass@downloader.disk.yandex.ru/file",
        "https://downloader.disk.yandex.ru:444/file",
        "https://downloader.disk.yandex.ru/file#fragment",
        "https://downloader.disk.yandex.ru.evil.test/file",
        "https://evil-downloader.disk.yandex.ru/file",
        "https://evil.downloader.disk.yandex.ru/file",
        "https://yandex.ru/file",
        "https://disk.yandex.ru/file",
        "https://other.yandex.ru/file",
    ],
)
def test_signed_url_shape_is_strict(url: str) -> None:
    with pytest.raises(InvalidInput):
        validate_signed_url(url)


@pytest.mark.asyncio
async def test_signed_download_host_allowlist_can_be_overridden() -> None:
    url = "https://downloader.disk.yandex.ru/file"
    with pytest.raises(InvalidInput):
        validate_signed_url(url, allowed_hosts=())
    client = SignedTransferClient(resolver=_public, allowed_hosts=())
    with pytest.raises(InvalidInput):
        await client.validate(url)
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["downloader.disk.yandex.net", "downloader.disk.yandex.ru"])
async def test_signed_validation_rejects_mixed_public_private_dns(host: str) -> None:
    async def mixed(_host: str):
        return {ipaddress.ip_address("8.8.8.8"), ipaddress.ip_address("10.0.0.1")}

    client = SignedTransferClient(
        client=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200))),
        resolver=mixed,
    )
    with pytest.raises(PermissionDenied):
        await client.validate(f"https://{host}/file?secret=value")
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("host", ["downloader.disk.yandex.net", "downloader.disk.yandex.ru"])
async def test_signed_download_is_tokenless_peer_checked_and_bounded(host: str) -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            content=b"hello",
            headers={"Content-Length": "5"},
            extensions={"network_stream": _PeerStream("8.8.8.8")},
            request=request,
        )

    client = SignedTransferClient(
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            headers={"Authorization": "Bearer must-not-leak"},
            follow_redirects=False,
        ),
        resolver=_public,
    )
    assert await client.download(f"https://{host}/file?secret=value", max_bytes=5) == b"hello"
    assert requests[0].headers.get("Authorization") is None
    await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
async def test_official_download_redirect_validates_each_hop_without_credentials(
    status: int,
) -> None:
    source = "https://downloader.disk.yandex.ru/file?signature=test-only"
    target = "https://s64nrg.storage.yandex.net/file?signature=next-test-only"
    bodies = [_BodyStream([b"redirect-body"]), _BodyStream([b"hello"])]
    requests: list[httpx.Request] = []
    dns_calls: list[str] = []

    async def resolver(host: str):
        dns_calls.append(host)
        return {ipaddress.ip_address("8.8.8.8" if len(dns_calls) == 1 else "1.1.1.1")}

    def handler(request: httpx.Request) -> httpx.Response:
        index = len(requests)
        requests.append(request)
        if index:
            assert bodies[0].closed and bodies[0].read_count == 0
        return httpx.Response(
            status if index == 0 else 200,
            headers=(
                {"Location": target, "Set-Cookie": "from_redirect=must-not-leak; Path=/"}
                if index == 0
                else {"Content-Length": "5"}
            ),
            stream=bodies[index],
            extensions={"network_stream": _PeerStream("8.8.8.8" if index == 0 else "1.1.1.1")},
            request=request,
        )

    client = SignedTransferClient(
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            auth=httpx.BasicAuth("user", "must-not-leak"),
            headers={
                "Authorization": "Bearer must-not-leak",
                "Cookie": "header_cookie=must-not-leak",
                "Proxy-Authorization": "Basic must-not-leak",
            },
            cookies={"client_cookie": "must-not-leak"},
            follow_redirects=True,
        ),
        resolver=resolver,
    )
    try:
        assert await client.download(source, max_bytes=5) == b"hello"
        assert dns_calls == ["downloader.disk.yandex.ru", "s64nrg.storage.yandex.net"]
        assert [str(request.url) for request in requests] == [source, target]
        assert all(request.method == "GET" for request in requests)
        assert all(
            header not in request.headers
            for request in requests
            for header in ("Authorization", "Cookie", "Proxy-Authorization")
        )
        assert all(body.closed for body in bodies)
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "location,target",
    [
        ("../final?signature=next", "https://downloader.disk.yandex.ru/final?signature=next"),
        ("/final?signature=next", "https://downloader.disk.yandex.ru/final?signature=next"),
        (
            "//s64nrg.storage.yandex.net/final?signature=next",
            "https://s64nrg.storage.yandex.net/final?signature=next",
        ),
    ],
)
async def test_signed_download_resolves_relative_redirect_locations(
    location: str, target: str
) -> None:
    requests: list[httpx.Request] = []
    dns_calls: list[str] = []

    async def resolver(host: str):
        dns_calls.append(host)
        return await _public(host)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            302 if len(requests) == 1 else 200,
            headers={"Location": location} if len(requests) == 1 else {},
            content=b"" if len(requests) == 1 else b"ok",
            extensions={"network_stream": _PeerStream("8.8.8.8")},
            request=request,
        )

    client = SignedTransferClient(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)), resolver=resolver
    )
    try:
        assert (
            await client.download(
                "https://downloader.disk.yandex.ru/start/file?signature=first", max_bytes=2
            )
            == b"ok"
        )
        assert str(requests[1].url) == target
        assert dns_calls == ["downloader.disk.yandex.ru", requests[1].url.host]
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_signed_download_pins_and_closes_a_new_transport_for_each_of_four_hops(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hosts = ["downloader.disk.yandex.ru"] + ["s64nrg.storage.yandex.net"] * 3
    expected_ips = ["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4"]
    bodies = [_BodyStream([b"redirect-body"]) for _ in range(3)] + [_BodyStream([b"ok"])]
    transports: list["Transport"] = []
    dns_calls: list[str] = []

    async def resolver(host: str):
        dns_calls.append(host)
        return {ipaddress.ip_address(expected_ips[len(dns_calls) - 1])}

    class Transport(httpx.AsyncBaseTransport):
        def __init__(self, *, hostname: str, addresses: set) -> None:
            self.index = len(transports)
            self.closed = False
            assert hostname == hosts[self.index]
            assert addresses == {ipaddress.ip_address(expected_ips[self.index])}
            assert all(transport.closed for transport in transports)
            transports.append(self)

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            assert all(body.closed for body in bodies[: self.index])
            return httpx.Response(
                302 if self.index < 3 else 200,
                headers={"Location": f"https://s64nrg.storage.yandex.net/{self.index + 1}"},
                stream=bodies[self.index],
                extensions={"network_stream": _PeerStream(expected_ips[self.index])},
                request=request,
            )

        async def aclose(self) -> None:
            self.closed = True

    monkeypatch.setattr("yandex_workspace_mcp.clients.signed._PinnedAsyncHTTPTransport", Transport)
    client = SignedTransferClient(resolver=resolver)
    try:
        assert (
            await client.download("https://downloader.disk.yandex.ru/start", max_bytes=2) == b"ok"
        )
        assert dns_calls == hosts
        assert len(transports) == 4 and all(transport.closed for transport in transports)
        assert all(body.closed for body in bodies)
        assert all(body.read_count == 0 for body in bodies[:3])
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "target",
    [
        "https://evil.test/file",
        "https://s64nrg.storage.yandex.net.evil.test/file",
        "https://other.yandex.ru/file",
        "http://s64nrg.storage.yandex.net/file",
        "https://user:pass@s64nrg.storage.yandex.net/file",
        "https://s64nrg.storage.yandex.net:444/file",
        "https://s64nrg.storage.yandex.net/file#fragment",
        "https://127.0.0.1/file",
    ],
)
async def test_redirect_target_url_is_rejected_before_dns_or_fetch(target: str) -> None:
    body = _BodyStream([b"redirect-body"])
    requests: list[httpx.Request] = []
    dns_calls: list[str] = []

    async def resolver(host: str):
        dns_calls.append(host)
        return await _public(host)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            302,
            headers={"Location": target},
            stream=body,
            extensions={"network_stream": _PeerStream("8.8.8.8")},
            request=request,
        )

    client = SignedTransferClient(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True),
        resolver=resolver,
    )
    try:
        with pytest.raises(InvalidInput):
            await client.download("https://downloader.disk.yandex.ru/file", max_bytes=5)
        assert dns_calls == ["downloader.disk.yandex.ru"] and len(requests) == 1
        assert body.closed and body.read_count == 0
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("target_addresses", [[], ["10.0.0.1"], ["8.8.8.8", "10.0.0.1"]])
async def test_redirect_target_private_or_mixed_dns_is_rejected_before_fetch(
    target_addresses: list[str],
) -> None:
    body = _BodyStream([b"redirect-body"])
    requests: list[httpx.Request] = []
    dns_calls: list[str] = []

    async def resolver(host: str):
        dns_calls.append(host)
        if len(dns_calls) == 1:
            return await _public(host)
        assert body.closed
        return {ipaddress.ip_address(address) for address in target_addresses}

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            302,
            headers={"Location": "https://s64nrg.storage.yandex.net/file"},
            stream=body,
            extensions={"network_stream": _PeerStream("8.8.8.8")},
            request=request,
        )

    client = SignedTransferClient(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)), resolver=resolver
    )
    try:
        with pytest.raises(PermissionDenied):
            await client.download("https://downloader.disk.yandex.ru/file", max_bytes=5)
        assert dns_calls == ["downloader.disk.yandex.ru", "s64nrg.storage.yandex.net"]
        assert len(requests) == 1 and body.closed and body.read_count == 0
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_hop", [0, 1])
@pytest.mark.parametrize("peer", [None, "1.1.1.1", "10.0.0.1"])
async def test_signed_download_checks_redirect_and_final_peers_before_accepting_response(
    failed_hop: int, peer: str | None
) -> None:
    bodies = [_BodyStream([b"must-not-read"]) for _ in range(failed_hop + 1)]
    requests: list[httpx.Request] = []
    dns_calls: list[str] = []

    async def resolver(host: str):
        dns_calls.append(host)
        return await _public(host)

    def handler(request: httpx.Request) -> httpx.Response:
        index = len(requests)
        requests.append(request)
        response_peer = peer if index == failed_hop else "8.8.8.8"
        return httpx.Response(
            302 if index == 0 else 200,
            headers={"Location": "https://s64nrg.storage.yandex.net/file"},
            stream=bodies[index],
            extensions={"network_stream": _PeerStream(response_peer)} if response_peer else {},
            request=request,
        )

    client = SignedTransferClient(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)), resolver=resolver
    )
    try:
        with pytest.raises(PermissionDenied):
            await client.download("https://downloader.disk.yandex.ru/file", max_bytes=5)
        assert len(requests) == len(dns_calls) == failed_hop + 1
        assert all(body.closed and body.read_count == 0 for body in bodies)
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,location",
    [
        (300, "/file"),
        (304, "/file"),
        (305, "/file"),
        (306, "/file"),
        (302, None),
        (302, ""),
        (302, " "),
    ],
)
async def test_unsupported_or_missing_location_redirect_is_closed_without_reading(
    status: int, location: str | None
) -> None:
    body = _BodyStream([b"redirect-body"])
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            status,
            headers={"Location": location} if location is not None else {},
            stream=body,
            extensions={"network_stream": _PeerStream("8.8.8.8")},
            request=request,
        )

    client = SignedTransferClient(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)), resolver=_public
    )
    try:
        with pytest.raises(PermissionDenied):
            await client.download("https://downloader.disk.yandex.ru/file", max_bytes=5)
        assert len(requests) == 1 and body.closed and body.read_count == 0
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("loop", [False, True])
async def test_signed_download_stops_redirect_chains_and_loops_after_four_requests(
    loop: bool,
) -> None:
    bodies: list[_BodyStream] = []
    requests: list[httpx.Request] = []
    dns_calls: list[str] = []

    async def resolver(host: str):
        dns_calls.append(host)
        assert all(body.closed for body in bodies)
        return await _public(host)

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        assert len(requests) <= 4
        body = _BodyStream([b"redirect-body"])
        bodies.append(body)
        return httpx.Response(
            302,
            headers={"Location": "/file" if loop else f"/file-{len(requests)}"},
            stream=body,
            extensions={"network_stream": _PeerStream("8.8.8.8")},
            request=request,
        )

    client = SignedTransferClient(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True),
        resolver=resolver,
    )
    try:
        with pytest.raises(PermissionDenied):
            await client.download("https://downloader.disk.yandex.ru/file", max_bytes=5)
        assert len(requests) == len(dns_calls) == 4
        assert all(body.closed and body.read_count == 0 for body in bodies)
    finally:
        await client.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "status,headers,error,read_count",
    [
        (200, {"Content-Length": "6"}, PermissionDenied, 0),
        (200, {}, PermissionDenied, 2),
        (200, {"Content-Length": "invalid"}, PermissionDenied, 0),
        (404, {}, UpstreamUnavailable, 0),
    ],
)
async def test_final_response_after_redirect_preserves_limits_and_status_handling(
    status: int, headers: dict[str, str], error: type[Exception], read_count: int
) -> None:
    bodies = [_BodyStream([b"redirect-body"]), _BodyStream([b"123", b"456", b"must-not-read"])]
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        index = len(requests)
        requests.append(request)
        return httpx.Response(
            302 if index == 0 else status,
            headers={"Location": "https://s64nrg.storage.yandex.net/file"}
            if index == 0
            else headers,
            stream=bodies[index],
            extensions={"network_stream": _PeerStream("8.8.8.8")},
            request=request,
        )

    client = SignedTransferClient(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        resolver=_public,
        chunk_size=3,
    )
    try:
        with pytest.raises(error):
            await client.download("https://downloader.disk.yandex.ru/file", max_bytes=5)
        assert len(requests) == 2 and all(body.closed for body in bodies)
        assert bodies[0].read_count == 0 and bodies[1].read_count == read_count
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_signed_download_closes_final_stream_on_cancellation_after_redirect() -> None:
    bodies = [_BodyStream([b"redirect-body"]), _BodyStream([b"ok"], cancel=True)]
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        index = len(requests)
        requests.append(request)
        return httpx.Response(
            302 if index == 0 else 200,
            headers={"Location": "/final"},
            stream=bodies[index],
            extensions={"network_stream": _PeerStream("8.8.8.8")},
            request=request,
        )

    client = SignedTransferClient(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)), resolver=_public
    )
    try:
        with pytest.raises(asyncio.CancelledError):
            await client.download("https://downloader.disk.yandex.ru/file", max_bytes=5)
        assert all(body.closed for body in bodies)
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_signed_upload_streams_and_rejects_oversized_response_body() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"response-too-large",
            extensions={"network_stream": _PeerStream("8.8.8.8")},
            request=request,
        )

    client = SignedTransferClient(
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        resolver=_public,
        max_response_bytes=4,
    )
    with pytest.raises(PermissionDenied):
        await client.upload_bytes(
            "https://uploader.yandex.net/file?signature=secret",
            b"upload",
        )
    await client.close()


class _CoreStream:
    def __init__(self, peer: str) -> None:
        self.peer = peer
        self.closed = False

    def get_extra_info(self, name: str):
        return (self.peer, 443) if name == "server_addr" else None

    async def aclose(self) -> None:
        self.closed = True


class _CoreBackend:
    def __init__(self, stream: _CoreStream) -> None:
        self.stream = stream
        self.connected_host: str | None = None

    async def connect_tcp(self, host: str, port: int, **_kwargs):
        self.connected_host = host
        return self.stream


@pytest.mark.asyncio
async def test_default_backend_pins_validated_ip_before_http_bytes() -> None:
    stream = _CoreStream("8.8.8.8")
    delegate = _CoreBackend(stream)
    backend = _PinnedNetworkBackend(
        hostname="downloader.disk.yandex.net",
        addresses={ipaddress.ip_address("8.8.8.8")},
        delegate=delegate,
    )

    assert await backend.connect_tcp("downloader.disk.yandex.net", 443) is stream
    assert delegate.connected_host == "8.8.8.8"

    mismatch = _CoreStream("1.1.1.1")
    backend = _PinnedNetworkBackend(
        hostname="downloader.disk.yandex.net",
        addresses={ipaddress.ip_address("8.8.8.8")},
        delegate=_CoreBackend(mismatch),
    )
    with pytest.raises(PermissionDenied):
        await backend.connect_tcp("downloader.disk.yandex.net", 443)
    assert mismatch.closed is True
