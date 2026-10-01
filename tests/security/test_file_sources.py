import asyncio
import ipaddress

import httpx
import pytest

from yandex_workspace_mcp.clients.files import PublicFileTransferClient, validate_file_source_url
from yandex_workspace_mcp.clients.signed import SignedTransferClient
from yandex_workspace_mcp.models.errors import (
    InvalidInput,
    PermissionDenied,
    UpstreamTimeout,
    UpstreamUnavailable,
)


class PeerStream:
    def __init__(self, peer: str = "8.8.8.8") -> None:
        self.peer = peer

    def get_extra_info(self, name: str):
        return (self.peer, 443) if name == "server_addr" else None


class BodyStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes], *, cancel: bool = False) -> None:
        self.chunks = chunks
        self.cancel = cancel
        self.closed = False
        self.read_count = 0

    async def __aiter__(self):
        for chunk in self.chunks:
            self.read_count += 1
            yield chunk
        if self.cancel:
            raise asyncio.CancelledError

    async def aclose(self) -> None:
        self.closed = True


async def public(_host: str):
    return {ipaddress.ip_address("8.8.8.8")}


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "http://files.example.test/document",
        "https://files.example.test:444/document",
        "https://files.example.test:bad/document",
        "https://user:pass@files.example.test/document",
        "https://@files.example.test/document",
        "https://files.example.test/document#fragment",
        "https://files.example.test/document#",
        "https://127.0.0.1/document",
        "https://8.8.8.8/document",
        "https://[::ffff:127.0.0.1]/document",
        "https://[::1/document",
        "https://files.example.test\\@127.0.0.1/document",
        "https://files.example.test/document\n",
    ],
)
def test_file_url_shape_rejected_before_network(url: str) -> None:
    with pytest.raises(InvalidInput):
        validate_file_source_url(url)


@pytest.mark.parametrize("addresses", [[], ["127.0.0.1"], ["8.8.8.8", "10.0.0.1"]])
async def test_file_source_refuses_private_or_mixed_dns_before_fetch(addresses) -> None:
    async def resolver(_host):
        return {ipaddress.ip_address(value) for value in addresses}

    def reject(_request):
        raise AssertionError("No source request is allowed")

    client = PublicFileTransferClient(
        resolver=resolver, client=httpx.AsyncClient(transport=httpx.MockTransport(reject))
    )
    try:
        with pytest.raises(PermissionDenied):
            await client.download(
                "https://files.example.test/private?capability=secret", max_bytes=5
            )
    finally:
        await client.close()


async def test_public_file_policy_keeps_signed_yandex_policy_separate() -> None:
    source = PublicFileTransferClient(resolver=public)
    assert (await source.validate("https://files.example.test/document"))[0].startswith("https://")
    signed = SignedTransferClient(resolver=public)
    with pytest.raises(InvalidInput):
        await signed.validate("https://files.example.test/document")


@pytest.mark.parametrize(
    "status,headers,peer,error,match",
    [
        (
            302,
            {"Location": "https://other.example.test/secret"},
            "8.8.8.8",
            PermissionDenied,
            "redirect",
        ),
        (200, {}, "127.0.0.1", PermissionDenied, "Permission denied"),
        (200, {"Content-Length": "6"}, "8.8.8.8", PermissionDenied, "maximum size"),
        (200, {"Content-Length": "-1"}, "8.8.8.8", InvalidInput, "invalid length"),
        (200, {"Content-Length": "invalid"}, "8.8.8.8", InvalidInput, "invalid length"),
        (200, {"Content-Length": "9" * 5000}, "8.8.8.8", InvalidInput, "invalid length"),
        (200, {"Content-Encoding": "gzip"}, "8.8.8.8", InvalidInput, "identity"),
        (403, {}, "8.8.8.8", InvalidInput, "Attach the file again"),
        (404, {}, "8.8.8.8", InvalidInput, "Attach the file again"),
        (500, {}, "8.8.8.8", UpstreamUnavailable, "source is unavailable"),
    ],
)
async def test_rejected_source_response_is_closed_without_read_or_redirect(
    status, headers, peer, error, match
) -> None:
    body = BodyStream([b"source-private-body"])
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            status,
            headers=headers,
            stream=body,
            extensions={"network_stream": PeerStream(peer)},
            request=request,
        )

    client = PublicFileTransferClient(
        resolver=public,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=True),
    )
    try:
        with pytest.raises(error, match=match) as failure:
            await client.download(
                "https://files.example.test/private?capability=secret", max_bytes=5
            )
        assert "capability" not in str(failure.value) and "private-body" not in str(failure.value)
        assert len(calls) == 1
        assert body.closed and body.read_count == 0
    finally:
        await client.close()


@pytest.mark.parametrize("headers", [{}, {"Content-Length": "2"}])
async def test_actual_stream_cap_enforced_for_missing_or_understated_length(headers) -> None:
    body = BodyStream([b"123", b"456", b"should-not-read"])

    def handler(request):
        return httpx.Response(
            200,
            headers=headers,
            stream=body,
            extensions={"network_stream": PeerStream()},
            request=request,
        )

    client = PublicFileTransferClient(
        resolver=public,
        chunk_size=3,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    try:
        with pytest.raises(PermissionDenied, match="maximum size"):
            await client.download("https://files.example.test/document", max_bytes=5)
        assert body.closed and body.read_count == 2
    finally:
        await client.close()


async def test_source_bytes_and_credential_isolation() -> None:
    payload = b"PK\x03\x04\x00\xff\x80\x00"
    body = BodyStream([payload])
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(
            200,
            stream=body,
            extensions={"network_stream": PeerStream()},
            request=request,
        )

    client = PublicFileTransferClient(
        resolver=public,
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(handler),
            auth=httpx.BasicAuth("user", "secret"),
            headers={"Authorization": "OAuth yandex", "Proxy-Authorization": "secret"},
            cookies={"session": "secret"},
        ),
    )
    try:
        assert (
            await client.download("https://files.example.test/document", max_bytes=len(payload))
            == payload
        )
        assert body.closed
        assert calls[0].headers["Accept-Encoding"] == "identity"
        assert not any(
            header in calls[0].headers
            for header in ("Authorization", "Cookie", "Proxy-Authorization")
        )
    finally:
        await client.close()


@pytest.mark.parametrize("error", [httpx.ConnectError, httpx.ReadTimeout])
async def test_source_network_errors_do_not_expose_capability(error) -> None:
    calls = []

    def handler(request):
        calls.append(request)
        raise error("https://files.example.test/private-capability?secret=value", request=request)

    client = PublicFileTransferClient(
        resolver=public, client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    try:
        expected = UpstreamTimeout if error is httpx.ReadTimeout else UpstreamUnavailable
        with pytest.raises(expected) as failure:
            await client.download("https://files.example.test/document", max_bytes=5)
        assert "secret" not in str(failure.value) and "capability" not in str(failure.value)
        assert len(calls) == 1
    finally:
        await client.close()


async def test_source_response_closed_on_cancellation() -> None:
    body = BodyStream([b"ok"], cancel=True)

    def handler(request):
        return httpx.Response(
            200, stream=body, extensions={"network_stream": PeerStream()}, request=request
        )

    client = PublicFileTransferClient(
        resolver=public, client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    try:
        with pytest.raises(asyncio.CancelledError):
            await client.download("https://files.example.test/document", max_bytes=5)
        assert body.closed
    finally:
        await client.close()
