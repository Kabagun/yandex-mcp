import os
from io import BytesIO
from pathlib import Path
from unittest.mock import AsyncMock
from zipfile import ZIP_DEFLATED, ZipFile

import httpx
import pytest

from tests.security.test_file_sources import BodyStream, PeerStream, public
from yandex_workspace_mcp.clients.disk import YandexDiskClient
from yandex_workspace_mcp.clients.files import PublicFileTransferClient
from yandex_workspace_mcp.clients.signed import SignedTransferClient
from yandex_workspace_mcp.models.disk import DiskOperationResponse, OpenAIFile
from yandex_workspace_mcp.models.errors import UpstreamUnavailable
from yandex_workspace_mcp.policies.local_files import open_allowed_local_file
from yandex_workspace_mcp.services.disk import DiskService


@pytest.mark.asyncio
@pytest.mark.skipif(
    os.name != "posix",
    reason="open_allowed_local_file() intentionally refuses all local access on non-POSIX systems",
)
async def test_local_upload_requests_one_link_then_one_guarded_put(tmp_path: Path) -> None:
    source = tmp_path / "payload.bin"
    source.write_bytes(b"payload")
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            json={"href": "https://uploader.disk.yandex.net/signed?secret=value", "method": "PUT"},
            request=request,
        )

    signed = AsyncMock()
    client = YandexDiskClient(
        token="token",
        client=httpx.AsyncClient(
            base_url="https://cloud-api.yandex.net/v1/disk",
            transport=httpx.MockTransport(handler),
        ),
    )
    opened = open_allowed_local_file(str(source), [str(tmp_path)], max_bytes=100)
    try:
        result = await client.upload_local_file(
            "/Work/payload.bin",
            opened,
            overwrite=True,
            signed_client=signed,
        )
    finally:
        opened.close()

    assert result == DiskOperationResponse(status="completed", path="/Work/payload.bin")
    assert len(requests) == 1
    assert dict(requests[0].url.params) == {"path": "/Work/payload.bin", "overwrite": "true"}
    signed.upload.assert_awaited_once()
    await client.close()


@pytest.mark.asyncio
async def test_inline_upload_uses_same_signed_transport() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"href": "https://uploader.disk.yandex.net/signed", "method": "PUT"},
            request=request,
        )

    signed = AsyncMock()
    client = YandexDiskClient(
        client=httpx.AsyncClient(
            base_url="https://cloud-api.yandex.net/v1/disk",
            transport=httpx.MockTransport(handler),
        ),
    )
    result = await client.upload_inline_text(
        "/Work/note.txt",
        "hello",
        overwrite=False,
        signed_client=signed,
    )

    assert result.path == "/Work/note.txt"
    signed.upload_bytes.assert_awaited_once_with(
        "https://uploader.disk.yandex.net/signed", b"hello"
    )
    await client.close()


@pytest.mark.asyncio
async def test_url_upload_sends_exact_official_request() -> None:
    requests: list[httpx.Request] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(201, request=request)

    client = YandexDiskClient(
        client=httpx.AsyncClient(
            base_url="https://cloud-api.yandex.net/v1/disk",
            transport=httpx.MockTransport(handler),
        ),
    )
    result = await client.upload_from_url(
        "https://downloads.example.test/file?signature=secret",
        "/Work/file",
        overwrite=True,
    )

    assert result.status == "completed"
    assert [(request.method, request.url.path) for request in requests] == [
        ("POST", "/v1/disk/resources/upload")
    ]
    assert dict(requests[0].url.params) == {
        "url": "https://downloads.example.test/file?signature=secret",
        "path": "/Work/file",
        "overwrite": "true",
    }
    await client.close()


@pytest.mark.parametrize("upload_status", [201, 500])
async def test_chatgpt_docx_upload_preserves_exact_binary_and_never_replays(upload_status) -> None:
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        archive.writestr(
            "[Content_Types].xml",
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>',
        )
        archive.writestr(
            "word/document.xml",
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>',
        )
    payload = buffer.getvalue()
    assert b"\x00" in payload
    with pytest.raises(UnicodeDecodeError):
        payload.decode("utf-8")
    calls = []

    def source_handler(request):
        calls.append(("source", request))
        return httpx.Response(
            200,
            stream=BodyStream([payload]),
            headers={"Content-Length": str(len(payload))},
            extensions={"network_stream": PeerStream()},
            request=request,
        )

    def api_handler(request):
        calls.append(("api", request))
        return httpx.Response(
            200,
            json={
                "href": "https://uploader.disk.yandex.net/signed?signature=private",
                "method": "PUT",
            },
            request=request,
        )

    async def upload_handler(request):
        calls.append(("upload", request))
        assert await request.aread() == payload
        assert "Authorization" not in request.headers and "Cookie" not in request.headers
        return httpx.Response(
            upload_status,
            stream=BodyStream([]),
            extensions={"network_stream": PeerStream()},
            request=request,
        )

    disk = YandexDiskClient(
        token="disk-private-token",
        client=httpx.AsyncClient(
            base_url="https://cloud-api.yandex.net/v1/disk",
            transport=httpx.MockTransport(api_handler),
        ),
    )
    source = PublicFileTransferClient(
        resolver=public,
        client=httpx.AsyncClient(transport=httpx.MockTransport(source_handler)),
    )
    signed = SignedTransferClient(
        resolver=public,
        client=httpx.AsyncClient(transport=httpx.MockTransport(upload_handler)),
    )
    service = DiskService(
        disk,
        ["/Work"],
        True,
        True,
        False,
        max_upload_bytes=len(payload),
        file_source_client=source,
        signed_client=signed,
    )
    file = OpenAIFile(
        download_url="https://files.example.test/document?capability=private",
        file_id="C:\\secret.docx",
        file_name="../../Private/override.docx",
        mime_type="application/x-untrusted",
    )
    try:
        if upload_status == 201:
            result = await service.upload_file(file, "/Work/report.docx")
            assert result == DiskOperationResponse(status="completed", path="/Work/report.docx")
        else:
            with pytest.raises(UpstreamUnavailable):
                await service.upload_file(file, "/Work/report.docx")
        assert [(kind, request.method) for kind, request in calls] == [
            ("source", "GET"),
            ("api", "GET"),
            ("upload", "PUT"),
        ]
        assert dict(calls[1][1].url.params) == {"path": "/Work/report.docx", "overwrite": "false"}
        assert calls[1][1].headers["Authorization"] == "OAuth disk-private-token"
        assert "Authorization" not in calls[0][1].headers
    finally:
        await source.close()
        await signed.close()
        await disk.close()
