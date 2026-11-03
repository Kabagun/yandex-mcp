from unittest.mock import AsyncMock

import pytest

from yandex_workspace_mcp.models.disk import DiskLinkResponse, DiskResource, DiskResourcePage
from yandex_workspace_mcp.models.errors import InvalidPath
from yandex_workspace_mcp.policies.cursors import CursorCodec
from yandex_workspace_mcp.services.disk import DiskService


def _resource(path: str, name: str | None = None) -> DiskResource:
    return DiskResource(
        path=path,
        name=name or path.rsplit("/", 1)[-1],
        type="file",
    )


def _service(client: AsyncMock, roots: list[str]) -> DiskService:
    return DiskService(
        client,
        roots,
        True,
        False,
        False,
        cursor_codec=CursorCodec((b"d" * 32,)),
    )


@pytest.mark.asyncio
async def test_disk_search_post_filters_every_pathless_scan_item() -> None:
    client = AsyncMock()
    client.list_files.return_value = DiskResourcePage(
        items=[
            _resource("/Work/report.md"),
            _resource("/Workshop/leak.md"),
            _resource("/Personal/leak.md"),
        ],
        limit=50,
        offset=0,
    )
    service = _service(client, ["/Work"])

    result = await service.search(".md", limit=50, principal="person")

    assert [item.path for item in result.items] == ["/Work/report.md"]


@pytest.mark.asyncio
async def test_disk_search_scans_until_allowed_result_and_emits_cursor() -> None:
    client = AsyncMock()
    client.list_files.side_effect = [
        DiskResourcePage(
            items=[_resource("/Other/0.txt")],
            limit=1,
            offset=0,
        ),
        DiskResourcePage(
            items=[_resource("/Work/needle.txt")],
            limit=1,
            offset=1,
        ),
        DiskResourcePage(items=[], limit=1, offset=2),
    ]
    service = _service(client, ["/Work"])

    first = await service.search("needle", limit=1, principal="person")

    assert [item.path for item in first.items] == ["/Work/needle.txt"]
    assert first.next_cursor is not None
    second = await service.search("needle", limit=1, cursor=first.next_cursor, principal="person")
    assert client.list_files.await_args.kwargs["offset"] == 2
    assert second.items == []


@pytest.mark.asyncio
async def test_disk_search_scan_is_bounded_to_one_thousand_items() -> None:
    client = AsyncMock()
    client.list_files.return_value = DiskResourcePage(
        items=[_resource(f"/Other/{index}.txt") for index in range(100)],
        limit=100,
        offset=0,
    )
    service = _service(client, ["/Work"])

    result = await service.search("needle", limit=100, principal="person")

    assert client.list_files.await_count == 10
    assert result.truncated_by_upstream is True


def test_enabled_disk_service_rejects_empty_roots() -> None:
    with pytest.raises(InvalidPath):
        DiskService(AsyncMock(), [], True, False, False)


@pytest.mark.asyncio
async def test_direct_reads_authorize_before_calling_client() -> None:
    client = AsyncMock()
    service = _service(client, ["/Work"])

    for invocation in (
        service.list_folder("/Workshop"),
        service.get_metadata("/Personal/a.txt"),
        service.get_download_url("/Other/a.txt"),
        service.read_file("/Private/a.txt"),
    ):
        with pytest.raises(InvalidPath):
            await invocation

    client.assert_not_awaited()


@pytest.mark.asyncio
async def test_metadata_rejects_upstream_path_outside_authorized_root() -> None:
    client = AsyncMock()
    client.get_metadata.return_value = _resource("/Other/leak.txt")
    service = _service(client, ["/Work"])

    with pytest.raises(InvalidPath):
        await service.get_metadata("/Work/requested.txt")


@pytest.mark.asyncio
async def test_list_filters_embedded_children_and_recent_filters_every_item() -> None:
    client = AsyncMock()
    client.list_resources.return_value = DiskResource(
        path="/Work",
        name="Work",
        type="dir",
        embedded=DiskResourcePage(
            items=[_resource("/Work/ok.txt"), _resource("/Other/leak.txt")],
            limit=100,
            offset=0,
        ),
    )
    client.recent.return_value = DiskResourcePage(
        items=[_resource("/Work/new.txt"), _resource("/Other/leak.txt")],
        limit=100,
        offset=0,
    )
    client.get_download_link.return_value = DiskLinkResponse(
        download_url="https://downloader.disk.yandex.net/value"
    )
    service = _service(client, ["disk:/Work/"])
    service.signed_client = AsyncMock()

    listed = await service.list_folder("disk:/Work/")
    recent = await service.recent()
    link = await service.get_download_url("/Work/ok.txt")

    assert listed.path == "/Work"
    assert listed.embedded is not None
    assert [item.path for item in listed.embedded.items] == ["/Work/ok.txt"]
    assert [item.path for item in recent.items] == ["/Work/new.txt"]
    assert str(link.download_url).startswith("https://downloader.disk.yandex.net/")


@pytest.mark.asyncio
async def test_search_filters_encoded_paths_that_would_alias_an_authorized_root() -> None:
    client = AsyncMock()
    client.list_files.return_value = DiskResourcePage(
        items=[
            _resource("/Work/needle.txt"),
            _resource("/Personal/%2E%2E/Work/needle-private.txt"),
            _resource("/Personal%2F..%2FWork/needle-other.txt"),
            _resource("/Work/needle%00.txt"),
        ],
        limit=50,
        offset=0,
    )
    result = await _service(client, ["/Work"]).search("needle", limit=50, principal="person")
    assert [item.path for item in result.items] == ["/Work/needle.txt"]


@pytest.mark.asyncio
async def test_encoded_mutation_path_is_rejected_before_dispatch() -> None:
    client = AsyncMock()
    service = DiskService(client, ["/Work"], True, True, True)
    with pytest.raises(InvalidPath):
        await service.delete("/Work/private%2Ffile.txt")
    client.delete_resource.assert_not_awaited()
