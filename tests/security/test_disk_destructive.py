from unittest.mock import AsyncMock

import pytest

from yandex_workspace_mcp.models.disk import DiskResource, DiskTrashEntry, DiskTrashPage
from yandex_workspace_mcp.models.errors import InvalidPath
from yandex_workspace_mcp.services.disk import DiskService


def _service(client: AsyncMock, roots: list[str]) -> DiskService:
    return DiskService(client, roots, True, True, True)


@pytest.mark.asyncio
async def test_copy_and_move_authorize_source_and_destination() -> None:
    client = AsyncMock()
    service = _service(client, ["/Work"])

    with pytest.raises(InvalidPath):
        await service.copy("/Work/a", "/Other/b")
    with pytest.raises(InvalidPath):
        await service.move("/Other/a", "/Work/b")

    client.assert_not_awaited()


@pytest.mark.asyncio
async def test_permanent_delete_of_configured_root_is_forbidden() -> None:
    client = AsyncMock()
    service = _service(client, ["/Work"])

    with pytest.raises(InvalidPath):
        await service.delete("/Work", permanently=True)
    client.delete_resource.assert_not_awaited()


@pytest.mark.asyncio
async def test_rename_rejects_non_basename_before_client_call() -> None:
    client = AsyncMock()
    service = _service(client, ["/Work"])

    with pytest.raises(InvalidPath):
        await service.rename("/Work/a.txt", "../leak.txt")
    client.move_resource.assert_not_awaited()


@pytest.mark.asyncio
async def test_trash_list_filters_by_original_path_and_restore_authorizes_effective_destination() -> (
    None
):
    client = AsyncMock()
    client.list_trash.return_value = DiskTrashPage(
        items=[
            DiskTrashEntry(
                resource=DiskResource(path="/a.txt", name="a.txt", type="file"),
                origin_path="/Work/a.txt",
            ),
            DiskTrashEntry(
                resource=DiskResource(path="/leak.txt", name="leak.txt", type="file"),
                origin_path="/Other/leak.txt",
            ),
        ],
        limit=100,
        offset=0,
    )
    client.get_trash_resource.return_value = DiskTrashEntry(
        resource=DiskResource(path="/a.txt", name="a.txt", type="file"),
        origin_path="/Work/a.txt",
    )
    service = _service(client, ["/Work"])

    page = await service.list_trash()
    assert [item.name for item in page.items] == ["a.txt"]
    with pytest.raises(InvalidPath):
        await service.restore_from_trash("/a.txt", destination_path="/Other/a.txt")


@pytest.mark.asyncio
async def test_empty_trash_is_forbidden_even_with_all_legacy_gates() -> None:
    client = AsyncMock()
    for roots, global_flag, confirm in [
        (["/"], True, True),
        (["/Work"], True, True),
        (["/"], False, True),
        (["/"], True, False),
    ]:
        service = DiskService(
            client,
            roots,
            True,
            True,
            True,
            allow_global_destructive=global_flag,
        )
        with pytest.raises(InvalidPath):
            await service.empty_trash(confirm=confirm)
    client.empty_trash.assert_not_awaited()
