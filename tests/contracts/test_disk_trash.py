import httpx
import pytest

from yandex_workspace_mcp.clients.disk import YandexDiskClient
from yandex_workspace_mcp.models.errors import PermissionDenied


@pytest.mark.asyncio
async def test_trash_clients_use_exact_endpoints_and_preserve_origin_for_policy() -> None:
    requests: list[httpx.Request] = []
    responses = iter(
        [
            httpx.Response(
                200,
                json={
                    "name": "trash",
                    "type": "dir",
                    "_embedded": {
                        "items": [
                            {
                                "name": "a.txt",
                                "path": "trash:/a.txt",
                                "origin_path": "disk:/Work/a.txt",
                                "type": "file",
                            }
                        ],
                        "limit": 10,
                        "offset": 2,
                        "total": 1,
                    },
                },
            ),
            httpx.Response(
                200,
                json={
                    "name": "a.txt",
                    "path": "trash:/a.txt",
                    "origin_path": "disk:/Work/a.txt",
                    "type": "file",
                },
            ),
            httpx.Response(201),
        ]
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        response = next(responses)
        response.request = request
        return response

    client = YandexDiskClient(
        client=httpx.AsyncClient(
            base_url="https://cloud-api.yandex.net/v1/disk",
            transport=httpx.MockTransport(handler),
        )
    )
    page = await client.list_trash(limit=10, offset=2, sort="-deleted")
    item = await client.get_trash_resource("/a.txt")
    restored = await client.restore_from_trash(
        "/a.txt", destination_path="/Work/restored.txt", overwrite=True
    )
    with pytest.raises(PermissionDenied):
        await client.empty_trash()

    assert page.items[0].origin_path == "/Work/a.txt"
    assert item.origin_path == "/Work/a.txt"
    assert restored.status == "completed"
    assert [(request.method, request.url.path) for request in requests] == [
        ("GET", "/v1/disk/trash/resources"),
        ("GET", "/v1/disk/trash/resources"),
        ("PUT", "/v1/disk/trash/resources/restore"),
    ]
    assert dict(requests[2].url.params) == {
        "path": "/a.txt",
        "dst_path": "/Work/restored.txt",
        "overwrite": "true",
    }
    await client.close()
