import urllib.parse
from collections.abc import Awaitable, Callable
from typing import Any

import httpx
from pydantic import ValidationError

from ..models.disk import (
    DiskInfo,
    DiskInfoWire,
    DiskLinkResponse,
    DiskLinkWire,
    DiskOperationResponse,
    DiskPublicResource,
    DiskResource,
    DiskResourcePage,
    DiskResourcePageWire,
    DiskResourceWire,
    DiskSort,
    DiskTrashEntry,
    DiskTrashPage,
    TrashSort,
    map_disk_info,
    map_disk_public_resource,
    map_disk_resource,
    map_disk_resource_page,
    map_disk_trash_entry,
    map_disk_trash_page,
)
from ..models.errors import APIError, ContractMismatchError, InvalidInput, PermissionDenied
from ..policies.local_files import AllowedLocalFile
from ..policies.urls import poll_operation, validate_disk_operation_url
from .base import BaseYandexClient, RequestCredentials, RequestSemantics
from .signed import SignedTransferClient, validate_signed_url


def validate_yandex_signed_url(url: str) -> None:
    """Compatibility wrapper around the shared signed-link policy."""

    try:
        validate_signed_url(url, allowed_suffixes=("yandex.net",))
    except InvalidInput as exc:
        if not isinstance(url, str) or not url.startswith("https://"):
            raise APIError("Signed URL must use HTTPS") from exc
        raise APIError("Invalid download URL domain returned by Yandex") from exc


class YandexDiskClient(BaseYandexClient):
    def __init__(
        self,
        token: str | None = None,
        *,
        client: httpx.AsyncClient | None = None,
        signed_url_client: httpx.AsyncClient | None = None,
        credential_provider: Callable[[], Awaitable[RequestCredentials]] | None = None,
    ):
        super().__init__(
            token,
            base_url="https://cloud-api.yandex.net/v1/disk",
            client=client,
            credential_provider=credential_provider,
        )
        self._compat_signed_transfer = (
            SignedTransferClient(client=signed_url_client)
            if signed_url_client is not None
            else None
        )

    async def close(self):
        await super().close()
        if self._compat_signed_transfer is not None:
            await self._compat_signed_transfer.close()

    async def list_files(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        media_type: str | None = None,
        credentials: RequestCredentials | None = None,
    ) -> DiskResourcePage:
        params: dict[str, str | int] = {"limit": limit, "offset": offset}
        if media_type:
            params["media_type"] = media_type
        response = await self._request(
            "GET",
            "/resources/files",
            semantics=RequestSemantics.SAFE_READ,
            credentials=credentials,
            params=params,
        )
        try:
            return map_disk_resource_page(DiskResourcePageWire.model_validate(response.json()))
        except (ValidationError, ValueError, TypeError) as exc:
            raise ContractMismatchError() from exc

    async def info(
        self,
        *,
        credentials: RequestCredentials | None = None,
    ) -> DiskInfo:
        response = await self._request(
            "GET",
            self.base_url,
            semantics=RequestSemantics.SAFE_READ,
            credentials=credentials,
        )
        try:
            return map_disk_info(DiskInfoWire.model_validate(response.json()))
        except (ValidationError, ValueError, TypeError) as exc:
            raise ContractMismatchError() from exc

    async def list_resources(
        self,
        path: str,
        *,
        limit: int = 100,
        offset: int = 0,
        sort: DiskSort = "name",
        credentials: RequestCredentials | None = None,
    ) -> DiskResource:
        response = await self._request(
            "GET",
            "/resources",
            semantics=RequestSemantics.SAFE_READ,
            credentials=credentials,
            params={"path": path, "limit": limit, "offset": offset, "sort": sort},
        )
        try:
            return map_disk_resource(DiskResourceWire.model_validate(response.json()))
        except (ValidationError, ValueError, TypeError) as exc:
            raise ContractMismatchError() from exc

    async def recent(
        self,
        *,
        limit: int = 100,
        media_type: str | None = None,
        credentials: RequestCredentials | None = None,
    ) -> DiskResourcePage:
        params: dict[str, str | int] = {"limit": limit}
        if media_type:
            params["media_type"] = media_type
        response = await self._request(
            "GET",
            "/resources/last-uploaded",
            semantics=RequestSemantics.SAFE_READ,
            credentials=credentials,
            params=params,
        )
        try:
            return map_disk_resource_page(DiskResourcePageWire.model_validate(response.json()))
        except (ValidationError, ValueError, TypeError) as exc:
            raise ContractMismatchError() from exc

    async def get_metadata(
        self,
        path: str,
        limit: int = 50,
        offset: int = 0,
        *,
        credentials: RequestCredentials | None = None,
    ) -> DiskResource:
        response = await self._request(
            "GET",
            "/resources",
            semantics=RequestSemantics.SAFE_READ,
            credentials=credentials,
            params={"path": path, "limit": limit, "offset": offset},
        )
        try:
            return map_disk_resource(DiskResourceWire.model_validate(response.json()))
        except (ValidationError, ValueError, TypeError) as exc:
            raise ContractMismatchError() from exc

    async def get_download_link(
        self,
        path: str,
        *,
        credentials: RequestCredentials | None = None,
    ) -> DiskLinkResponse:
        response = await self._request(
            "GET",
            "/resources/download",
            semantics=RequestSemantics.SAFE_READ,
            credentials=credentials,
            params={"path": path},
        )
        try:
            wire = DiskLinkWire.model_validate(response.json())
            return DiskLinkResponse(download_url=wire.href, expires_at=wire.expires)
        except (ValidationError, ValueError, TypeError) as exc:
            raise ContractMismatchError() from exc

    async def _map_mutation_response(
        self,
        response: httpx.Response,
        *,
        path: str | None = None,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        if response.status_code != 202:
            return DiskOperationResponse(status="completed", path=path)
        try:
            payload = response.json()
            href = payload["href"]
            if not isinstance(href, str):
                raise TypeError
            validated = validate_disk_operation_url(href)
        except (KeyError, ValueError, TypeError) as exc:
            raise ContractMismatchError() from exc
        result = await poll_operation(
            self,
            validated,
            credentials=credentials,
            validator=validate_disk_operation_url,
        )
        if result.get("status") != "success":
            raise ContractMismatchError()
        operation_id = urllib.parse.urlsplit(validated).path.rstrip("/").rsplit("/", 1)[-1]
        return DiskOperationResponse(
            status="completed",
            operation_id=operation_id or None,
            path=path,
        )

    async def create_folder(
        self,
        path: str,
        *,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        response = await self._request(
            "PUT",
            "/resources",
            semantics=RequestSemantics.MUTATION,
            credentials=credentials,
            params={"path": path},
        )
        return await self._map_mutation_response(response, path=path, credentials=credentials)

    async def delete_resource(
        self,
        path: str,
        *,
        permanently: bool = False,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        response = await self._request(
            "DELETE",
            "/resources",
            semantics=RequestSemantics.MUTATION,
            credentials=credentials,
            params={"path": path, "permanently": str(permanently).lower()},
        )
        return await self._map_mutation_response(response, path=path, credentials=credentials)

    async def copy_resource(
        self,
        source_path: str,
        destination_path: str,
        *,
        overwrite: bool = False,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        response = await self._request(
            "POST",
            "/resources/copy",
            semantics=RequestSemantics.MUTATION,
            credentials=credentials,
            params={
                "from": source_path,
                "path": destination_path,
                "overwrite": str(overwrite).lower(),
            },
        )
        return await self._map_mutation_response(
            response,
            path=destination_path,
            credentials=credentials,
        )

    async def move_resource(
        self,
        source_path: str,
        destination_path: str,
        *,
        overwrite: bool = False,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        response = await self._request(
            "POST",
            "/resources/move",
            semantics=RequestSemantics.MUTATION,
            credentials=credentials,
            params={
                "from": source_path,
                "path": destination_path,
                "overwrite": str(overwrite).lower(),
            },
        )
        return await self._map_mutation_response(
            response,
            path=destination_path,
            credentials=credentials,
        )

    async def _get_upload_href(
        self,
        path: str,
        *,
        overwrite: bool,
        credentials: RequestCredentials | None = None,
    ) -> str:
        response = await self._request(
            "GET",
            "/resources/upload",
            semantics=RequestSemantics.SAFE_READ,
            credentials=credentials,
            params={"path": path, "overwrite": str(overwrite).lower()},
        )
        try:
            wire = DiskLinkWire.model_validate(response.json())
            if wire.method not in {None, "PUT"}:
                raise ContractMismatchError()
            return wire.href
        except (ValidationError, ValueError, TypeError) as exc:
            raise ContractMismatchError() from exc

    async def upload_local_file(
        self,
        path: str,
        opened: AllowedLocalFile,
        *,
        overwrite: bool = False,
        signed_client: SignedTransferClient,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        opened.verify_identity()
        href = await self._get_upload_href(
            path,
            overwrite=overwrite,
            credentials=credentials,
        )
        await signed_client.upload(href, opened)
        return DiskOperationResponse(status="completed", path=path)

    async def upload_inline_text(
        self,
        path: str,
        content: str,
        *,
        overwrite: bool = False,
        signed_client: SignedTransferClient,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        href = await self._get_upload_href(
            path,
            overwrite=overwrite,
            credentials=credentials,
        )
        await signed_client.upload_bytes(href, content.encode("utf-8"))
        return DiskOperationResponse(status="completed", path=path)

    async def upload_from_url(
        self,
        url: str,
        path: str,
        *,
        overwrite: bool = False,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        response = await self._request(
            "POST",
            "/resources/upload",
            semantics=RequestSemantics.MUTATION,
            credentials=credentials,
            params={
                "url": url,
                "path": path,
                "overwrite": str(overwrite).lower(),
            },
        )
        return await self._map_mutation_response(response, path=path, credentials=credentials)

    async def publish_resource(
        self,
        path: str,
        *,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        response = await self._request(
            "PUT",
            "/resources/publish",
            semantics=RequestSemantics.MUTATION,
            credentials=credentials,
            params={"path": path},
        )
        return await self._map_mutation_response(response, path=path, credentials=credentials)

    async def unpublish_resource(
        self,
        path: str,
        *,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        response = await self._request(
            "PUT",
            "/resources/unpublish",
            semantics=RequestSemantics.MUTATION,
            credentials=credentials,
            params={"path": path},
        )
        return await self._map_mutation_response(response, path=path, credentials=credentials)

    async def get_public_resource(
        self,
        *,
        public_key: str | None = None,
        public_url: str | None = None,
        path: str | None = None,
        limit: int = 100,
        offset: int = 0,
        credentials: RequestCredentials | None = None,
    ) -> DiskPublicResource:
        params: dict[str, str | int] = {"limit": limit, "offset": offset}
        if public_key is not None:
            params["public_key"] = public_key
        if public_url is not None:
            params["public_url"] = public_url
        if path is not None:
            params["path"] = path
        response = await self._request(
            "GET",
            "/public/resources",
            semantics=RequestSemantics.SAFE_READ,
            credentials=credentials,
            params=params,
        )
        try:
            return map_disk_public_resource(DiskResourceWire.model_validate(response.json()))
        except (ValidationError, ValueError, TypeError) as exc:
            raise ContractMismatchError() from exc

    async def list_trash(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        sort: TrashSort = "name",
        credentials: RequestCredentials | None = None,
    ) -> DiskTrashPage:
        response = await self._request(
            "GET",
            "/trash/resources",
            semantics=RequestSemantics.SAFE_READ,
            credentials=credentials,
            params={"path": "/", "limit": limit, "offset": offset, "sort": sort},
        )
        try:
            return map_disk_trash_page(DiskResourceWire.model_validate(response.json()))
        except (ValidationError, ValueError, TypeError) as exc:
            raise ContractMismatchError() from exc

    async def get_trash_resource(
        self,
        path: str,
        *,
        credentials: RequestCredentials | None = None,
    ) -> DiskTrashEntry:
        response = await self._request(
            "GET",
            "/trash/resources",
            semantics=RequestSemantics.SAFE_READ,
            credentials=credentials,
            params={"path": path, "limit": 1},
        )
        try:
            return map_disk_trash_entry(DiskResourceWire.model_validate(response.json()))
        except (ValidationError, ValueError, TypeError) as exc:
            raise ContractMismatchError() from exc

    async def restore_from_trash(
        self,
        path: str,
        *,
        destination_path: str | None = None,
        overwrite: bool = False,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        params: dict[str, str] = {
            "path": path,
            "overwrite": str(overwrite).lower(),
        }
        if destination_path is not None:
            params["dst_path"] = destination_path
        response = await self._request(
            "PUT",
            "/trash/resources/restore",
            semantics=RequestSemantics.MUTATION,
            credentials=credentials,
            params=params,
        )
        return await self._map_mutation_response(
            response,
            path=destination_path,
            credentials=credentials,
        )

    async def empty_trash(
        self,
        *,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        """Reject legacy purge calls before making any upstream request."""
        raise PermissionDenied()

    async def get_download_url(self, path: str) -> str:
        link = await self.get_download_link(path)
        return str(link.download_url)

    async def read_file_text(self, path: str) -> str:
        if self._compat_signed_transfer is None:
            raise ContractMismatchError()
        url = await self.get_download_url(path)

        from ..config import get_settings

        settings = get_settings()

        # Stream download to enforce limits
        max_bytes = settings.max_inline_text_size_kb * 1024

        content = await self._compat_signed_transfer.download(url, max_bytes=max_bytes)
        return content.decode("utf-8", errors="replace")

    async def upload_file_text(self, path: str, content: str) -> None:
        if self._compat_signed_transfer is None:
            raise ContractMismatchError()
        # 1. Get upload URL
        resp = await self._request(
            "GET", "/resources/upload", params={"path": path, "overwrite": "true"}
        )
        if resp.status_code != 200:
            raise APIError(f"Failed to get upload URL: {resp.text}")

        upload_url = resp.json().get("href")
        if not upload_url:
            raise APIError("No upload URL returned")

        await self._compat_signed_transfer.upload_bytes(upload_url, content.encode("utf-8"))

    async def search(self, query: str, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        # Yandex Disk doesn't have a content search endpoint in the standard API.
        # We can use /resources/files to fetch a flat list and filter by name.
        params = {
            "limit": limit,
            "offset": offset,
            "media_type": "document,text,data,development",  # Filter somewhat
        }
        resp = await self._request("GET", "/resources/files", params=params)
        if resp.status_code != 200:
            raise APIError(f"Disk API error {resp.status_code}: {resp.text}")

        data = resp.json()
        items = data.get("items", [])

        # Simple name filtering
        query_lower = query.lower()
        matched = [item for item in items if query_lower in item.get("name", "").lower()]

        return {"items": matched}

    async def flat_files(self, limit: int = 50, offset: int = 0) -> dict[str, Any]:
        page = await self.list_files(limit=limit, offset=offset)
        return page.model_dump(mode="json")
