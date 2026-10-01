import posixpath
import secrets
from collections.abc import Callable
from uuid import UUID

import structlog

from ..clients.base import RequestCredentials
from ..clients.disk import YandexDiskClient
from ..clients.files import PublicFileTransferClient
from ..clients.signed import SignedTransferClient
from ..jobs.uploads import UploadJobStore
from ..models.disk import (
    DiskInfo,
    DiskLinkResponse,
    DiskOperationResponse,
    DiskPublicResource,
    DiskResource,
    DiskResourcePage,
    DiskSearchResponse,
    DiskSort,
    DiskTrashPage,
    OpenAIFile,
    TrashSort,
    UploadJobListResponse,
    UploadJobResponse,
    UploadJobStatus,
)
from ..models.errors import InvalidPath, PermissionDenied
from ..policies.cursors import CursorCodec, DiskSearchCursorV1
from ..policies.local_files import AllowedLocalFile, open_allowed_local_file
from ..policies.paths import normalize_path, validate_path
from ..policies.urls import authorize_public_locator, validate_remote_upload_url
from ..security.audit import audit_logger

logger = structlog.get_logger()


class DiskService:
    def __init__(
        self,
        client: YandexDiskClient,
        allowed_roots: list[str],
        can_read: bool,
        can_write: bool,
        can_delete: bool,
        *,
        cursor_codec: CursorCodec | None = None,
        upload_allowed_dirs: list[str] | None = None,
        max_upload_bytes: int = 100 * 1024 * 1024,
        signed_client: SignedTransferClient | None = None,
        file_source_client: PublicFileTransferClient | None = None,
        upload_url_allowed_hosts: list[str] | None = None,
        allowed_public_keys: list[str] | None = None,
        allow_global_destructive: bool = False,
        upload_job_store: UploadJobStore | None = None,
        credential_provider: Callable[[], RequestCredentials | None] | None = None,
        max_inline_text_bytes: int = 512 * 1024,
    ):
        if (can_read or can_write or can_delete) and not allowed_roots:
            raise InvalidPath()
        self.client = client
        self.allowed_roots = list(dict.fromkeys(normalize_path(root) for root in allowed_roots))
        self.can_read = can_read
        self.can_write = can_write
        self.can_delete = can_delete
        self.cursor_codec = cursor_codec or CursorCodec((secrets.token_bytes(32),))
        self.upload_allowed_dirs = list(upload_allowed_dirs or [])
        self.max_upload_bytes = max_upload_bytes
        self.signed_client = signed_client
        self.file_source_client = file_source_client
        self.upload_url_allowed_hosts = list(upload_url_allowed_hosts or [])
        self.allowed_public_keys = list(allowed_public_keys or [])
        self.allow_global_destructive = allow_global_destructive
        self.upload_job_store = upload_job_store
        self.credential_provider = credential_provider or (lambda: None)
        self.max_inline_text_bytes = max_inline_text_bytes

    def authorize_disk_path(self, path: str) -> str:
        return validate_path(path, self.allowed_roots)

    def _filter_resource(self, item: DiskResource) -> DiskResource | None:
        if item.path is None:
            return None
        try:
            self.authorize_disk_path(item.path)
        except InvalidPath:
            return None
        embedded = self._filter_page(item.embedded) if item.embedded is not None else None
        return item.model_copy(update={"embedded": embedded})

    def _filter_page(self, page: DiskResourcePage) -> DiskResourcePage:
        return page.model_copy(
            update={
                "items": [
                    allowed
                    for item in page.items
                    if (allowed := self._filter_resource(item)) is not None
                ]
            }
        )

    async def info(
        self,
        *,
        credentials: RequestCredentials | None = None,
    ) -> DiskInfo:
        if not self.can_read:
            raise PermissionDenied("Disk read is disabled.")
        return await self.client.info(credentials=credentials)

    async def list_folder(
        self,
        path: str,
        limit: int = 100,
        offset: int = 0,
        sort: DiskSort = "name",
        *,
        credentials: RequestCredentials | None = None,
    ) -> DiskResource:
        if not self.can_read:
            raise PermissionDenied("Disk read is disabled.")
        valid_path = self.authorize_disk_path(path)
        logger.info("disk.list", path=valid_path)
        resource = await self.client.list_resources(
            valid_path,
            limit=limit,
            offset=offset,
            sort=sort,
            credentials=credentials,
        )
        filtered = self._filter_resource(resource)
        if filtered is None:
            raise InvalidPath()
        return filtered

    async def recent(
        self,
        *,
        limit: int = 100,
        media_type: str | None = None,
        credentials: RequestCredentials | None = None,
    ) -> DiskResourcePage:
        if not self.can_read:
            raise PermissionDenied("Disk read is disabled.")
        page = await self.client.recent(
            limit=limit,
            media_type=media_type,
            credentials=credentials,
        )
        return self._filter_page(page)

    async def list_page(
        self,
        path: str,
        limit: int = 100,
        offset: int = 0,
        sort: DiskSort = "name",
        *,
        credentials: RequestCredentials | None = None,
    ) -> DiskResourcePage:
        resource = await self.list_folder(
            path,
            limit,
            offset,
            sort,
            credentials=credentials,
        )
        if resource.embedded is not None:
            return resource.embedded
        return DiskResourcePage(items=[resource], limit=limit, offset=offset, total=1)

    async def search(
        self,
        query: str,
        limit: int = 50,
        offset: int = 0,
        *,
        cursor: str | None = None,
        principal: str = "trusted-local",
        media_type: str | None = None,
        credentials: RequestCredentials | None = None,
    ) -> DiskSearchResponse:
        if not self.can_read:
            raise PermissionDenied("Disk read is disabled.")
        logger.info("disk.search", query_length=len(query))

        seen: list[str] = []
        if cursor:
            state = self.cursor_codec.decode_disk(
                cursor,
                query=query,
                principal=principal,
            )
            current_offset = state.offset
            seen = list(state.seen)
        else:
            current_offset = offset

        seen_set = set(seen)
        matched: list[DiskResource] = []
        max_scans = 1000
        scanned = 0
        query_lower = query.casefold()
        exhausted = False

        while len(matched) < limit and scanned < max_scans:
            batch_size = min(100, max(1, limit - len(matched)))
            page = await self.client.list_files(
                limit=batch_size,
                offset=current_offset,
                media_type=media_type,
                credentials=credentials,
            )
            if not page.items:
                exhausted = True
                break
            scanned += len(page.items)
            current_offset += len(page.items)
            for item in page.items:
                if not item.path or query_lower not in item.name.casefold():
                    continue
                try:
                    valid_path = validate_path(item.path, self.allowed_roots)
                except InvalidPath:
                    continue
                identity_hash = self.cursor_codec.item_hash("disk", valid_path)
                if identity_hash in seen_set:
                    continue
                seen_set.add(identity_hash)
                seen.append(identity_hash)
                matched.append(item)
                if len(matched) >= limit:
                    break
            if len(page.items) < batch_size:
                exhausted = True
                break

        next_cursor = None
        if not exhausted and (len(matched) >= limit or scanned >= max_scans):
            next_cursor = self.cursor_codec.encode_disk(
                DiskSearchCursorV1(
                    query_hash=self.cursor_codec.query_hash(query),
                    principal_hash=self.cursor_codec.principal_hash(principal),
                    offset=current_offset,
                    seen=seen[-100:],
                )
            )
        return DiskSearchResponse(
            items=matched,
            query=query,
            next_cursor=next_cursor,
            truncated_by_upstream=scanned >= max_scans and len(matched) < limit,
        )

    async def get_metadata(
        self,
        path: str,
        *,
        credentials: RequestCredentials | None = None,
    ) -> DiskResource:
        if not self.can_read:
            raise PermissionDenied("Disk read is disabled.")
        valid_path = self.authorize_disk_path(path)
        logger.info("disk.metadata", path=valid_path)
        resource = await self.client.get_metadata(
            valid_path,
            limit=1,
            credentials=credentials,
        )
        filtered = self._filter_resource(resource)
        if filtered is None:
            raise InvalidPath()
        return filtered

    async def read_file(self, path: str) -> str:
        if not self.can_read:
            raise PermissionDenied("Disk read is disabled.")
        valid_path = self.authorize_disk_path(path)

        # Check MIME type
        meta = await self.client.get_metadata(valid_path, limit=1)
        mime = meta.mime_type or ""
        if (
            mime
            and not mime.startswith("text/")
            and "json" not in mime
            and "xml" not in mime
            and mime != "application/x-empty"
        ):
            raise PermissionDenied(f"Cannot read binary file as text: {mime}")

        if self.signed_client is None:
            raise PermissionDenied("Signed download transport is unavailable.")
        link = await self.client.get_download_link(valid_path)
        content = await self.signed_client.download(
            str(link.download_url),
            max_bytes=self.max_inline_text_bytes,
        )
        logger.info("disk.read", path=valid_path)
        return content.decode("utf-8", errors="replace")

    async def get_download_url(
        self,
        path: str,
        *,
        credentials: RequestCredentials | None = None,
    ) -> DiskLinkResponse:
        if not self.can_read:
            raise PermissionDenied("Disk read is disabled.")
        valid_path = self.authorize_disk_path(path)
        if self.signed_client is None:
            raise PermissionDenied("Signed download transport is unavailable.")
        link = await self.client.get_download_link(valid_path, credentials=credentials)
        await self.signed_client.validate(str(link.download_url))
        return link

    async def create_folder(
        self,
        path: str,
        *,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        if not self.can_write:
            raise PermissionDenied("Disk write is disabled.")
        valid_path = self.authorize_disk_path(path)
        logger.info("disk.create_folder", path=valid_path)
        try:
            result = await self.client.create_folder(valid_path, credentials=credentials)
            audit_logger.log("disk.create_folder", path=valid_path, result="success")
            return result
        except Exception as e:
            audit_logger.log("disk.create_folder", path=valid_path, result="failure", error=str(e))
            raise

    async def copy(
        self,
        from_path: str,
        to_path: str,
        *,
        overwrite: bool = False,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        if not self.can_write:
            raise PermissionDenied("Disk write is disabled.")
        valid_from = self.authorize_disk_path(from_path)
        valid_to = self.authorize_disk_path(to_path)
        logger.info("disk.copy", from_path=valid_from, to_path=valid_to)
        try:
            result = await self.client.copy_resource(
                valid_from,
                valid_to,
                overwrite=overwrite,
                credentials=credentials,
            )
            audit_logger.log("disk.copy", from_path=valid_from, to_path=valid_to, result="success")
            return result
        except Exception as e:
            audit_logger.log(
                "disk.copy", from_path=valid_from, to_path=valid_to, result="failure", error=str(e)
            )
            raise

    async def move(
        self,
        from_path: str,
        to_path: str,
        *,
        overwrite: bool = False,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        if not self.can_write:
            raise PermissionDenied("Disk write is disabled.")
        valid_from = self.authorize_disk_path(from_path)
        valid_to = self.authorize_disk_path(to_path)
        logger.info("disk.move", from_path=valid_from, to_path=valid_to)
        try:
            result = await self.client.move_resource(
                valid_from,
                valid_to,
                overwrite=overwrite,
                credentials=credentials,
            )
            audit_logger.log("disk.move", from_path=valid_from, to_path=valid_to, result="success")
            return result
        except Exception as e:
            audit_logger.log(
                "disk.move", from_path=valid_from, to_path=valid_to, result="failure", error=str(e)
            )
            raise

    async def delete(
        self,
        path: str,
        permanently: bool = False,
        *,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        if not self.can_delete:
            raise PermissionDenied("Disk delete is disabled.")
        valid_path = self.authorize_disk_path(path)
        if permanently and valid_path in self.allowed_roots:
            raise InvalidPath()
        logger.info("disk.delete", path=valid_path, permanently=permanently)
        try:
            result = await self.client.delete_resource(
                valid_path,
                permanently=permanently,
                credentials=credentials,
            )
            audit_logger.log(
                "disk.delete", path=valid_path, permanently=permanently, result="success"
            )
            return result
        except Exception as e:
            audit_logger.log(
                "disk.delete",
                path=valid_path,
                permanently=permanently,
                result="failure",
                error=str(e),
            )
            raise

    async def rename(
        self,
        path: str,
        new_name: str,
        *,
        overwrite: bool = False,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        if not self.can_write:
            raise PermissionDenied("Disk write is disabled.")
        valid_path = self.authorize_disk_path(path)
        if not new_name or new_name in {".", ".."} or "/" in new_name or "\\" in new_name:
            raise InvalidPath()
        destination = self.authorize_disk_path(
            posixpath.join(posixpath.dirname(valid_path), new_name)
        )
        return await self.client.move_resource(
            valid_path,
            destination,
            overwrite=overwrite,
            credentials=credentials,
        )

    async def upload(
        self,
        path: str,
        content: str,
        *,
        overwrite: bool = True,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        if not self.can_write:
            raise PermissionDenied("Disk write is disabled.")
        valid_path = self.authorize_disk_path(path)
        max_bytes = self.max_upload_bytes

        if len(content.encode("utf-8")) > max_bytes:
            raise PermissionDenied("Upload exceeds the configured maximum size.")
        if self.signed_client is None:
            raise PermissionDenied("Signed upload transport is unavailable.")

        logger.info("disk.upload", path=valid_path)
        try:
            result = await self.client.upload_inline_text(
                valid_path,
                content,
                overwrite=overwrite,
                signed_client=self.signed_client,
                credentials=credentials,
            )
            audit_logger.log("disk.upload", path=valid_path, size=len(content), result="success")
            return result
        except Exception as e:
            audit_logger.log(
                "disk.upload", path=valid_path, size=len(content), result="failure", error=str(e)
            )
            raise

    async def upload_file(
        self,
        file: OpenAIFile,
        destination_path: str,
        *,
        overwrite: bool = False,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        """Upload a ChatGPT file after authorizing the explicit Disk destination."""
        if not self.can_write:
            raise PermissionDenied("Disk write is disabled.")
        destination = self.authorize_disk_path(destination_path)
        if self.file_source_client is None or self.signed_client is None:
            raise PermissionDenied("File upload transport is unavailable.")
        logger.info("disk.upload_file", path=destination)
        try:
            content = await self.file_source_client.download(
                file.download_url, max_bytes=self.max_upload_bytes
            )
            result = await self.client.upload_bytes(
                destination,
                content,
                overwrite=overwrite,
                signed_client=self.signed_client,
                credentials=credentials,
            )
            audit_logger.log(
                "disk.upload_file", path=destination, size=len(content), result="success"
            )
            return result
        except Exception as exc:
            audit_logger.log("disk.upload_file", path=destination, result="failure", error=str(exc))
            raise

    async def upload_local_file(
        self,
        file_path: str,
        destination_path: str,
        *,
        overwrite: bool = False,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        if not self.can_write or not self.upload_allowed_dirs or self.signed_client is None:
            raise PermissionDenied("Local Disk upload is disabled.")
        destination = self.authorize_disk_path(destination_path)
        opened = open_allowed_local_file(
            file_path,
            self.upload_allowed_dirs,
            max_bytes=self.max_upload_bytes,
        )
        try:
            return await self.client.upload_local_file(
                destination,
                opened,
                overwrite=overwrite,
                signed_client=self.signed_client,
                credentials=credentials,
            )
        finally:
            opened.close()

    async def upload_local_file_background(
        self,
        file_path: str,
        destination_path: str,
        *,
        overwrite: bool = False,
    ) -> UploadJobResponse:
        if (
            not self.can_write
            or not self.upload_allowed_dirs
            or self.signed_client is None
            or self.upload_job_store is None
        ):
            raise PermissionDenied("Background Disk upload is disabled.")
        signed_client = self.signed_client
        job_store = self.upload_job_store
        destination = self.authorize_disk_path(destination_path)
        opened = open_allowed_local_file(
            file_path,
            self.upload_allowed_dirs,
            max_bytes=self.max_upload_bytes,
        )

        async def runner(
            opened_file: AllowedLocalFile,
            selected_destination: str,
            selected_overwrite: bool,
        ) -> None:
            await self.client.upload_local_file(
                selected_destination,
                opened_file,
                overwrite=selected_overwrite,
                signed_client=signed_client,
                credentials=self.credential_provider(),
            )

        return await job_store.submit(
            opened,
            destination_path=destination,
            overwrite=overwrite,
            runner=runner,
        )

    async def get_upload_status(self, job_id: UUID) -> UploadJobResponse:
        if self.upload_job_store is None:
            raise PermissionDenied("Background Disk upload is disabled.")
        return await self.upload_job_store.get(job_id)

    async def list_upload_jobs(
        self,
        *,
        limit: int = 50,
        cursor: str | None = None,
        status: UploadJobStatus | None = None,
        principal: str = "trusted-local",
    ) -> UploadJobListResponse:
        if self.upload_job_store is None:
            raise PermissionDenied("Background Disk upload is disabled.")
        return await self.upload_job_store.list(
            limit=limit,
            cursor=cursor,
            status=status,
            principal=principal,
        )

    async def upload_from_url(
        self,
        url: str,
        destination_path: str,
        *,
        overwrite: bool = False,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        if not self.can_write or not self.upload_url_allowed_hosts:
            raise PermissionDenied("Disk URL upload is disabled.")
        destination = self.authorize_disk_path(destination_path)
        validated_url = validate_remote_upload_url(url, self.upload_url_allowed_hosts)
        logger.info("disk.upload_from_url", destination_path=destination)
        return await self.client.upload_from_url(
            validated_url,
            destination,
            overwrite=overwrite,
            credentials=credentials,
        )

    async def publish(
        self,
        path: str,
        *,
        credentials: RequestCredentials | None = None,
    ) -> DiskPublicResource:
        if not self.can_write:
            raise PermissionDenied("Disk write is disabled.")
        valid_path = self.authorize_disk_path(path)
        await self.client.publish_resource(valid_path, credentials=credentials)
        resource = await self.client.get_metadata(valid_path, credentials=credentials)
        return DiskPublicResource.model_validate(resource.model_dump())

    async def unpublish(
        self,
        path: str,
        *,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        if not self.can_write:
            raise PermissionDenied("Disk write is disabled.")
        valid_path = self.authorize_disk_path(path)
        return await self.client.unpublish_resource(valid_path, credentials=credentials)

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
        if not self.can_read:
            raise PermissionDenied("Disk read is disabled.")
        allowed_key, allowed_url = authorize_public_locator(
            public_key=public_key,
            public_url=public_url,
            allowed_values=self.allowed_public_keys,
        )
        nested_path = normalize_path(path) if path is not None else None
        logger.info("disk.public_resource", has_nested_path=nested_path is not None)
        return await self.client.get_public_resource(
            public_key=allowed_key,
            public_url=allowed_url,
            path=nested_path,
            limit=limit,
            offset=offset,
            credentials=credentials,
        )

    async def list_trash(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        sort: TrashSort = "name",
        credentials: RequestCredentials | None = None,
    ) -> DiskResourcePage:
        if not self.can_read:
            raise PermissionDenied("Disk read is disabled.")
        page: DiskTrashPage = await self.client.list_trash(
            limit=limit,
            offset=offset,
            sort=sort,
            credentials=credentials,
        )
        allowed: list[DiskResource] = []
        for entry in page.items:
            if entry.origin_path is None:
                continue
            try:
                self.authorize_disk_path(entry.origin_path)
            except InvalidPath:
                continue
            allowed.append(entry.resource)
        return DiskResourcePage(
            items=allowed,
            limit=page.limit,
            offset=page.offset,
            total=page.total,
        )

    async def restore_from_trash(
        self,
        trash_path: str,
        *,
        destination_path: str | None = None,
        overwrite: bool = False,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        if not self.can_delete:
            raise PermissionDenied("Disk delete is disabled.")
        normalized_trash_path = normalize_path(trash_path)
        entry = await self.client.get_trash_resource(
            normalized_trash_path,
            credentials=credentials,
        )
        if entry.origin_path is None:
            raise InvalidPath()
        self.authorize_disk_path(entry.origin_path)
        effective_destination = self.authorize_disk_path(destination_path or entry.origin_path)
        return await self.client.restore_from_trash(
            normalized_trash_path,
            destination_path=effective_destination if destination_path is not None else None,
            overwrite=overwrite,
            credentials=credentials,
        )

    async def empty_trash(
        self,
        *,
        confirm: bool,
        credentials: RequestCredentials | None = None,
    ) -> DiskOperationResponse:
        """Reject account-wide purges unconditionally, including legacy callers."""
        raise InvalidPath()
