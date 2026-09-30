from typing import Annotated, Protocol
from uuid import UUID

from mcp.server import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from ..auth.scopes import OperationClass, WorkspacePrincipal, WorkspaceScope, require_scope
from ..config import Settings
from ..models.disk import (
    Cursor,
    DiskInfo,
    DiskLinkResponse,
    DiskOperationResponse,
    DiskPublicResource,
    DiskResource,
    DiskResourcePage,
    DiskSearchResponse,
    DiskSort,
    TrashSort,
    UploadJobListResponse,
    UploadJobResponse,
    UploadJobStatus,
)
from ..services.disk import DiskService


class DiskApplication(Protocol):
    @property
    def principal(self) -> WorkspacePrincipal: ...

    def require_disk_service(self) -> DiskService: ...


READ_ANNOTATIONS = ToolAnnotations(
    read_only_hint=True,
    destructive_hint=False,
    idempotent_hint=True,
    open_world_hint=False,
)
WRITE_ANNOTATIONS = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=False,
    idempotent_hint=False,
    open_world_hint=False,
)
DESTRUCTIVE_ANNOTATIONS = ToolAnnotations(
    read_only_hint=False,
    destructive_hint=True,
    idempotent_hint=False,
    open_world_hint=False,
)


def _scope_meta(scope: WorkspaceScope) -> dict[str, list[str]]:
    return {"required_scopes": [scope.value]}


def register_disk_tools(mcp: MCPServer, application: DiskApplication, settings: Settings) -> None:
    if not settings.yandex_disk_enabled:
        return
    if settings.disk_read:

        @mcp.tool(
            name="disk_info",
            description="Get Yandex Disk capacity information",
            annotations=READ_ANNOTATIONS,
            meta=_scope_meta(WorkspaceScope.READ),
        )
        async def disk_info() -> DiskInfo:
            require_scope(application.principal, OperationClass.READ)
            return await application.require_disk_service().info()

        @mcp.tool(
            name="disk_list",
            description="List contents of an allowlisted Yandex Disk folder",
            annotations=READ_ANNOTATIONS,
            meta=_scope_meta(WorkspaceScope.READ),
        )
        async def disk_list(
            path: str = "/",
            limit: Annotated[int, Field(ge=1, le=100)] = 100,
            offset: Annotated[int, Field(ge=0, le=10_000)] = 0,
            sort: DiskSort = "name",
        ) -> DiskResourcePage:
            require_scope(application.principal, OperationClass.READ)
            return await application.require_disk_service().list_page(path, limit, offset, sort)

        @mcp.tool(
            name="disk_recent",
            description="List recently uploaded files under allowed roots",
            annotations=READ_ANNOTATIONS,
            meta=_scope_meta(WorkspaceScope.READ),
        )
        async def disk_recent(
            limit: Annotated[int, Field(ge=1, le=100)] = 100,
            media_type: Annotated[str, Field(min_length=1, max_length=64)] | None = None,
        ) -> DiskResourcePage:
            require_scope(application.principal, OperationClass.READ)
            return await application.require_disk_service().recent(
                limit=limit,
                media_type=media_type,
            )

        @mcp.tool(
            name="disk_search",
            description="Search file names under allowed Yandex Disk roots",
            annotations=READ_ANNOTATIONS,
            meta=_scope_meta(WorkspaceScope.READ),
        )
        async def disk_search(
            query: Annotated[str, Field(min_length=1, max_length=1000)],
            limit: Annotated[int, Field(ge=1, le=100)] = 50,
            cursor: Cursor | None = None,
            media_type: Annotated[str, Field(min_length=1, max_length=64)] | None = None,
        ) -> DiskSearchResponse:
            require_scope(application.principal, OperationClass.READ)
            return await application.require_disk_service().search(
                query,
                limit,
                cursor=cursor,
                principal=application.principal.principal_id,
                media_type=media_type,
            )

        @mcp.tool(
            name="disk_get_metadata",
            description="Get metadata for an allowlisted Yandex Disk resource",
            annotations=READ_ANNOTATIONS,
            meta=_scope_meta(WorkspaceScope.READ),
        )
        async def disk_get_metadata(path: str) -> DiskResource:
            require_scope(application.principal, OperationClass.READ)
            return await application.require_disk_service().get_metadata(path)

        @mcp.tool(
            name="disk_get_download_url",
            description="Get a guarded temporary download URL for a Disk file",
            annotations=READ_ANNOTATIONS,
            meta=_scope_meta(WorkspaceScope.READ),
        )
        async def disk_get_download_url(path: str) -> DiskLinkResponse:
            require_scope(application.principal, OperationClass.READ)
            return await application.require_disk_service().get_download_url(path)

        @mcp.tool(
            name="disk_read",
            description="Read bounded text content from an allowlisted Disk file",
            annotations=READ_ANNOTATIONS,
            meta=_scope_meta(WorkspaceScope.READ),
        )
        async def disk_read(path: str) -> str:
            require_scope(application.principal, OperationClass.READ)
            return await application.require_disk_service().read_file(path)

        @mcp.tool(
            name="disk_list_trash",
            description="List Trash entries whose original paths are allowlisted",
            annotations=READ_ANNOTATIONS,
            meta=_scope_meta(WorkspaceScope.READ),
        )
        async def disk_list_trash(
            limit: Annotated[int, Field(ge=1, le=100)] = 100,
            offset: Annotated[int, Field(ge=0, le=10_000)] = 0,
            sort: TrashSort = "name",
        ) -> DiskResourcePage:
            require_scope(application.principal, OperationClass.READ)
            return await application.require_disk_service().list_trash(
                limit=limit,
                offset=offset,
                sort=sort,
            )

        if settings.disk_allowed_public_keys:

            @mcp.tool(
                name="disk_get_public_resource",
                description="Get one explicitly allowlisted public Disk resource",
                annotations=READ_ANNOTATIONS,
                meta=_scope_meta(WorkspaceScope.READ),
            )
            async def disk_get_public_resource(
                public_key: Annotated[str, Field(min_length=1, max_length=4096)] | None = None,
                public_url: Annotated[str, Field(min_length=1, max_length=4096)] | None = None,
                path: Annotated[str, Field(min_length=1, max_length=4096)] | None = None,
                limit: Annotated[int, Field(ge=1, le=100)] = 100,
                offset: Annotated[int, Field(ge=0, le=10_000)] = 0,
            ) -> DiskPublicResource:
                require_scope(application.principal, OperationClass.READ)
                return await application.require_disk_service().get_public_resource(
                    public_key=public_key,
                    public_url=public_url,
                    path=path,
                    limit=limit,
                    offset=offset,
                )

    if settings.disk_write:

        @mcp.tool(
            name="disk_upload",
            description="Upload bounded inline UTF-8 text to Yandex Disk",
            annotations=WRITE_ANNOTATIONS,
            meta=_scope_meta(WorkspaceScope.WRITE),
        )
        async def disk_upload(
            path: str,
            content: str,
            overwrite: bool = True,
        ) -> DiskOperationResponse:
            require_scope(application.principal, OperationClass.WRITE)
            return await application.require_disk_service().upload(
                path,
                content,
                overwrite=overwrite,
            )

        @mcp.tool(
            name="disk_create_folder",
            description="Create an allowlisted Yandex Disk folder",
            annotations=WRITE_ANNOTATIONS,
            meta=_scope_meta(WorkspaceScope.WRITE),
        )
        async def disk_create_folder(path: str) -> DiskOperationResponse:
            require_scope(application.principal, OperationClass.WRITE)
            return await application.require_disk_service().create_folder(path)

        @mcp.tool(
            name="disk_copy",
            description="Copy a Disk resource between allowlisted paths",
            annotations=WRITE_ANNOTATIONS,
            meta=_scope_meta(WorkspaceScope.WRITE),
        )
        async def disk_copy(
            from_path: str,
            to_path: str,
            overwrite: bool = False,
        ) -> DiskOperationResponse:
            require_scope(application.principal, OperationClass.WRITE)
            return await application.require_disk_service().copy(
                from_path,
                to_path,
                overwrite=overwrite,
            )

        @mcp.tool(
            name="disk_move",
            description="Move a Disk resource between allowlisted paths",
            annotations=WRITE_ANNOTATIONS,
            meta=_scope_meta(WorkspaceScope.WRITE),
        )
        async def disk_move(
            from_path: str,
            to_path: str,
            overwrite: bool = False,
        ) -> DiskOperationResponse:
            require_scope(application.principal, OperationClass.WRITE)
            return await application.require_disk_service().move(
                from_path,
                to_path,
                overwrite=overwrite,
            )

        @mcp.tool(
            name="disk_rename",
            description="Rename an allowlisted Disk resource",
            annotations=WRITE_ANNOTATIONS,
            meta=_scope_meta(WorkspaceScope.WRITE),
        )
        async def disk_rename(
            path: str,
            new_name: Annotated[str, Field(min_length=1, max_length=255)],
            overwrite: bool = False,
        ) -> DiskOperationResponse:
            require_scope(application.principal, OperationClass.WRITE)
            return await application.require_disk_service().rename(
                path,
                new_name,
                overwrite=overwrite,
            )

        @mcp.tool(
            name="disk_publish",
            description="Publish an allowlisted Disk resource",
            annotations=WRITE_ANNOTATIONS,
            meta=_scope_meta(WorkspaceScope.WRITE),
        )
        async def disk_publish(path: str) -> DiskPublicResource:
            require_scope(application.principal, OperationClass.WRITE)
            return await application.require_disk_service().publish(path)

        @mcp.tool(
            name="disk_unpublish",
            description="Remove public access from an allowlisted Disk resource",
            annotations=WRITE_ANNOTATIONS,
            meta=_scope_meta(WorkspaceScope.WRITE),
        )
        async def disk_unpublish(path: str) -> DiskOperationResponse:
            require_scope(application.principal, OperationClass.WRITE)
            return await application.require_disk_service().unpublish(path)

        if settings.disk_upload_url_allowed_hosts:

            @mcp.tool(
                name="disk_upload_from_url",
                description="Ask Yandex Disk to fetch from an explicitly allowlisted HTTPS host",
                annotations=WRITE_ANNOTATIONS,
                meta=_scope_meta(WorkspaceScope.WRITE),
            )
            async def disk_upload_from_url(
                url: Annotated[str, Field(min_length=1, max_length=4096)],
                destination_path: str,
                overwrite: bool = False,
            ) -> DiskOperationResponse:
                require_scope(application.principal, OperationClass.WRITE)
                return await application.require_disk_service().upload_from_url(
                    url,
                    destination_path,
                    overwrite=overwrite,
                )

        if settings.mcp_transport == "stdio" and settings.disk_upload_allowed_dirs:

            @mcp.tool(
                name="disk_upload_local_file",
                description="Upload an allowlisted local file to Yandex Disk",
                annotations=WRITE_ANNOTATIONS,
                meta=_scope_meta(WorkspaceScope.WRITE),
            )
            async def disk_upload_local_file(
                file_path: Annotated[str, Field(min_length=1, max_length=4096)],
                destination_path: str,
                overwrite: bool = False,
            ) -> DiskOperationResponse:
                require_scope(application.principal, OperationClass.WRITE)
                return await application.require_disk_service().upload_local_file(
                    file_path,
                    destination_path,
                    overwrite=overwrite,
                )

            @mcp.tool(
                name="disk_upload_local_file_background",
                description="Start a bounded local Disk upload job",
                annotations=WRITE_ANNOTATIONS,
                meta=_scope_meta(WorkspaceScope.WRITE),
            )
            async def disk_upload_local_file_background(
                file_path: Annotated[str, Field(min_length=1, max_length=4096)],
                destination_path: str,
                overwrite: bool = False,
            ) -> UploadJobResponse:
                require_scope(application.principal, OperationClass.WRITE)
                return await application.require_disk_service().upload_local_file_background(
                    file_path,
                    destination_path,
                    overwrite=overwrite,
                )

            @mcp.tool(
                name="disk_get_upload_status",
                description="Get one local Disk upload job",
                annotations=READ_ANNOTATIONS,
                meta=_scope_meta(WorkspaceScope.WRITE),
            )
            async def disk_get_upload_status(job_id: UUID) -> UploadJobResponse:
                require_scope(application.principal, OperationClass.WRITE)
                return await application.require_disk_service().get_upload_status(job_id)

            @mcp.tool(
                name="disk_list_upload_jobs",
                description="List bounded local Disk upload jobs",
                annotations=READ_ANNOTATIONS,
                meta=_scope_meta(WorkspaceScope.WRITE),
            )
            async def disk_list_upload_jobs(
                limit: Annotated[int, Field(ge=1, le=100)] = 50,
                cursor: Cursor | None = None,
                status: UploadJobStatus | None = None,
            ) -> UploadJobListResponse:
                require_scope(application.principal, OperationClass.WRITE)
                return await application.require_disk_service().list_upload_jobs(
                    limit=limit,
                    cursor=cursor,
                    status=status,
                    principal=application.principal.principal_id,
                )

    if settings.disk_delete:

        @mcp.tool(
            name="disk_delete",
            description="Delete an allowlisted Disk resource",
            annotations=DESTRUCTIVE_ANNOTATIONS,
            meta=_scope_meta(WorkspaceScope.DELETE),
        )
        async def disk_delete(path: str, permanently: bool = False) -> DiskOperationResponse:
            require_scope(application.principal, OperationClass.DELETE)
            return await application.require_disk_service().delete(path, permanently=permanently)

        @mcp.tool(
            name="disk_restore_from_trash",
            description="Restore a Trash resource to an allowlisted destination",
            annotations=WRITE_ANNOTATIONS,
            meta=_scope_meta(WorkspaceScope.DELETE),
        )
        async def disk_restore_from_trash(
            trash_path: str,
            destination_path: str | None = None,
            overwrite: bool = False,
        ) -> DiskOperationResponse:
            require_scope(application.principal, OperationClass.DELETE)
            return await application.require_disk_service().restore_from_trash(
                trash_path,
                destination_path=destination_path,
                overwrite=overwrite,
            )
