import urllib.parse
from typing import Annotated, Any, Literal, Self
from uuid import UUID

from pydantic import Field, model_validator
from pydantic.json_schema import SkipJsonSchema

from .base import PublicModel, WireModel

Cursor = Annotated[str, Field(min_length=1, max_length=4096)]
DiskPath = Annotated[str, Field(min_length=1, max_length=4096)]
Timestamp = Annotated[str, Field(min_length=1, max_length=128)]
DiskSort = Literal["name", "-name", "created", "-created", "modified", "-modified"]
TrashSort = Literal["name", "-name", "deleted", "-deleted"]
UploadJobStatus = Literal["queued", "running", "completed", "failed", "cancelled"]


class DiskListInput(PublicModel):
    path: DiskPath = "/"
    limit: Annotated[int, Field(ge=1, le=100)] = 100
    offset: Annotated[int, Field(ge=0, le=10_000)] = 0
    sort: DiskSort = "name"


class DiskRecentInput(PublicModel):
    limit: Annotated[int, Field(ge=1, le=100)] = 100
    media_type: Annotated[str, Field(min_length=1, max_length=64)] | None = None


class DiskSearchInput(PublicModel):
    query: Annotated[str, Field(min_length=1, max_length=1000)]
    limit: Annotated[int, Field(ge=1, le=100)] = 50
    cursor: Cursor | None = None
    media_type: Annotated[str, Field(min_length=1, max_length=64)] | None = None


class DiskPathInput(PublicModel):
    path: DiskPath


class DiskDeleteInput(DiskPathInput):
    permanently: bool = False


class DiskCopyInput(PublicModel):
    source_path: DiskPath
    destination_path: DiskPath
    overwrite: bool = False


class DiskMoveInput(DiskCopyInput):
    pass


class DiskRenameInput(DiskPathInput):
    new_name: Annotated[str, Field(min_length=1, max_length=255)]

    @model_validator(mode="after")
    def validate_basename(self) -> Self:
        if self.new_name in {".", ".."} or "/" in self.new_name or "\\" in self.new_name:
            raise ValueError("new_name must be a basename")
        return self


class DiskLocalUploadInput(PublicModel):
    file_path: Annotated[str, Field(min_length=1, max_length=4096)]
    destination_path: DiskPath
    overwrite: bool = False


def _omit_file_default(schema: dict[str, Any]) -> None:
    schema.pop("default", None)


class OpenAIFile(PublicModel):
    """ChatGPT file capability; IDs and metadata never select a local or Disk path."""

    download_url: str
    file_id: str
    mime_type: str | SkipJsonSchema[None] = Field(
        default=None, json_schema_extra=_omit_file_default
    )
    file_name: str | SkipJsonSchema[None] = Field(
        default=None, json_schema_extra=_omit_file_default
    )


class DiskFileUploadInput(PublicModel):
    """Upload a ChatGPT file to an explicit, allowlisted Disk destination."""

    file: OpenAIFile
    destination_path: DiskPath
    overwrite: bool = False


class UploadJobIDInput(PublicModel):
    job_id: UUID


class UploadJobListInput(PublicModel):
    limit: Annotated[int, Field(ge=1, le=100)] = 50
    cursor: Cursor | None = None
    status: UploadJobStatus | None = None


class DiskURLUploadInput(PublicModel):
    url: Annotated[str, Field(min_length=1, max_length=4096)]
    destination_path: DiskPath
    overwrite: bool = False

    @model_validator(mode="after")
    def validate_https(self) -> Self:
        if urllib.parse.urlsplit(self.url).scheme != "https":
            raise ValueError("url must use HTTPS")
        return self


class DiskPublicResourceInput(PublicModel):
    public_key: Annotated[str, Field(min_length=1, max_length=4096)] | None = None
    public_url: Annotated[str, Field(min_length=1, max_length=4096)] | None = None
    path: Annotated[str, Field(min_length=1, max_length=4096)] | None = None
    limit: Annotated[int, Field(ge=1, le=100)] = 100
    offset: Annotated[int, Field(ge=0, le=10_000)] = 0

    @model_validator(mode="after")
    def validate_exactly_one_locator(self) -> Self:
        if (self.public_key is None) == (self.public_url is None):
            raise ValueError("exactly one public locator is required")
        if self.public_url is not None and urllib.parse.urlsplit(self.public_url).scheme != "https":
            raise ValueError("public_url must use HTTPS")
        return self


class DiskTrashListInput(PublicModel):
    limit: Annotated[int, Field(ge=1, le=100)] = 100
    offset: Annotated[int, Field(ge=0, le=10_000)] = 0
    sort: TrashSort = "name"


class DiskTrashRestoreInput(PublicModel):
    trash_path: DiskPath
    destination_path: DiskPath | None = None
    overwrite: bool = False


class DiskInfoWire(WireModel):
    total_space: int
    used_space: int
    trash_size: int
    max_file_size: int
    paid_max_file_size: int | None = None
    system_folders: dict[str, str] = Field(default_factory=dict)


class DiskResourceWire(WireModel):
    path: str | None = None
    name: str
    type: str
    size: int | None = None
    mime_type: str | None = None
    md5: str | None = None
    created: str | None = None
    modified: str | None = None
    public_url: str | None = None
    file: str | None = None
    origin_path: str | None = None
    embedded: "DiskResourcePageWire | None" = Field(default=None, alias="_embedded")


class DiskResourcePageWire(WireModel):
    items: list[DiskResourceWire] = Field(default_factory=list)
    limit: int = 100
    offset: int = 0
    total: int | None = None


class DiskOperationWire(WireModel):
    status: str | None = None
    href: str | None = None
    operation_id: str | None = None
    path: str | None = None


class DiskLinkWire(WireModel):
    href: str
    method: str | None = None
    templated: bool | None = None
    expires: str | None = None


class DiskInfo(PublicModel):
    total_space: Annotated[int, Field(ge=0)]
    used_space: Annotated[int, Field(ge=0)]
    trash_size: Annotated[int, Field(ge=0)]
    max_file_size: Annotated[int, Field(ge=0)]
    paid_max_file_size: Annotated[int, Field(ge=0)] | None = None
    system_folders: dict[str, str] = Field(default_factory=dict)


class DiskResource(PublicModel):
    path: str | None = None
    name: str
    type: Literal["file", "dir"]
    size: Annotated[int, Field(ge=0)] | None = None
    mime_type: str | None = None
    md5: str | None = None
    created_at: str | None = None
    modified_at: str | None = None
    public_url: str | None = None
    embedded: "DiskResourcePage | None" = None


class DiskPublicResource(DiskResource):
    pass


class DiskResourcePage(PublicModel):
    items: list[DiskResource] = Field(default_factory=list)
    limit: Annotated[int, Field(ge=1, le=100)] = 100
    offset: Annotated[int, Field(ge=0, le=10_000)] = 0
    total: Annotated[int, Field(ge=0)] | None = None
    next_cursor: Cursor | None = None


class DiskTrashEntry(PublicModel):
    resource: DiskResource
    origin_path: str | None = None


class DiskTrashPage(PublicModel):
    items: list[DiskTrashEntry] = Field(default_factory=list)
    limit: Annotated[int, Field(ge=1, le=100)] = 100
    offset: Annotated[int, Field(ge=0, le=10_000)] = 0
    total: Annotated[int, Field(ge=0)] | None = None


class DiskSearchResponse(PublicModel):
    items: list[DiskResource] = Field(default_factory=list)
    query: str
    next_cursor: Cursor | None = None
    truncated_by_upstream: bool = False


class DiskOperationResponse(PublicModel):
    status: Literal["completed", "pending"]
    operation_id: str | None = None
    path: str | None = None


class DiskLinkResponse(PublicModel):
    download_url: Annotated[str, Field(min_length=1, max_length=4096)]
    expires_at: str | None = None

    @model_validator(mode="after")
    def validate_https(self) -> Self:
        if urllib.parse.urlsplit(self.download_url).scheme != "https":
            raise ValueError("download_url must use HTTPS")
        return self


class UploadJobResponse(PublicModel):
    job_id: UUID
    status: UploadJobStatus
    created_at: Timestamp
    updated_at: Timestamp
    expires_at: Timestamp
    bytes_total: Annotated[int, Field(ge=0)] | None = None
    bytes_sent: Annotated[int, Field(ge=0)] = 0
    destination_path: DiskPath
    error_category: Annotated[str, Field(min_length=1, max_length=128)] | None = None


class UploadJobListResponse(PublicModel):
    jobs: list[UploadJobResponse] = Field(default_factory=list)
    next_cursor: Cursor | None = None


def _normalize_wire_path(path: str | None) -> str | None:
    if path is None:
        return None
    for prefix in ("disk:", "trash:"):
        if path.startswith(prefix):
            path = path.removeprefix(prefix)
    return path or "/"


def map_disk_info(wire: DiskInfoWire) -> DiskInfo:
    return DiskInfo(
        total_space=wire.total_space,
        used_space=wire.used_space,
        trash_size=wire.trash_size,
        max_file_size=wire.max_file_size,
        paid_max_file_size=wire.paid_max_file_size,
        system_folders=dict(wire.system_folders),
    )


def map_disk_resource_page(wire: DiskResourcePageWire) -> DiskResourcePage:
    return DiskResourcePage(
        items=[map_disk_resource(item) for item in wire.items],
        limit=wire.limit,
        offset=wire.offset,
        total=wire.total,
    )


def map_disk_resource(wire: DiskResourceWire) -> DiskResource:
    return DiskResource(
        path=_normalize_wire_path(wire.path),
        name=wire.name,
        type="dir" if wire.type == "dir" else "file",
        size=wire.size,
        mime_type=wire.mime_type,
        md5=wire.md5,
        created_at=wire.created,
        modified_at=wire.modified,
        public_url=wire.public_url,
        embedded=map_disk_resource_page(wire.embedded) if wire.embedded else None,
    )


def map_disk_public_resource(wire: DiskResourceWire) -> DiskPublicResource:
    resource = map_disk_resource(wire)
    return DiskPublicResource.model_validate(resource.model_dump())


def map_disk_trash_entry(wire: DiskResourceWire) -> DiskTrashEntry:
    return DiskTrashEntry(
        resource=map_disk_resource(wire),
        origin_path=_normalize_wire_path(wire.origin_path),
    )


def map_disk_trash_page(wire: DiskResourceWire) -> DiskTrashPage:
    if wire.embedded is None:
        raise ValueError("trash response missing embedded resources")
    return DiskTrashPage(
        items=[map_disk_trash_entry(item) for item in wire.embedded.items],
        limit=wire.embedded.limit,
        offset=wire.embedded.offset,
        total=wire.embedded.total,
    )
