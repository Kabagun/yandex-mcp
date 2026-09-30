import json
from pathlib import Path
from uuid import UUID

import pytest
from pydantic import ValidationError

from scripts.generate_schema_snapshots import DISK_MODELS
from yandex_workspace_mcp.models.disk import (
    DiskCopyInput,
    DiskInfo,
    DiskInfoWire,
    DiskListInput,
    DiskPublicResourceInput,
    DiskRenameInput,
    DiskResourceWire,
    DiskURLUploadInput,
    UploadJobIDInput,
    UploadJobListInput,
    map_disk_info,
    map_disk_resource,
)


def test_disk_list_defaults_and_strict_unknown_fields() -> None:
    assert DiskListInput().model_dump() == {
        "path": "/",
        "limit": 100,
        "offset": 0,
        "sort": "name",
    }
    with pytest.raises(ValidationError):
        DiskListInput.model_validate({"unknown": True})
    with pytest.raises(ValidationError):
        DiskListInput(limit=101)


@pytest.mark.parametrize("name", [".", "..", "a/b", r"a\b", ""])
def test_disk_rename_requires_a_basename(name: str) -> None:
    with pytest.raises(ValidationError):
        DiskRenameInput(path="/Work/old.txt", new_name=name)


def test_source_destination_inputs_are_explicit() -> None:
    value = DiskCopyInput(source_path="/Work/a", destination_path="/Work/b")
    assert value.overwrite is False
    with pytest.raises(ValidationError):
        DiskCopyInput.model_validate({"from_path": "/Work/a", "to_path": "/Work/b"})


def test_public_resource_requires_exactly_one_locator() -> None:
    assert DiskPublicResourceInput(public_key="key").public_key == "key"
    assert str(DiskPublicResourceInput(public_url="https://disk.yandex.ru/d/key").public_url)
    for payload in ({}, {"public_key": "key", "public_url": "https://disk.yandex.ru/d/key"}):
        with pytest.raises(ValidationError):
            DiskPublicResourceInput.model_validate(payload)


def test_url_upload_is_https_and_bounded() -> None:
    value = DiskURLUploadInput(
        url="https://downloads.example.test/file.bin",
        destination_path="/Work/file.bin",
    )
    assert str(value.url).startswith("https://")
    with pytest.raises(ValidationError):
        DiskURLUploadInput(url="http://downloads.example.test/file.bin", destination_path="/Work/x")


def test_upload_job_filters_are_typed() -> None:
    identifier = UUID("00000000-0000-4000-8000-000000000001")
    assert UploadJobIDInput(job_id=identifier).job_id == identifier
    assert UploadJobListInput(status="running").status == "running"
    with pytest.raises(ValidationError):
        UploadJobListInput.model_validate({"status": "unknown"})


def test_disk_wire_mapping_discards_unknown_and_signed_url_fields() -> None:
    resource = map_disk_resource(
        DiskResourceWire.model_validate(
            {
                "name": "report.txt",
                "type": "file",
                "path": "disk:/Work/report.txt",
                "file": "https://downloader.disk.yandex.net/signed?token=secret",
                "unknown": "wire-only",
            }
        )
    )
    assert resource.path == "/Work/report.txt"
    assert "file" not in resource.model_dump()
    assert "unknown" not in resource.model_dump()


def test_disk_info_mapping_is_field_by_field() -> None:
    info = map_disk_info(
        DiskInfoWire.model_validate(
            {
                "total_space": 100,
                "used_space": 25,
                "trash_size": 2,
                "max_file_size": 50,
                "paid_max_file_size": 75,
                "system_folders": {"applications": "disk:/Apps"},
                "unknown": "wire-only",
            }
        )
    )
    assert info == DiskInfo(
        total_space=100,
        used_space=25,
        trash_size=2,
        max_file_size=50,
        paid_max_file_size=75,
        system_folders={"applications": "disk:/Apps"},
    )


def test_disk_model_schema_snapshot_matches_generator() -> None:
    from yandex_workspace_mcp.models import disk

    expected = json.loads(Path("tests/snapshots/disk_tool_schemas.json").read_text())
    actual = {name: getattr(disk, name).model_json_schema() for name in DISK_MODELS}
    assert actual == expected
