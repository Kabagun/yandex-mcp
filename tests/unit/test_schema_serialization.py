import pytest

from yandex_workspace_mcp.models.base import PublicModel, WireModel
from yandex_workspace_mcp.models.disk import DiskResource, DiskResourcePage
from yandex_workspace_mcp.models.mail import MailMessage


@pytest.mark.parametrize("model", [DiskResource, DiskResourcePage, MailMessage])
def test_public_object_schema_adds_only_explicit_root_type(model: type[PublicModel]) -> None:
    original = super(PublicModel, model).model_json_schema()
    normalized = model.model_json_schema()
    assert normalized["type"] == "object"
    assert normalized == original | {"type": "object"}
    assert model.model_json_schema(by_alias=True, mode="serialization")["type"] == "object"


def test_recursive_public_schema_preserves_refs_definitions_and_constraints() -> None:
    schema = DiskResourcePage.model_json_schema()
    assert schema["$ref"] == "#/$defs/DiskResourcePage"
    assert schema["$defs"]["DiskResourcePage"]["properties"]["items"]["items"] == {
        "$ref": "#/$defs/DiskResource"
    }
    assert schema["$defs"]["DiskResource"]["additionalProperties"] is False
    assert "name" in schema["$defs"]["DiskResource"]["required"]


def test_internal_wire_schema_generation_is_unmodified() -> None:
    assert "model_json_schema" not in WireModel.__dict__
    assert WireModel.model_json_schema()["type"] == "object"
