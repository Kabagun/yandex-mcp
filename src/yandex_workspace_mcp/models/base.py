from typing import Any

from pydantic import BaseModel, ConfigDict


class PublicModel(BaseModel):
    """Stable MCP-facing contract."""

    model_config = ConfigDict(extra="forbid", strict=True)

    @classmethod
    def model_json_schema(cls, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Keep an object root for MCP output schemas, including recursive model references."""
        schema = super().model_json_schema(*args, **kwargs)
        # Recursive models may have only $ref/$defs at the root. MCP's object
        # output contract also requires an explicit type; retain the references
        # and every validation constraint rather than flattening the schema.
        schema.setdefault("type", "object")
        return schema


class WireModel(BaseModel):
    """Upstream contract that tolerates additive Yandex fields."""

    model_config = ConfigDict(extra="allow")
