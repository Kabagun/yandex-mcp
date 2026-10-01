"""ChatGPT's authenticated account profile contract."""

from typing import Any

from pydantic import Field
from pydantic.json_schema import SkipJsonSchema

from .base import PublicModel


def _omit_default(schema: dict[str, Any]) -> None:
    schema.pop("default", None)


class AccountProfile(PublicModel):
    """An immutable account ID and optional current Yandex display metadata."""

    id: str = Field(min_length=1, pattern=r"\S")
    name: str | SkipJsonSchema[None] = Field(default=None, json_schema_extra=_omit_default)
    email: str | SkipJsonSchema[None] = Field(default=None, json_schema_extra=_omit_default)
    nickname: str | SkipJsonSchema[None] = Field(default=None, json_schema_extra=_omit_default)
