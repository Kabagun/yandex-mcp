import json
from pathlib import Path

import pytest

from scripts.generate_schema_snapshots import mail_schemas


@pytest.mark.asyncio
async def test_mail_public_models_and_mcp_contract_snapshot():
    expected = json.loads(
        Path("tests/snapshots/mail_tool_schemas.json").read_text(encoding="utf-8")
    )
    assert await mail_schemas() == expected
