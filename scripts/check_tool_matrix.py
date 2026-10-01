"""Verify exact installed-package tool counts for the supported deployment matrix."""

import asyncio
import tempfile

from pydantic import SecretStr

from yandex_workspace_mcp.config import Settings
from yandex_workspace_mcp.server import create_application

EXPECTED = [19, 20, 54, 49]


async def main() -> None:
    token = SecretStr("package-smoke-token")
    key = SecretStr("eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHg")
    base = {
        "yandex_oauth_token": token,
        "disk_allowed_roots": ["/"],
        "wiki_allowed_roots": ["/"],
    }
    read_only = Settings(**base)
    public_read = Settings(**base, disk_allowed_public_keys=["public-key"])
    temporary_root = tempfile.gettempdir()
    local_all = Settings(
        **base,
        disk_write=True,
        disk_delete=True,
        wiki_write=True,
        wiki_delete=True,
        disk_upload_allowed_dirs=[temporary_root],
        wiki_upload_allowed_dirs=[temporary_root],
        disk_upload_url_allowed_hosts=["downloads.example.test"],
        disk_allowed_public_keys=["public-key"],
    )
    remote_all = Settings(
        **{
            **local_all.model_dump(),
            "mcp_transport": "streamable-http",
            "mcp_token_encryption_keys": [key],
        }
    )
    observed = [
        len(await create_application(settings).mcp_server.list_tools())
        for settings in (read_only, public_read, local_all, remote_all)
    ]
    if observed != EXPECTED:
        raise SystemExit(f"tool matrix mismatch: expected {EXPECTED}, observed {observed}")
    print(observed)


if __name__ == "__main__":
    asyncio.run(main())
