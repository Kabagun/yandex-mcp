# Yandex MCP: Disk and Mail

Fork of [Yandex Workspace MCP](https://github.com/denis-samatov/yandex-workspace-mcp) by Denis Samatov, under the original MIT license.

[![CI](https://github.com/Kabagun/yandex-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Kabagun/yandex-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Python](https://img.shields.io/badge/python-3.12%2B-blue.svg)

One Python codebase serving two isolated multi-user MCP connections: **Yandex Disk** and **Yandex Mail**. Each connection has its own OAuth application, issuer, keys and token namespace. The upstream Workspace/Wiki mode remains available for compatibility; Wiki is disabled in both dedicated profiles.

Start with the [Disk and Mail profile setup](docs/profiles.md), including the exact Yandex OAuth fields, permission gates and mail tool contract.

Multi-user connections expose an authenticated `get_profile` tool so ChatGPT can
identify the connected Yandex account by its real login and, when permitted,
email. Its profile ID stays the same across reconnections and token refreshes.

## Start here

- **Review the engineering:** run the [credential-free permission demo](examples/permission_demo.py) and inspect [permission regression tests](tests/security/test_permission_gating.py).
- **Connect a client:** follow the [minimal read-only quick start](docs/quickstart.md), then the client configuration below.
- **Deploy:** read [authentication](docs/authentication.md), [deployment](docs/deployment.md), and [security](SECURITY.md).

The offline example uses a mocked upstream client. It demonstrates local authorization behavior; it does not validate Yandex availability, live API parity, load capacity, or a particular deployment. The opt-in contract sweep below checks a different, live integration boundary.

## Features

- **Yandex Disk Integration**: 21 parity tools plus `disk_read` and inline `disk_upload` cover capacity, list/recent/search, metadata, signed links, uploads, mutations, public resources, Trash, and bounded local jobs.
- **Yandex Mail Integration**: native TLS IMAP/SMTP XOAUTH2 for folders, bounded search/list/read, attachments, sending, replies, forwarding, read flags and moving to Trash. No account-wide purge or automatic send retry.
- **Yandex Wiki Integration**: 27 typed tools plus the `wiki_get_tree` compatibility alias cover search, page reads/writes, comments, resources, recovery, attachments, and dynamic tables.
- **Unified Workspace Search**: A single `search` tool allows agents to query both Disk and Wiki simultaneously.
- **Security-First Architecture**:
  - Read-only by default.
  - Granular permissions for read, write, and delete operations.
  - Path allowlisting (`ALLOWED_ROOTS`) to strictly confine AI operations.
  - Detailed, structured audit logging of all write/destructive operations.

## Installation

```bash
git clone https://github.com/Kabagun/yandex-mcp.git
cd yandex-mcp
uv sync
```

## Configuration

Copy `.env.example` to `.env` and fill in the values:

```env
# OAuth token generated from Yandex OAuth portal
YANDEX_OAUTH_TOKEN=your_oauth_token

# Your Organization ID (required if Wiki is enabled and you are under an org)
YANDEX_WIKI_ORG_ID=your_org_id

# Toggle services
YANDEX_DISK_ENABLED=true
YANDEX_WIKI_ENABLED=true

# Transport (stdio or streamable-http)
MCP_TRANSPORT=stdio

# For streamable-http
# MCP_TRANSPORT=streamable-http
# MCP_HOST=127.0.0.1
# MCP_PORT=8000
# MCP_AUTH_TOKEN=your_secure_bearer_token  # Required for auth on streamable endpoints
# MCP_AUTH_MODE=static
# MCP_STATIC_SCOPES=workspace:read
# MCP_ISSUER_URL=http://localhost:8000
# MCP_RESOURCE_SERVER_URL=http://localhost:8000
# Required for restart-stable cursors in remote mode. Comma-separated
# base64url secrets, each decoding to at least 32 bytes; first signs, all verify.
# MCP_CURSOR_KEYS=base64url-current-key,base64url-previous-key
# Exact public values; wildcards are rejected.
# MCP_ALLOWED_HOSTS=mcp.example.com
# MCP_ALLOWED_ORIGINS=https://app.example.com

# Disk Permissions
DISK_READ=true
DISK_WRITE=false
DISK_DELETE=false
DISK_ALLOWED_ROOTS=/Work,/Research
# Trusted stdio only. Enables local upload plus background job tools.
DISK_UPLOAD_ALLOWED_DIRS=/Users/me/disk-uploads
# Maximum descriptor-based/inline upload size in bytes (default: 104857600).
DISK_MAX_UPLOAD_BYTES=104857600
# Enables server-side URL import only for these exact HTTPS hosts.
DISK_UPLOAD_URL_ALLOWED_HOSTS=downloads.example.com
# Enables public-resource lookup only for these exact keys or normalized URLs.
DISK_ALLOWED_PUBLIC_KEYS=public-key,https://disk.yandex.ru/d/example
# Legacy setting: must remain false; account-wide Trash purge is prohibited.
DISK_ALLOW_GLOBAL_DESTRUCTIVE=false
# Bounded in-process trusted-local job store.
DISK_UPLOAD_JOB_CAPACITY=100
DISK_UPLOAD_JOB_TTL_SECONDS=3600

# Wiki Permissions
WIKI_READ=true
WIKI_WRITE=false
WIKI_DELETE=false
WIKI_ALLOWED_ROOTS=projects,research
# Trusted stdio only: comma-separated local roots for attachment upload.
# The tool is absent when this is empty or the transport is remote.
WIKI_UPLOAD_ALLOWED_DIRS=/Users/me/wiki-attachments
# Maximum local attachment size in bytes (default: 104857600).
WIKI_MAX_ATTACHMENT_BYTES=104857600

# Required when streamable-http and Wiki delete/recovery are enabled.
# Ordered base64url keys (>=32 decoded bytes): first encrypts, all decrypt.
MCP_TOKEN_ENCRYPTION_KEYS=base64url-current-key,base64url-previous-key
```

HTTP deployments have three explicit modes: loopback development, static single-tenant bearer, and multi-user Yandex OAuth backed by encrypted memory/Redis state. CLI transport overrides are validated before server construction, authenticated HTTP requests fail closed without an SDK auth context, and MCP access tokens must be distinct from Yandex credentials. See [authentication](docs/authentication.md) and [deployment](docs/deployment.md) for IAM headers, scopes, PKCE, callback registration, key rotation, TLS/proxy rules, and Compose profiles.

### Wiki tools and permission gates

`WIKI_READ` publishes eight reference reads plus `wiki_get_tree`. `WIKI_WRITE` adds page append/clone/comment operations and the grid create/update/copy/row/cell/column mutations. `WIKI_DELETE` adds page/grid/row/column deletion and page recovery. Local attachment upload additionally requires `stdio` and a non-empty `WIKI_UPLOAD_ALLOWED_DIRS`; it is never registered for remote transports.

Every locator and grid owner is resolved and checked against `WIKI_ALLOWED_ROOTS` before data is returned or changed. Grid mutations require the caller-provided revision, are serialized per grid within one process, and conflicts are surfaced without automatic replay. Page clone and grid copy accept only validated exact-origin operation URLs; those URLs are not returned to MCP clients.

Page deletion returns a random MCP recovery handle rather than Yandex's token. Handles expire after 15 minutes, are principal-bound and single-use, and the upstream token is encrypted at rest. Multi-user replicas store handles in the same Redis backend as OAuth state, so another replica can consume them after a restart; local/static deployments use process-local handles. Remote delete/recovery requires `MCP_TOKEN_ENCRYPTION_KEYS`.

### Disk tools and permission gates

`DISK_READ` exposes `disk_info`, list/recent/search/metadata/download, `disk_list_trash`, and the bounded-text `disk_read` compatibility tool. `disk_get_public_resource` is additionally registered only when `DISK_ALLOWED_PUBLIC_KEYS` is non-empty. Every direct path is checked before the HTTP call; recent, search, embedded children, and Trash results are post-filtered before output.

`DISK_WRITE` exposes inline upload, folder/copy/move/rename, publish/unpublish, and—when `DISK_UPLOAD_URL_ALLOWED_HOSTS` is non-empty—URL import. Local-file upload and its four local job tools require `stdio` plus `DISK_UPLOAD_ALLOWED_DIRS`; they are absent remotely. Jobs are in-memory, bounded, expire, never return source paths or credentials, and are cancelled during shutdown.

`DISK_DELETE` exposes resource deletion and Trash restore. Permanent deletion of a configured root is refused. Account-wide Trash purge is prohibited: there is no `disk_empty_trash` tool, the service rejects legacy purge calls, and `DISK_ALLOW_GLOBAL_DESTRUCTIVE=true` is rejected at startup.

### Search contract and API drift

The canonical `search` tool queries Wiki and Disk concurrently, returns Wiki-first round-robin results, reports partial source failures, and uses a signed composite cursor. Standalone `disk_search` cursors and canonical workspace cursors are distinct and bound to the normalized query and caller. Invalid or stale cursors fail closed.

Wiki full-text search uses `POST /v1/search`. The endpoint is tracked as `YANDEX_API_DOCS_WIRE_DRIFT` because documented and observed Yandex fields can change independently. If the search endpoint is unavailable or its successful response no longer matches the typed contract, the server uses a bounded descendants fallback. Fallback results are explicitly marked `degraded=true` and `search_mode="descendants"`; authentication, permission, rate-limit, transport, validation, and normal empty-result cases never trigger fallback.

Every Wiki/Disk result is post-filtered against configured roots even when an upstream filter was sent. An enabled service with no allowed roots fails startup. Signed downloads/uploads use a separate tokenless transport: HTTPS/Yandex suffix, all DNS answers, the connected peer, redirects, and byte caps are checked without forwarding OAuth headers.

The opt-in live drift sweep mutates only explicitly supplied scratch subtrees, refuses `/`, and always attempts cleanup:

```bash
uv run python scripts/contract_sweep.py \
  --acknowledge-live \
  --wiki-scratch-root team/mcp-contract-sweep \
  --disk-scratch-root /mcp-contract-sweep
```

### OAuth Setup
1. Go to [Yandex OAuth portal](https://oauth.yandex.com/).
2. Create a new client application.
3. Grant permissions for "Yandex.Disk REST API" (`cloud_api:disk.read`, `cloud_api:disk.write`, `cloud_api:disk.info`) and "Yandex Wiki" (`wiki:read`, `wiki:write`).
4. Generate and save the OAuth token to your `.env` file.

For multi-user mode, register the exact HTTPS `MCP_OAUTH_CALLBACK_URL` instead of generating a global token, then set `YANDEX_OAUTH_CLIENT_ID`, `YANDEX_OAUTH_CLIENT_SECRET`, both auth modes to `multi-user`, Redis, and independent cursor/encryption key rings.

## Running

Run via the provided CLI:

```bash
uv run yandex-workspace-mcp
```

To run diagnostics and verify configuration:

```bash
uv run yandex-workspace-mcp doctor
```

## Client Configuration (Claude Desktop / Cursor)

Add the following to your MCP client's configuration file:

```json
{
  "mcpServers": {
    "yandex-workspace": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/yandex-workspace-mcp",
        "run",
        "yandex-workspace-mcp"
      ],
      "env": {
        "YANDEX_OAUTH_TOKEN": "YOUR_TOKEN",
        "YANDEX_WIKI_ORG_ID": "YOUR_ORG_ID"
      }
    }
  }
}
```
