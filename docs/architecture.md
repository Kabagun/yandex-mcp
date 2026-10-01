# Architecture

## Overview
`yandex-workspace-mcp` connects MCP clients (such as Codex, Claude, Cursor) to Yandex Disk and Yandex Wiki using their official REST APIs.

## Components
1. **MCP Transport & Server (`mcp.server.MCPServer`)**: `create_application(settings, dependencies)` builds an isolated registry and typed application state. Network clients open only inside MCP lifespan and close once in reverse order. Importing `server` creates no client, task, store, or credential-bearing object.
2. **Services (`DiskService`, `WikiService`, `WorkspaceService`)**: Houses the core business logic, including the unified `search` logic. Implements access control and auditing.
3. **Clients (`YandexDiskClient`, `YandexWikiClient`)**: Raw HTTP adapters built on `httpx.AsyncClient` that implement exponential backoff and error translation.
4. **Security (`paths`, `urls`, `local_files`, `permissions`, `audit`)**: Responsible for canonical roots, exact-origin operation polling, signed-transfer DNS/peer checks, descriptor-safe local files, scopes, and safe JSON audit logs.
5. **Models**: Pydantic models for data validation and schema definitions.
6. **Upload jobs (`jobs/uploads.py`)**: Application-owned, bounded trusted-local state with atomic terminal transitions, TTL/eviction, descriptor ownership, and shutdown cancellation.
7. **Authentication (`auth/oauth.py`, `auth/stores.py`)**: Keeps MCP OAuth state/tokens separate from encrypted per-principal Yandex credentials. Shared API clients resolve a new immutable credential at request time and have no default authorization header in multi-user mode.

Wire models tolerate additive upstream fields. Stable public MCP models explicitly map reviewed fields and forbid unknown properties, so Yandex additions cannot silently expand tool schemas.

## Key Decisions
- **REST API vs WebDAV**: Yandex Disk REST API is used because it provides JSON responses and fits well with the Python ecosystem. For searching files on Disk, we fetch a flat file list (`/v1/disk/resources/files`) and perform a client-side filter, as the REST API lacks a public `search` endpoint.
- **Wiki mutation concurrency**: Dynamic-table writes carry an explicit revision. The service serializes mutations per grid within one process, while upstream `409` conflicts are returned without replay. Page writes retain their documented merge/silent controls.
- **File Processing**: `disk_read` accepts reviewed text MIME types and streams through the shared tokenless signed client with a byte cap. Inline and descriptor-based uploads obtain one signed target and make one non-retried PUT. Local paths are never reopened after descriptor authorization.
- **ChatGPT file input**: `disk_upload_file` accepts the strict `OpenAIFile` contract and advertises `openai/fileParams`. The lifespan owns a separate `PublicFileTransferClient`, which reuses pinned TLS networking with a public HTTPS source policy; Yandex signed targets retain their Yandex-only policy. After scope and destination authorization, the service downloads bounded bytes into memory and passes them unchanged to `YandexDiskClient.upload_bytes`. No local file path, spool, conversion, or automatic transfer retry is involved.
- **Search orchestration**: Wiki `POST /v1/search` is a logical read even though its HTTP method is POST. Logical reads and GET/HEAD operations use bounded retries; mutations and signed uploads never replay after an ambiguous attempt. Canonical search runs sources concurrently, preserves per-source order, interleaves Wiki first, and reports partial failures rather than converting them to empty success.
- **Cursor ownership**: Standalone Disk and Workspace cursors are separate HMAC-authenticated envelopes. Workspace cursors embed bounded source offsets/state, not another signed cursor. Query, principal, enabled sources, and Wiki-root policy are verified before continuation.
- **Wiki authorization**: Page locators are resolved to an ID and normalized slug before root checks. Grid IDs are resolved to their owning page; copy operations authorize the source owner and destination separately.
- **Async Wiki operations**: Page clone is polled with bounded exact-origin status requests. Grid copy returns a typed pending operation identity after validating and then discarding the upstream status URL.
- **Recovery and local files**: Application lifespan owns the encrypted, principal-bound recovery store and the tokenless signed-transfer client. Local attachment paths are opened descriptor-first beneath configured roots; the client receives an already-open regular-file handle and never reopens the path.
- **Disk global/pathless controls**: Direct paths, both copy/move endpoints, effective Trash restore destinations, recent/search results, and embedded pages pass through service authorization. Public keys/URLs and remote-fetch hosts use independent exact allowlists and never expand Disk roots.
- **Disk operations**: Mutation calls and signed PUTs are one-attempt. A `202` status link is accepted only on the exact Disk API origin, polled with a 0.5-second minimum interval, 30-second deadline, and 100-poll cap, then discarded from public output.
- **Production HTTP**: The MCP SDK authorization-server provider owns dynamic registration, authorization-code/PKCE exchange, refresh rotation, and revocation. Streamable HTTP is stateless, body-bounded, Host/Origin allowlisted, and exposes a credential-free minimal `/healthz`; forwarded scheme/host values are honored only from configured proxy CIDRs.

## Native Mail boundary

The `mail` profile registers only Mail tools and passes request-local credentials
into a fresh TLS IMAP/SMTP session. `clients/mail.py` handles XOAUTH2 and MIME;
`services/mail.py` enforces configured permissions and audits mutations;
`tools/mail.py` validates the public MCP contract and requires `mail:*` rights.
Blocking socket operations run in worker threads. Redis prefixes include service
profile and issuer; account-specific UID references additionally bind to folder
UIDVALIDITY. See [profiles](profiles.md) for capabilities and limits.
