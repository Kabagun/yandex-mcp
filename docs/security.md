# Security Model

The security model of `yandex-workspace-mcp` is designed to prevent data exfiltration, accidental deletion, and unauthorized access outside of defined scopes.

## 1. Default Deny & Read-Only
By default, the server operates in a strict read-only mode (`DISK_WRITE=false`, `WIKI_WRITE=false`). Write operations must be explicitly opted into via environment variables.

## 2. Allowed Roots
Agents are sandboxed to specific directories/projects via `DISK_ALLOWED_ROOTS` and `WIKI_ALLOWED_ROOTS`.
All paths provided by the agent are:
1. Stripped of schema prefixes.
2. Normalized to resolve `.` and `..`.
3. Checked for path traversal attacks (e.g. `%2e%2e`).
4. Validated to ensure they fall under one of the configured `allowed_roots`.
Operations attempting to access paths outside the whitelist will raise a `PermissionDenied` error.

## 3. Safe Uploads/Downloads
Signed Yandex URLs are never fetched with the authenticated API client. By default, the shared tokenless transfer client accepts `yandex.net` and its subdomains plus the exact hostname `downloader.disk.yandex.ru`. Yandex documents both `downloader.disk.yandex.net` and `downloader.disk.yandex.ru` as [download and preview endpoints](https://yandex.ru/support/yandex-360/business/admin/ru/network-settings); other `yandex.ru` hosts and subdomains of the `.ru` downloader are not approved. The client requires HTTPS, rejects credentials/fragments/non-default ports/IP literals, validates every DNS answer and the connected peer, and enforces byte/time limits. Signed downloads may manually follow at most three redirects (four requests) with status 301, 302, 303, 307 or 308 and a nonempty Location. Relative locations resolve against the validated URL; every hop must pass the same URL and public-DNS checks, uses a newly pinned connection, and has its peer checked before its response is accepted or followed. Each response is closed before proceeding. Automatic redirects and client authentication are explicitly disabled for downloads, and Authorization, Cookie and Proxy-Authorization are stripped from every request. Signed upload PUTs continue to reject redirects.

`disk_upload_file` uses a separate public-file source policy because ChatGPT's file contract does not guarantee a download hostname. Before any source network request, the tool enforces `workspace:write`, `DISK_WRITE`, and the explicit destination's `DISK_ALLOWED_ROOTS`. Source downloads require public HTTPS on port 443 without userinfo, fragments or IP literals; all DNS answers must be public, the connection is pinned to a reviewed address, and its peer is checked. Redirects and proxy/environment credentials are disabled. OAuth, cookies and proxy authorization are never forwarded. Identity HTTP encoding is requested and other encodings are refused, preventing decompression expansion and preserving file bytes. Declared and actual lengths are capped by `DISK_MAX_UPLOAD_BYTES`; responses are closed on rejection or cancellation. Downloads and signed upload PUTs are not automatically retried. File IDs and capability URLs are redacted, and file names/MIME metadata do not choose a destination or a local filesystem path.

`wiki_upload_attachment` exists only for trusted `stdio` deployments with an explicit `WIKI_UPLOAD_ALLOWED_DIRS`. POSIX paths are opened component-by-component from an allowlisted directory descriptor with no-follow flags; only a size-bounded regular file is accepted, and the opened descriptor is rechecked before streaming. The default cap is 100 MiB.

Disk local uploads use the same descriptor walker and require `stdio`, `DISK_WRITE`, and `DISK_UPLOAD_ALLOWED_DIRS`. Background jobs own the open handle, hold no credential or source-path string in their public state, fetch the current credential immediately before transfer, never evict active work, and cancel/close on application shutdown.

URL import does not fetch through the MCP host. It is absent without `DISK_UPLOAD_URL_ALLOWED_HOSTS` and accepts only an exact allowlisted hostname over HTTPS; wildcards, subdomain lookalikes, credentials, fragments, non-default ports, IP literals, and localhost are rejected before Yandex receives the request. Public-resource lookup has a separate exact `DISK_ALLOWED_PUBLIC_KEYS` allowlist; denial does not reveal the supplied key or URL.

Search continuation uses a signed cursor with an 8 KiB decoded cap, bounded offsets/seen state, key rotation, and caller/query/policy binding. Remote deployments must configure `MCP_CURSOR_KEYS`; local ephemeral keys intentionally invalidate cursors on restart.

Safe reads and logical read POSTs may retry at most twice. Mutations, destructive calls, and signed upload PUTs are attempted once. Authentication headers are created from immutable per-request credentials and are never stored on the shared HTTP client.

Wiki page deletion never exposes the upstream recovery token. A random handle indexes a keyed hash; the stored token is AES-GCM encrypted, bound to the MCP principal and normalized locator, expires after 15 minutes, and is consumed atomically once. Multi-user mode keeps these records in the shared Redis backend for restart/cross-replica recovery. Unknown, expired, consumed, and cross-principal handles all return the same not-found category. Remote delete/recovery requires an ordered `MCP_TOKEN_ENCRYPTION_KEYS` key ring.

Wiki grid IDs are untrusted locators: the owning page is fetched and root-authorized before any read or mutation. Source and destination are independently checked for copies. Revision conflicts and ambiguous mutation transport failures are never automatically replayed.

Trash listing is authorized using each item's original Disk path. Restore checks both original and effective destination. Whole-Trash deletion requires delete scope, allowed root `/`, `DISK_ALLOW_GLOBAL_DESTRUCTIVE=true`, and literal `confirm=true`; the tool is otherwise not registered.

## 4. Authentication and HTTP boundary

MCP tokens and Yandex tokens are separate and configuration rejects identical values. Static MCP bearer scopes are intersected with the enabled permission ceiling. Multi-user authorization uses MCP authorization code + PKCE, a separate Yandex OAuth grant, one-time state/code records, opaque unrelated MCP tokens, atomic access/refresh rotation, and pair revocation. Downstream credentials are encrypted with AES-GCM and looked up by keyed hashes; the first configured key writes and the full ring reads. Redacting stderr logging strips bearer values, signed URL queries, recovery-token path segments, cookies, and exception text before output; HTTPX request INFO logs are disabled.

Non-loopback HTTP rejects unauthenticated mode, plaintext public issuer/resource/callback URLs, wildcard Host/Origin rules, missing persistent cursor keys, and production multi-user memory storage. DNS rebinding checks run on `/mcp`, request bodies are capped, and only a directly trusted proxy can replace scheme/Host. `/healthz` is intentionally credential-free and does not probe Yandex.

## 5. Audit Logging
Every modifying operation (`create`, `update`, `append`, `move`, `copy`, `delete`) emits a structured JSON audit log entry.
- Audit logs never contain sensitive data like OAuth tokens or raw document content.
- Destructive actions (like `permanently=True` deletions) are explicitly flagged in the log.

Audit records use a fixed twelve-field schema and a correlation ID. Tokens, headers, cookies, request/response bodies, content, public keys, signed URL queries, and raw exceptions are neither audit fields nor public error text.

Mail is isolated from Disk by process, OAuth client, issuer, keys, token namespace
and MCP scopes. Message content, addresses and credentials are excluded from
mutation audit events. Mail exposes only structured bounded operations, verified
TLS and XOAUTH2; no raw IMAP, global purge, EXPUNGE or automatic SMTP retries.
Read-only mock tests do not certify a live upstream OAuth connection.
