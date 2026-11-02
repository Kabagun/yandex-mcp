# Deployment

## Reverse-proxy static bearer

Run the `static` Compose profile behind an HTTPS reverse proxy. Keep port 8000 bound to loopback, set the public HTTPS issuer/resource URL, and allow only the proxy-facing public Host and browser Origin. If the proxy changes Host or scheme, add only its private network to `MCP_TRUSTED_PROXY_CIDRS`; forwarded headers from other peers are ignored.

```bash
docker compose --profile static up --build mcp-static
```

The unauthenticated `/healthz` response contains only `{"status":"ok"}`. `/mcp` remains bearer protected. Request bodies are capped by `MCP_MAX_REQUEST_BODY_BYTES`.

## Multi-user

Use the `multi-user` profile, durable Redis, two independent key rings, and a Yandex OAuth callback exactly matching the public callback URL. Install/run the package with `.[multi-user]` when not using the provided image.

The provided image installs the project and its `multi-user` dependencies with `uv sync --frozen` from the checked-in `uv.lock`; CI builds and executes `doctor` inside that exact image.

```bash
docker compose --profile multi-user up --build mcp-multi-user redis
```

Back up Redis consistently with the active encryption-key ring. Rotate by prepending a new key, restart all replicas, allow records encrypted by the previous key to expire or be rewritten, and only then remove the old key. Removing a key immediately invalidates records encrypted with it.

### Upgrading registrations created with the legacy client TTL

Disk and Mail use the same client migration. With the default permanent-client
policy, startup removes Redis TTLs from existing registrations, including clients
that have not connected recently. Their original IDs, secrets, redirects and
scopes remain unchanged. Access tokens still expire and refresh tokens rotate.

If registrations already expired before the upgrade, set
`MCP_LEGACY_CLIENT_AOF_PATH=/var/lib/redis/appendonlydir/appendonly.aof.1.incr.aof`
in each affected service's protected environment. Use the actual retained,
trusted incremental AOF file and keep the original encryption keys. The service
user needs read access. This is an explicit, one-time legacy migration; it is not
a fallback that accepts unknown OAuth clients.

Before serving requests, the migration reads a bounded AOF snapshot and restores
only encrypted client entries in the current Redis database and profile
namespace whose old expiry matches a retained, expired registration-source index
entry. It also follows a known `COPY` from a legacy namespace when the encrypted
value, original expiry and client-key HMAC are preserved. Atomic writes preserve
current registrations. A permanent completion
marker prevents a later restart from restoring a registration deleted after the
migration. Normal client lookup still authenticates the encrypted record and
validates its original metadata and secret. No user grants or tokens are restored.

An AOF `DEL` does not record whether deletion came from expiry or an operator, so
this option deliberately enrolls matching legacy expired registrations. Enable
it only for a trusted deployment where this recovery is intended. An unreadable,
malformed or oversized archive fails startup without marking the migration done.
Incomplete final writes are ignored. After successful migration the archive path
can be removed from the environment.

Recovery requires the historical encrypted value and its source-index evidence.
An AOF rewrite or a newer registration may have removed them. If either is gone,
the old client secret cannot be reconstructed; a new server connection must be
registered. Backups of Redis and the encryption keys remain necessary.

## Operational boundaries

- Local descriptor upload and background job tools are intentionally absent over HTTP and in multi-user mode.
- ChatGPT `disk_upload_file` is available remotely when Disk writes are enabled and the caller has `workspace:write`; `DISK_MAX_UPLOAD_BYTES` caps its source download (100 MiB default). Refresh ChatGPT's app tools to discover the file input after a server update.
- Signed Yandex download/upload URLs are fetched by the server's isolated tokenless transport, not by the MCP client.
- A passing health check does not verify Yandex credentials or live API compatibility.
- Live contract tests require dedicated scratch roots and explicit secrets. They are not part of ordinary pull-request CI.
- Do not import the module singleton in tests or embedding code. Build isolated instances with `create_application(settings, dependencies)` and enter their lifespan.

## Two service processes from one checkout

For the hosted Disk and Mail deployment use [the profile runbook](profiles.md)
and the two `.env.disk.example` / `.env.mail.example` templates. Use separate
systemd units and protected environment files; one Git checkout and dependency
environment can serve both. Register callbacks with distinct Yandex OAuth
applications before activating Mail. Publish each domain only after the matching
process passes health and OAuth discovery checks. Legacy Disk token namespaces
must be migrated with retained keys and TTLs as described in the runbook.
