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
