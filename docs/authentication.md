# Authentication

MCP client authentication and Yandex credentials are separate trust boundaries. An MCP bearer token is accepted only by this server; it is never sent to Yandex. A Yandex OAuth or IAM token is sent only to the official Disk/Wiki API, and is never accepted as an MCP bearer token.

## Modes

### Trusted local stdio

Set `MCP_AUTH_MODE=local`, `YANDEX_AUTH_MODE=oauth`, and `YANDEX_OAUTH_TOKEN`. This is the only mode that publishes server-local upload and background-job tools. The process and MCP client share one Yandex identity.

### Static single-tenant HTTP

Set `MCP_AUTH_MODE=static` and a random `MCP_AUTH_TOKEN`, independently of `YANDEX_OAUTH_TOKEN`. `MCP_STATIC_SCOPES` can narrow the token to `workspace:read`, `workspace:write`, and/or `workspace:delete`; it can never exceed the enabled Disk/Wiki permission ceiling. For IAM, use `YANDEX_AUTH_MODE=iam`, `YANDEX_IAM_TOKEN`, and the deployment-pinned `YANDEX_IAM_ORG_ID`. IAM requests use `Bearer` and `X-Cloud-Org-Id`; OAuth uses `OAuth` plus the configured Wiki organization header.

### Multi-user HTTP

Set both auth modes to `multi-user`, configure a Yandex OAuth application, and register the exact `MCP_OAUTH_CALLBACK_URL` in Yandex. MCP dynamic clients use authorization-code + PKCE. The server performs a separate Yandex grant, derives the principal from issuer, MCP client ID, and Yandex account subject, and issues unrelated opaque MCP access/refresh tokens.

Yandex tokens are AES-GCM encrypted at rest. Store keys and lookup keys are keyed hashes, state and authorization codes are single-use, and access/refresh pairs are issued and rotated atomically by the backend. Revocation removes the pair. Recovery handles use the same encrypted Redis backend in multi-user mode, remain available across replicas, and are consumed atomically with principal-bound lookup keys. The first `MCP_TOKEN_ENCRYPTION_KEYS` key encrypts new records; all listed keys decrypt old records, enabling staged rotation. Non-loopback multi-user mode requires Redis and the `multi-user` package extra.

Generate independent 32-byte base64url secrets for cursor signing and token encryption:

```bash
python -c "import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b'=').decode())"
```

Never reuse the MCP bearer, cursor key, encryption key, Yandex client secret, or downstream token for another purpose.

## Network binding

Loopback HTTP is allowed for development. A non-loopback listener requires an authenticated MCP mode, HTTPS issuer/resource/callback URLs, exact non-wildcard `MCP_ALLOWED_HOSTS` and `MCP_ALLOWED_ORIGINS`, and persistent cursor keys. TLS normally terminates at a reverse proxy. Forwarded scheme/host headers are honored only when the direct peer belongs to `MCP_TRUSTED_PROXY_CIDRS`.

## Dedicated Disk and Mail

See [profile configuration and mail contracts](profiles.md). Dedicated service
profiles have independent upstream OAuth clients, public issuers and Redis key
namespaces. Disk keeps workspace scopes; Mail requires `mail:*` scopes and a
Yandex ID email in its encrypted downstream credential. Global Trash purge is
prohibited. Wiki remains available only in the legacy workspace profile.

The OAuth revocation endpoint is enabled and advertised at `/revoke`. A bounded
form adapter compensates for the pinned SDK requiring an explicit secret field
even for public clients; confidential-client authentication and token ownership
checks remain in the SDK.
