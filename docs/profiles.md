# Dedicated Disk and Mail profiles

The hosted endpoints are `https://yandex-disk.kabagun.top/mcp` and
`https://yandex-mail.kabagun.top/mcp`. They run from one checkout in two processes.
A user authorizes each connection independently with their own Yandex account.
A running HTTP endpoint alone does not prove a working upstream OAuth grant.

## OAuth application fields

Create two separate **Web services** applications in [Yandex OAuth](https://oauth.yandex.ru/).
For the Mail application use:

| Field | Value |
| --- | --- |
| Name | Yandex Mail MCP |
| Platform | Web services |
| Redirect URI | `https://yandex-mail.kabagun.top/oauth/yandex/callback` |
| Suggested homepage | `https://yandex-mail.kabagun.top` |
| Permissions | `mail:imap_full`, `mail:smtp`, `login:email` |
| Contact email | The application owner's working email |

Copy that application's ClientID and Client secret into the Mail process's
`YANDEX_OAUTH_CLIENT_ID` and `YANDEX_OAUTH_CLIENT_SECRET`. The redirect must match
exactly. The hosted flow uses its own callback, not the CLI debugging redirect.
The Disk application uses `https://yandex-disk.kabagun.top/oauth/yandex/callback`
and its existing Disk read/write/info permissions. Do not reuse the Mail client
for Disk or the Disk client for Mail.

Yandex documents [IMAP/SMTP OAuth permissions and XOAUTH2](https://yandex.ru/support/yandex-360/business/mail/ru/web/security/oauth).
The Mail callback obtains `default_email` from [Yandex ID](https://yandex.ru/dev/id/doc/ru/user-information),
requiring `login:email`; missing or malformed addresses fail authorization.
Users must enable IMAP and OAuth tokens in their [mail client settings](https://www.yandex.ru/support/yandex-360/customers/mail/ru/mail-clients/others).
No account password is used. Addresses are never accepted from a tool caller as
a choice of account or sender.

## Process configuration and isolation

Use [.env.disk.example](../.env.disk.example) and [.env.mail.example](../.env.mail.example)
as separate protected environment files. Replace every placeholder before startup.
`MCP_PROFILE=disk` enables only Disk; `MCP_PROFILE=mail` enables only Mail.
Contradictory enable flags fail startup. The legacy `workspace` profile retains
upstream Disk/Wiki compatibility. Mail requires multi-user authentication.

Each dedicated profile owns its issuer/resource/callback, OAuth client and cursor
and encryption keys. Redis may be shared: all record keys (clients, OAuth state,
authorization codes, MCP tokens, downstream credentials and recovery handles)
are prefixed with the profile and a SHA-256 digest of the issuer. The default
namespace is available as `Settings.auth_storage_prefix`; never manually put
records from one service into another's namespace. The legacy workspace prefix
is `ywmcp:auth:v1`.

For upgrading an existing Disk instance: stop only that service, preserve its
revision/environment and signing/encryption keys, then copy its legacy Redis
records to the new Disk prefix using Redis `COPY` so values and TTLs are retained.
Refuse destination collisions and remap the full client-key members of copied
`registration-source` quota indexes to the new prefix, preserving scores/TTL.
Copy only the known Disk deployment's namespace;
keep the legacy records for rollback. Issue no `FLUSHDB`, `FLUSHALL` or global
key deletion. Restart and check discovery, health and authentication boundaries.
Existing principal IDs remain valid when issuer and MCP client IDs are unchanged.

MCP rights remain `workspace:read`, `workspace:write`, `workspace:delete` for Disk
compatibility. Mail uses `mail:read`, `mail:write`, `mail:delete`. Within each
namespace write implies read and delete implies write/read. These implications
never cross namespaces. Each tool also enforces its process permission gate.
Revoking a grant removes that user's downstream credentials in this profile and
the access/refresh pair; another user's grant and the other profile are unaffected.

Mail resolves request-local credentials before starting a blocking operation in
a worker thread. Every operation owns a fresh verified TLS connection to
`imap.yandex.ru:993` or `smtp.yandex.ru:465`. No global account or connection pool
selects a mailbox. Access tokens are refreshed through the existing OAuth provider.
IMAP/SMTP commands are never retried automatically.

## Mail tool contract

| Tools | Gate / MCP scope | Behavior |
| --- | --- | --- |
| `mail_folders` | `MAIL_READ` / `mail:read` | List selectable folders and server flags |
| `mail_list`, `mail_search` | `MAIL_READ` / `mail:read` | Bounded newest-first UID scan, structured search, pagination |
| `mail_read`, `mail_attachment` | `MAIL_READ` / `mail:read` | MIME content/attachment read without changing Seen |
| `mail_send`, `mail_reply`, `mail_forward` | `MAIL_WRITE` / `mail:write` | SMTP submission using the authorized sender |
| `mail_set_read` | `MAIL_WRITE` / `mail:write` | Set or clear Seen for the exact referenced message |
| `mail_trash` | `MAIL_DELETE` / `mail:delete` | Move one referenced message to server-designated Trash |

Obtain message references from list/search. They carry account identity, folder,
UID and UIDVALIDITY. References from another account or a rebuilt folder fail;
sequence numbers and caller-supplied raw IMAP commands are not accepted. Search
results state their bounded scan and continuation: an empty page does not prove
that an entire mailbox has no matches. Folder names support IMAP modified UTF-7.

Read operations check advertised MIME size before fetching message bytes and use
`BODY.PEEK`. Default caps: 10 MiB per message, 5 MiB per decoded attachment, 30 s
socket timeout. The HTTP request body cap (`MCP_MAX_REQUEST_BODY_BYTES`, default
2 MiB) further limits base64 attachments in submitted MCP calls. Raising it must
remain consistent with mail size caps. Attachments are inline data; arbitrary
server-local paths and remote URLs are not supported.

Moving to Trash requires the server's safe UID MOVE capability and an unambiguous
Trash folder. If unavailable the operation fails without a destructive fallback.
No `EXPUNGE`, Trash purge or permanent-mail-deletion tool exists. SMTP acceptance
is not a delivery receipt. A disconnect after submission can leave the outcome
unknown; investigate acceptance/delivery before retrying. The client does not append
a Sent-folder copy (`sent_copy_saved=false`); absence from Sent does not prove
failure. No automatic retry is performed.

The Disk profile retains reading, writing, moving to Trash and restoring from
Trash. Account-wide Disk purge is prohibited even with legacy confirmation flags.

## Verification and activation

Offline tests cover two simulated Yandex accounts, separate Disk/Mail grants,
PKCE rejection/replay, refresh/revoke, protocol failures, permission gates and
safe Trash semantics. They never send or delete real mail. Test fixtures are not
proof of live Yandex compatibility: after installing Mail ClientID/secret, each
user must authorize through the actual callback. Validate only read-only folder
and message operations; sending and deleting require a real user task.

Keep the Mail service disabled until its client credentials are present. With
systemd, use independent units and environment files while sharing the executable:
`yandex-workspace-mcp serve`. Bind Disk to `127.0.0.1:18001` and Mail to the reserved
`127.0.0.1:18003`, and proxy each domain only to its own port. Do not expose Redis.
