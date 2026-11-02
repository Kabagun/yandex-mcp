import hashlib
import hmac
import json
import math
import re
import time
from collections.abc import Callable
from importlib import import_module
from pathlib import Path
from typing import Any, TypeVar

import anyio
import structlog
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import BaseModel

from ..models.errors import ConfigurationError
from .client_migration import LegacyClientValue, read_legacy_client_aof
from .models import (
    AccessTokenRecord,
    AuthorizationCodeRecord,
    DownstreamCredentialRecord,
    OAuthClientRecord,
    OAuthStateRecord,
    RecoveryHandleRecord,
    RefreshTokenRecord,
)
from .stores import (
    _DOWNSTREAM_REFRESH_KIND,
    _MAX_REFRESH_CLAIM_LIMIT,
    _REFRESH_CLAIM_SECONDS,
    EncryptedRecord,
    EncryptedRecordCodec,
    TokenStoreMiss,
    _DownstreamRefreshLocator,
    _validate_downstream_record,
)

RecordT = TypeVar("RecordT", bound=BaseModel)
logger = structlog.get_logger()
_PERMANENT_CLIENT_SCORE = 9_999_999_999.0


_MIGRATE_CLIENT_SCRIPT = """
local score = redis.call('ZSCORE', KEYS[2], KEYS[1])
if not score or tonumber(score) ~= tonumber(ARGV[1]) then return 0 end
if redis.call('EXISTS', KEYS[1]) == 1 then
  redis.call('PERSIST', KEYS[1])
  redis.call('ZADD', KEYS[2], ARGV[2], KEYS[1])
  return 1
end
if ARGV[3] == '' or redis.call('EXISTS', KEYS[3]) == 1 then return 0 end
redis.call('SET', KEYS[1], ARGV[3])
redis.call('ZADD', KEYS[2], ARGV[2], KEYS[1])
return 2
"""

_RECOVER_CLIENT_SCRIPT = """
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
for index = 4, #KEYS do
  if redis.call('EXISTS', KEYS[index]) == 1 then
    redis.call('SET', KEYS[1], 'existing')
    return 0
  end
end
redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', ARGV[3])
if redis.call('ZCARD', KEYS[3]) >= tonumber(ARGV[4]) then return -1 end
redis.call('SET', KEYS[2], ARGV[1])
redis.call('ZADD', KEYS[3], ARGV[2], KEYS[2])
redis.call('SET', KEYS[1], 'recovered')
return 1
"""


_CONSUME_SCRIPT = """
local value = redis.call('GET', KEYS[1])
if not value then return false end
redis.call('DEL', KEYS[1])
return value
"""

_ROTATE_PAIR_SCRIPT = """
local value = redis.call('GET', KEYS[1])
if not value or value ~= ARGV[1] then return false end
local key_count = tonumber(ARGV[2])
redis.call('DEL', KEYS[1])
for index = 2, #KEYS do
  redis.call('DEL', KEYS[index])
end
local refresh_key = 2 + key_count
local access_key = 2 + (2 * key_count)
if tonumber(ARGV[4]) > 0 then
  redis.call('SET', KEYS[refresh_key], ARGV[3], 'EX', ARGV[4])
else
  redis.call('SET', KEYS[refresh_key], ARGV[3])
end
if tonumber(ARGV[6]) > 0 then
  redis.call('SET', KEYS[access_key], ARGV[5], 'EX', ARGV[6])
else
  redis.call('SET', KEYS[access_key], ARGV[5])
end
return value
"""

_REGISTER_CLIENT_SCRIPT = """
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[4])
local exists = redis.call('ZSCORE', KEYS[2], ARGV[3])
if not exists and redis.call('ZCARD', KEYS[2]) >= tonumber(ARGV[5]) then return false end
redis.call('DEL', unpack(KEYS, 3))
if tonumber(ARGV[2]) > 0 then
  redis.call('SET', KEYS[1], ARGV[1], 'EX', ARGV[2])
else
  redis.call('SET', KEYS[1], ARGV[1])
end
redis.call('ZADD', KEYS[2], ARGV[6], ARGV[3])
return true
"""

_CLAIM_DOWNSTREAM_SCRIPT = """
local limit = math.min(math.max(tonumber(ARGV[3]) or 0, 0), 1000)
if limit == 0 then return {} end
local members = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', 0, limit)
for _, member in ipairs(members) do
  redis.call('ZADD', KEYS[1], ARGV[2], member)
end
return members
"""

_DISCARD_DOWNSTREAM_SCRIPT = """
local score = redis.call('ZSCORE', KEYS[1], ARGV[1])
if not score or tonumber(score) ~= tonumber(ARGV[2]) then return false end
local value = redis.call('GET', KEYS[2])
if (value or '') ~= ARGV[3] then return false end
redis.call('ZREM', KEYS[1], ARGV[1])
redis.call('DEL', KEYS[2])
return true
"""


class RedisTokenStore:
    """Encrypted Redis store; Redis keys contain keyed hashes, never bearer tokens."""

    def __init__(
        self,
        keys: tuple[bytes, ...],
        *,
        url: str | None = None,
        client: Any | None = None,
        prefix: str = "ywmcp:auth:v1",
        clock: Callable[[], float] = time.time,
        registration_cap: int = 100,
        permanent_clients: bool = False,
        legacy_client_aof_path: Path | None = None,
        client_recovery_ids: tuple[str, ...] = (),
    ) -> None:
        if client is None:
            if not url:
                raise ConfigurationError("Redis auth storage requires a URL.")
            try:
                redis_asyncio = import_module("redis.asyncio")
            except ImportError as exc:
                raise ConfigurationError(
                    "Redis auth storage requires the 'multi-user' package extra."
                ) from exc
            client = redis_asyncio.Redis.from_url(url, decode_responses=False)
            self._owns_client = True
        else:
            self._owns_client = False
        self._client = client
        self._codec = EncryptedRecordCodec(keys)
        self._lookup_keys = tuple(key[:32] for key in keys)
        self._prefix = prefix
        self._clock = clock
        self._registration_cap = registration_cap
        self._permanent_clients = permanent_clients
        self._legacy_client_aof_path = legacy_client_aof_path
        self._client_recovery_ids = tuple(dict.fromkeys(client_recovery_ids))
        self._closed = False

    async def open(self) -> None:
        if self._closed:
            raise ConfigurationError("Redis token store is closed.")
        await self._client.ping()
        if self._permanent_clients:
            await self._recover_configured_clients()
            await self._migrate_clients()

    async def _recover_configured_clients(self) -> None:
        """Restore only operator-selected original clients after an authorization reset."""
        pending: list[tuple[str, str]] = []
        for client_id in self._client_recovery_ids:
            receipt = (
                f"{self._prefix}:client-recovery:v1:"
                + self._redis_keys("client", client_id)[0].rsplit(":", 1)[1]
            )
            if not await self._client.exists(receipt):
                pending.append((client_id, receipt))
        if not pending:
            return
        archive_path = self._legacy_client_aof_path
        if archive_path is None or len(pending) > self._registration_cap:
            raise ConfigurationError("Configured OAuth client recovery source is required.")
        db = int(self._client.connection_pool.connection_kwargs.get("db", 0))
        archive = await anyio.to_thread.run_sync(
            lambda: read_legacy_client_aof(
                archive_path, prefix=self._prefix, db=db, include_permanent=True
            )
        )
        recovered = 0
        for client_id, receipt in pending:
            candidates = self._redis_keys("client", client_id)
            if any([await self._client.exists(key) for key in candidates]):
                await self._client.set(receipt, "existing", nx=True)
                continue
            snapshot = next(
                (archive[key.encode()] for key in candidates if key.encode() in archive), None
            )
            if snapshot is None:
                raise ConfigurationError("Configured OAuth client recovery record is unavailable.")
            try:
                original = self._decode("client", client_id, snapshot.payload, OAuthClientRecord)
                if (
                    original.client_id != client_id
                    or original.metadata.get("client_id") != client_id
                ):
                    raise TokenStoreMiss()
                info = OAuthClientInformationFull.model_validate(original.metadata)
                if (
                    info.client_secret != original.client_secret
                    or tuple(map(str, info.redirect_uris or ())) != original.redirect_uris
                    or set((info.scope or "").split()) != set(original.allowed_scopes)
                ):
                    raise TokenStoreMiss()
            except (TokenStoreMiss, ValueError, TypeError):
                raise ConfigurationError(
                    "Configured OAuth client recovery record is invalid."
                ) from None
            record = original.model_copy(
                update={
                    "expires_at": None,
                    "client_secret_expires_at": None,
                    "metadata": {**original.metadata, "client_secret_expires_at": 0},
                }
            )
            source_hash = hmac.new(
                self._lookup_keys[0],
                f"registration-source\0{record.registration_source}".encode(),
                hashlib.sha256,
            ).hexdigest()
            result = await self._client.eval(
                _RECOVER_CLIENT_SCRIPT,
                3 + len(candidates),
                receipt,
                candidates[0],
                f"{self._prefix}:registration-source:{source_hash}",
                *candidates,
                self._encode("client", client_id, record),
                _PERMANENT_CLIENT_SCORE,
                self._clock(),
                self._registration_cap,
            )
            if result < 0:
                raise ConfigurationError("OAuth client registration capacity reached.")
            recovered += result == 1
        logger.info("oauth.configured_client_recovery", restored=recovered)

    async def _migrate_clients(self) -> None:
        """Preserve existing clients and enroll legacy TTL losses once, before serving HTTP."""
        marker = f"{self._prefix}:client-migration:v1"
        archive: dict[bytes, LegacyClientValue] = {}
        archive_path = self._legacy_client_aof_path
        recovering = archive_path is not None and not await self._client.exists(marker)
        if recovering and archive_path is not None:
            db = int(self._client.connection_pool.connection_kwargs.get("db", 0))
            archive = await anyio.to_thread.run_sync(
                lambda: read_legacy_client_aof(archive_path, prefix=self._prefix, db=db)
            )
        promoted = restored = 0
        now = self._clock()
        async for source in self._client.scan_iter(match=f"{self._prefix}:registration-source:*"):
            async for key, score in self._client.zscan_iter(source):
                candidate = archive.get(key)
                payload = b""
                # Redis rewrites EX seconds as PXAT; ceil-based TTL rounds up by <1 second.
                if (
                    candidate is not None
                    and candidate.expires_at is not None
                    and score <= now
                    and candidate.expires_at <= now
                    and abs(candidate.expires_at - score) <= 1.1
                ):
                    payload = candidate.payload
                if not re.fullmatch(
                    re.escape(f"{self._prefix}:client:".encode()) + rb"[0-9a-f]{64}", key
                ):
                    continue
                result = await self._client.eval(
                    _MIGRATE_CLIENT_SCRIPT,
                    3,
                    key,
                    source,
                    marker,
                    score,
                    _PERMANENT_CLIENT_SCORE,
                    payload,
                )
                promoted += result == 1
                restored += result == 2
        # PERSIST orphaned live clients as well: a previous registration may have pruned its index.
        async for key in self._client.scan_iter(match=f"{self._prefix}:client:*"):
            await self._client.persist(key)
        if recovering:
            await self._client.set(marker, "complete", nx=True)
        logger.info("oauth.client_migration", preserved=promoted, restored=restored)

    def _redis_keys(self, kind: str, record_key: str) -> tuple[str, ...]:
        return tuple(
            f"{self._prefix}:{kind}:"
            + hmac.new(key, f"lookup\0{kind}\0{record_key}".encode(), hashlib.sha256).hexdigest()
            for key in self._lookup_keys
        )

    def _encode(self, kind: str, record_key: str, record: BaseModel) -> bytes:
        encrypted = self._codec.encrypt(kind, record_key, record.model_dump_json().encode())
        return json.dumps(
            {
                "key_id": encrypted.key_id,
                "nonce": encrypted.nonce,
                "ciphertext": encrypted.ciphertext,
            },
            separators=(",", ":"),
        ).encode()

    def _decode(
        self, kind: str, record_key: str, payload: bytes | str, model: type[RecordT]
    ) -> RecordT:
        try:
            value = json.loads(payload)
            encrypted = EncryptedRecord(
                key_id=value["key_id"], nonce=value["nonce"], ciphertext=value["ciphertext"]
            )
            plaintext = self._codec.decrypt(kind, record_key, encrypted)
            return model.model_validate_json(plaintext)
        except (KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
            raise TokenStoreMiss() from exc

    def _ttl(self, expires_at: float | None) -> int | None:
        if expires_at is None:
            return None
        remaining = math.ceil(expires_at - self._clock())
        if remaining <= 0:
            raise TokenStoreMiss()
        return remaining

    async def _put(self, kind: str, key: str, record: BaseModel) -> None:
        if self._closed:
            raise TokenStoreMiss()
        redis_key = self._redis_keys(kind, key)[0]
        payload = self._encode(kind, key, record)
        ttl = self._ttl(getattr(record, "expires_at", None))
        candidates = self._redis_keys(kind, key)
        pipeline = self._client.pipeline(transaction=True)
        pipeline.delete(*candidates)
        pipeline.set(redis_key, payload, ex=ttl)
        await pipeline.execute()

    async def _find(self, kind: str, key: str) -> tuple[str, bytes]:
        if self._closed:
            raise TokenStoreMiss()
        for candidate in self._redis_keys(kind, key):
            payload = await self._client.get(candidate)
            if payload is not None:
                return candidate, payload
        raise TokenStoreMiss()

    async def _get(self, kind: str, key: str, model: type[RecordT]) -> RecordT:
        _, payload = await self._find(kind, key)
        return self._decode(kind, key, payload, model)

    async def _consume(self, kind: str, key: str, model: type[RecordT]) -> RecordT:
        candidate, _ = await self._find(kind, key)
        payload = await self._client.eval(_CONSUME_SCRIPT, 1, candidate)
        if not payload:
            raise TokenStoreMiss()
        return self._decode(kind, key, payload, model)

    async def put_client(self, record: OAuthClientRecord) -> None:
        candidates = self._redis_keys("client", record.client_id)
        redis_key = candidates[0]
        source_hash = hmac.new(
            self._lookup_keys[0],
            f"registration-source\0{record.registration_source}".encode(),
            hashlib.sha256,
        ).hexdigest()
        source_key = f"{self._prefix}:registration-source:{source_hash}"
        payload = self._encode("client", record.client_id, record)
        ttl = self._ttl(record.expires_at) or 0
        score = record.expires_at if record.expires_at is not None else 9_999_999_999.0
        result = await self._client.eval(
            _REGISTER_CLIENT_SCRIPT,
            2 + len(candidates),
            redis_key,
            source_key,
            *candidates,
            payload,
            ttl,
            redis_key,
            self._clock(),
            self._registration_cap,
            score,
        )
        if not result:
            raise ConfigurationError("OAuth client registration capacity reached.")

    async def get_client(self, client_id: str) -> OAuthClientRecord:
        return await self._get("client", client_id, OAuthClientRecord)

    async def put_state(self, state: str, record: OAuthStateRecord) -> None:
        await self._put("state", state, record)

    async def consume_state(self, state: str) -> OAuthStateRecord:
        return await self._consume("state", state, OAuthStateRecord)

    async def get_state(self, state: str) -> OAuthStateRecord:
        return await self._get("state", state, OAuthStateRecord)

    async def put_authorization_code(self, code: str, record: AuthorizationCodeRecord) -> None:
        await self._put("authorization-code", code, record)

    async def consume_authorization_code(self, code: str) -> AuthorizationCodeRecord:
        return await self._consume("authorization-code", code, AuthorizationCodeRecord)

    async def get_authorization_code(self, code: str) -> AuthorizationCodeRecord:
        return await self._get("authorization-code", code, AuthorizationCodeRecord)

    async def put_access_token(self, token: str, record: AccessTokenRecord) -> None:
        await self._put("access-token", token, record)

    async def get_access_token(self, token: str) -> AccessTokenRecord:
        return await self._get("access-token", token, AccessTokenRecord)

    async def put_refresh_token(self, token: str, record: RefreshTokenRecord) -> None:
        await self._put("refresh-token", token, record)

    async def get_refresh_token(self, token: str) -> RefreshTokenRecord:
        return await self._get("refresh-token", token, RefreshTokenRecord)

    async def put_token_pair(
        self,
        *,
        access_token: str,
        access_record: AccessTokenRecord,
        refresh_token: str,
        refresh_record: RefreshTokenRecord,
    ) -> None:
        self._validate_pair(access_token, access_record, refresh_token, refresh_record)
        access_keys = self._redis_keys("access-token", access_token)
        refresh_keys = self._redis_keys("refresh-token", refresh_token)
        access_payload = self._encode("access-token", access_token, access_record)
        refresh_payload = self._encode("refresh-token", refresh_token, refresh_record)
        access_ttl = self._ttl(access_record.expires_at)
        refresh_ttl = self._ttl(refresh_record.expires_at)
        pipeline = self._client.pipeline(transaction=True)
        pipeline.delete(*access_keys, *refresh_keys)
        pipeline.set(access_keys[0], access_payload, ex=access_ttl)
        pipeline.set(refresh_keys[0], refresh_payload, ex=refresh_ttl)
        await pipeline.execute()

    async def rotate_token_pair(
        self,
        *,
        old_refresh_token: str,
        new_refresh_token: str,
        new_refresh_record: RefreshTokenRecord,
        new_access_token: str,
        new_access_record: AccessTokenRecord,
    ) -> RefreshTokenRecord:
        self._validate_pair(
            new_access_token, new_access_record, new_refresh_token, new_refresh_record
        )
        old_key, old_payload = await self._find("refresh-token", old_refresh_token)
        old_record = self._decode(
            "refresh-token", old_refresh_token, old_payload, RefreshTokenRecord
        )
        old_access_keys = self._redis_keys("access-token", old_record.access_token or "")
        new_refresh_keys = self._redis_keys("refresh-token", new_refresh_token)
        new_access_keys = self._redis_keys("access-token", new_access_token)
        refresh_payload = self._encode("refresh-token", new_refresh_token, new_refresh_record)
        access_payload = self._encode("access-token", new_access_token, new_access_record)
        refresh_ttl = self._ttl(new_refresh_record.expires_at) or 0
        access_ttl = self._ttl(new_access_record.expires_at) or 0
        result = await self._client.eval(
            _ROTATE_PAIR_SCRIPT,
            1 + len(old_access_keys) + len(new_refresh_keys) + len(new_access_keys),
            old_key,
            *old_access_keys,
            *new_refresh_keys,
            *new_access_keys,
            old_payload,
            len(self._lookup_keys),
            refresh_payload,
            refresh_ttl,
            access_payload,
            access_ttl,
        )
        if not result:
            raise TokenStoreMiss()
        return old_record

    @staticmethod
    def _validate_pair(
        access_token: str,
        access_record: AccessTokenRecord,
        refresh_token: str,
        refresh_record: RefreshTokenRecord,
    ) -> None:
        if (
            access_record.refresh_token != refresh_token
            or refresh_record.access_token != access_token
            or access_record.client_id != refresh_record.client_id
            or access_record.subject != refresh_record.subject
            or access_record.scopes != refresh_record.scopes
        ):
            raise ConfigurationError("OAuth token pair is inconsistent.")

    async def revoke_token_pair(
        self, *, access_token: str | None, refresh_token: str | None
    ) -> None:
        keys: list[str] = []
        if access_token:
            keys.extend(self._redis_keys("access-token", access_token))
        if refresh_token:
            keys.extend(self._redis_keys("refresh-token", refresh_token))
        if keys:
            await self._client.delete(*keys)

    async def put_downstream(self, principal_id: str, record: DownstreamCredentialRecord) -> None:
        if self._closed:
            raise TokenStoreMiss()
        _validate_downstream_record(principal_id, record)
        pipeline = self._client.pipeline(transaction=True)
        self._queue_put_downstream(pipeline, principal_id, record)
        await pipeline.execute()

    def _queue_put_downstream(
        self, pipeline: Any, principal_id: str, record: DownstreamCredentialRecord
    ) -> None:
        candidates = self._redis_keys("downstream", principal_id)
        locators = self._redis_keys(_DOWNSTREAM_REFRESH_KIND, principal_id)
        members = tuple(key.rsplit(":", 1)[1] for key in locators)
        ttl = self._ttl(record.expires_at)
        payload = self._encode("downstream", principal_id, record)
        locator_payload = None
        if record.refresh_token and record.refresh_after is not None:
            locator_payload = self._encode(
                _DOWNSTREAM_REFRESH_KIND,
                members[0],
                _DownstreamRefreshLocator(principal_id=principal_id, expires_at=record.expires_at),
            )
        self._queue_delete_downstream(pipeline, principal_id)
        pipeline.set(candidates[0], payload, ex=ttl)
        if locator_payload is not None:
            pipeline.set(locators[0], locator_payload, ex=ttl)
            pipeline.zadd(self._refresh_schedule_key, {members[0]: record.refresh_after})

    async def get_downstream(self, principal_id: str) -> DownstreamCredentialRecord:
        return await self._get("downstream", principal_id, DownstreamCredentialRecord)

    async def delete_downstream(self, principal_id: str) -> None:
        pipeline = self._client.pipeline(transaction=True)
        self._queue_delete_downstream(pipeline, principal_id)
        await pipeline.execute()

    def _queue_delete_downstream(self, pipeline: Any, principal_id: str) -> None:
        locators = self._redis_keys(_DOWNSTREAM_REFRESH_KIND, principal_id)
        pipeline.delete(*self._redis_keys("downstream", principal_id), *locators)
        pipeline.zrem(self._refresh_schedule_key, *(key.rsplit(":", 1)[1] for key in locators))

    async def replace_downstream(
        self,
        principal_id: str,
        expected: DownstreamCredentialRecord,
        replacement: DownstreamCredentialRecord,
    ) -> bool:
        """Replace only the expected current grant; a revoked grant is never recreated."""
        _validate_downstream_record(principal_id, replacement)
        return await self._mutate_downstream_if_current(principal_id, expected, replacement)

    async def delete_downstream_if_current(
        self, principal_id: str, expected: DownstreamCredentialRecord
    ) -> bool:
        """Delete only the expected current grant, preserving any newer authorization."""
        return await self._mutate_downstream_if_current(principal_id, expected, None)

    async def _mutate_downstream_if_current(
        self,
        principal_id: str,
        expected: DownstreamCredentialRecord,
        replacement: DownstreamCredentialRecord | None,
    ) -> bool:
        if self._closed:
            return False
        watch_error = import_module("redis.exceptions").WatchError
        candidates = self._redis_keys("downstream", principal_id)
        async with self._client.pipeline(transaction=True) as pipeline:
            try:
                await pipeline.watch(*candidates)
                payloads = await pipeline.mget(*candidates)
                payload = next((payload for payload in payloads if payload is not None), None)
                if payload is None:
                    return False
                current = self._decode(
                    "downstream", principal_id, payload, DownstreamCredentialRecord
                )
                if current != expected or (
                    current.expires_at is not None and current.expires_at <= self._clock()
                ):
                    return False
                pipeline.multi()
                if replacement is None:
                    self._queue_delete_downstream(pipeline, principal_id)
                else:
                    self._queue_put_downstream(pipeline, principal_id, replacement)
                await pipeline.execute()
                return True
            except (watch_error, TokenStoreMiss):
                return False

    @property
    def _refresh_schedule_key(self) -> str:
        return f"{self._prefix}:downstream-refresh-due"

    async def list_due_downstream(self, *, limit: int = 100) -> list[str]:
        """Atomically lease due refresh jobs for 300 seconds; cap each claim at 1,000."""
        if self._closed:
            raise TokenStoreMiss()
        now = self._clock()
        lease_until = now + _REFRESH_CLAIM_SECONDS
        members = await self._client.eval(
            _CLAIM_DOWNSTREAM_SCRIPT,
            1,
            self._refresh_schedule_key,
            now,
            lease_until,
            min(max(limit, 0), _MAX_REFRESH_CLAIM_LIMIT),
        )
        principals: list[str] = []
        for raw_member in members:
            try:
                member = raw_member.decode("ascii") if isinstance(raw_member, bytes) else raw_member
                if not isinstance(member, str) or not re.fullmatch(r"[0-9a-f]{64}", member):
                    raise ValueError()
            except (ValueError, UnicodeDecodeError):
                await self._client.zrem(self._refresh_schedule_key, raw_member)
                continue
            locator_key = f"{self._prefix}:{_DOWNSTREAM_REFRESH_KIND}:{member}"
            payload = await self._client.get(locator_key)
            try:
                if payload is None:
                    raise TokenStoreMiss()
                locator = self._decode(
                    _DOWNSTREAM_REFRESH_KIND, member, payload, _DownstreamRefreshLocator
                )
                if locator.expires_at is not None and locator.expires_at <= now:
                    raise TokenStoreMiss()
                candidates = self._redis_keys(_DOWNSTREAM_REFRESH_KIND, locator.principal_id)
                if locator_key not in candidates:
                    raise TokenStoreMiss()
                record = await self.get_downstream(locator.principal_id)
                if (
                    not record.refresh_token
                    or record.refresh_after is None
                    or (record.expires_at is not None and record.expires_at <= now)
                ):
                    raise TokenStoreMiss()
            except TokenStoreMiss:
                # Compare both lease and ciphertext so a concurrent refresh cannot be erased.
                await self._client.eval(
                    _DISCARD_DOWNSTREAM_SCRIPT,
                    2,
                    self._refresh_schedule_key,
                    locator_key,
                    member,
                    lease_until,
                    payload if payload is not None else b"",
                )
                continue
            if record.refresh_after <= now:
                principals.append(locator.principal_id)
        return principals

    async def put_recovery(
        self, handle: str, principal_id: str, record: RecoveryHandleRecord
    ) -> None:
        if not hmac.compare_digest(principal_id, record.principal_id):
            raise ConfigurationError("Recovery handle principal mismatch.")
        await self._put("recovery", f"{principal_id}\0{handle}", record)

    async def consume_recovery(self, handle: str, principal_id: str) -> RecoveryHandleRecord:
        return await self._consume("recovery", f"{principal_id}\0{handle}", RecoveryHandleRecord)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._owns_client:
            await self._client.aclose()
