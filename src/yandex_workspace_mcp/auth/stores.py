import base64
import hashlib
import hmac
import math
import secrets
import time
from collections.abc import Callable, MutableMapping
from dataclasses import dataclass, replace
from typing import Protocol, TypeVar

import anyio
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel

from ..models.errors import ConfigurationError
from .models import (
    AccessTokenRecord,
    AuthorizationCodeRecord,
    DownstreamCredentialRecord,
    OAuthClientRecord,
    OAuthStateRecord,
    RecoveryHandleRecord,
    RefreshTokenRecord,
)


class TokenStoreMiss(Exception):
    """Opaque lookup failure used for unknown, expired, replayed, and revoked records."""


@dataclass(frozen=True, slots=True)
class EncryptedRecord:
    key_id: str
    nonce: str
    ciphertext: str


class EncryptedRecordCodec:
    def __init__(
        self, keys: tuple[bytes, ...], random_bytes: Callable[[int], bytes] = secrets.token_bytes
    ):
        if not keys or any(len(key) < 32 for key in keys):
            raise ConfigurationError("Token encryption keys must contain at least 32 bytes.")
        self._keys = tuple(key[:32] for key in keys)
        self._key_ids = tuple(self._key_id(key) for key in self._keys)
        self._random_bytes = random_bytes

    def encrypt(self, kind: str, record_key: str, plaintext: bytes) -> EncryptedRecord:
        nonce = self._random_bytes(12)
        ciphertext = AESGCM(self._keys[0]).encrypt(
            nonce,
            plaintext,
            self._aad(kind, record_key, self._key_ids[0]),
        )
        return EncryptedRecord(
            key_id=self._key_ids[0],
            nonce=self._encode(nonce),
            ciphertext=self._encode(ciphertext),
        )

    def decrypt(self, kind: str, record_key: str, record: EncryptedRecord) -> bytes:
        try:
            index = self._key_ids.index(record.key_id)
            nonce = self._decode(record.nonce)
            ciphertext = self._decode(record.ciphertext)
            return AESGCM(self._keys[index]).decrypt(
                nonce,
                ciphertext,
                self._aad(kind, record_key, record.key_id),
            )
        except (ValueError, InvalidTag, TypeError) as exc:
            raise TokenStoreMiss() from exc

    @staticmethod
    def _aad(kind: str, record_key: str, key_id: str) -> bytes:
        return f"yandex-workspace-mcp:auth:v1\0{kind}\0{record_key}\0{key_id}".encode()

    @staticmethod
    def _key_id(key: bytes) -> str:
        return base64.urlsafe_b64encode(hashlib.sha256(key).digest()[:9]).rstrip(b"=").decode()

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

    @staticmethod
    def _decode(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass(frozen=True, slots=True)
class _StoredRecord:
    kind: str
    encrypted: EncryptedRecord
    expires_at: float | None
    scheduled_at: float | None = None


class _DownstreamRefreshLocator(BaseModel):
    principal_id: str
    expires_at: float | None = None


_DOWNSTREAM_REFRESH_KIND = "downstream-refresh"
_REFRESH_CLAIM_SECONDS = 300
_MAX_REFRESH_CLAIM_LIMIT = 1000


def _validate_downstream_record(principal_id: str, record: DownstreamCredentialRecord) -> None:
    if not hmac.compare_digest(principal_id, record.principal_id):
        raise ConfigurationError("Downstream credential principal mismatch.")
    if record.refresh_after is not None and not math.isfinite(record.refresh_after):
        raise ConfigurationError("Downstream refresh time must be finite.")


class TokenStore(Protocol):
    async def put_client(self, record: OAuthClientRecord) -> None: ...

    async def get_client(self, client_id: str) -> OAuthClientRecord: ...

    async def put_state(self, state: str, record: OAuthStateRecord) -> None: ...

    async def get_state(self, state: str) -> OAuthStateRecord: ...

    async def consume_state(self, state: str) -> OAuthStateRecord: ...

    async def put_authorization_code(self, code: str, record: AuthorizationCodeRecord) -> None: ...

    async def get_authorization_code(self, code: str) -> AuthorizationCodeRecord: ...

    async def consume_authorization_code(self, code: str) -> AuthorizationCodeRecord: ...

    async def put_access_token(self, token: str, record: AccessTokenRecord) -> None: ...

    async def get_access_token(self, token: str) -> AccessTokenRecord: ...

    async def put_refresh_token(self, token: str, record: RefreshTokenRecord) -> None: ...

    async def get_refresh_token(self, token: str) -> RefreshTokenRecord: ...

    async def put_token_pair(
        self,
        *,
        access_token: str,
        access_record: AccessTokenRecord,
        refresh_token: str,
        refresh_record: RefreshTokenRecord,
    ) -> None: ...

    async def rotate_token_pair(
        self,
        *,
        old_refresh_token: str,
        new_refresh_token: str,
        new_refresh_record: RefreshTokenRecord,
        new_access_token: str,
        new_access_record: AccessTokenRecord,
    ) -> RefreshTokenRecord: ...

    async def revoke_token_pair(
        self, *, access_token: str | None, refresh_token: str | None
    ) -> None: ...

    async def put_downstream(
        self, principal_id: str, record: DownstreamCredentialRecord
    ) -> None: ...

    async def get_downstream(self, principal_id: str) -> DownstreamCredentialRecord: ...

    async def delete_downstream(self, principal_id: str) -> None: ...

    async def replace_downstream(
        self,
        principal_id: str,
        expected: DownstreamCredentialRecord,
        replacement: DownstreamCredentialRecord,
    ) -> bool:
        """Atomically replace a matching current grant and its refresh schedule."""
        ...

    async def delete_downstream_if_current(
        self, principal_id: str, expected: DownstreamCredentialRecord
    ) -> bool:
        """Atomically delete a matching current grant and its refresh schedule."""
        ...

    async def list_due_downstream(self, *, limit: int = 100) -> list[str]:
        """Claim due refresh jobs for five minutes, returning at most 1,000 principal IDs."""
        ...

    async def put_recovery(
        self, handle: str, principal_id: str, record: RecoveryHandleRecord
    ) -> None: ...

    async def consume_recovery(self, handle: str, principal_id: str) -> RecoveryHandleRecord: ...

    async def close(self) -> None: ...


RecordT = TypeVar("RecordT", bound=BaseModel)


class InMemoryTokenStore:
    def __init__(
        self,
        keys: tuple[bytes, ...],
        *,
        clock: Callable[[], float] = time.time,
        random_bytes: Callable[[int], bytes] = secrets.token_bytes,
        records: MutableMapping[str, object] | None = None,
        registration_cap: int = 100,
    ) -> None:
        self._keys = tuple(key[:32] for key in keys)
        self._codec = EncryptedRecordCodec(self._keys, random_bytes)
        self._clock = clock
        self._records = records if records is not None else {}
        self._registration_cap = registration_cap
        self._client_sources: dict[str, set[str]] = {}
        self._lock = anyio.Lock()
        self._closed = False

    def _lookup_candidates(self, kind: str, key: str) -> tuple[str, ...]:
        return tuple(
            hmac.new(secret, f"lookup\0{kind}\0{key}".encode(), hashlib.sha256).hexdigest()
            for secret in self._keys
        )

    async def _put(self, kind: str, key: str, record: BaseModel) -> None:
        async with self._lock:
            self._put_locked(kind, key, record)

    def _put_locked(self, kind: str, key: str, record: BaseModel) -> None:
        if self._closed:
            raise TokenStoreMiss()
        candidates = self._lookup_candidates(kind, key)
        for candidate in candidates:
            self._records.pop(candidate, None)
        lookup = candidates[0]
        expires_at = getattr(record, "expires_at", None)
        self._records[lookup] = _StoredRecord(
            kind=kind,
            encrypted=self._codec.encrypt(kind, key, record.model_dump_json().encode()),
            expires_at=expires_at,
        )

    def _get_locked(self, kind: str, key: str, model: type[RecordT]) -> tuple[str, RecordT]:
        if self._closed:
            raise TokenStoreMiss()
        for lookup in self._lookup_candidates(kind, key):
            raw = self._records.get(lookup)
            if not isinstance(raw, _StoredRecord) or raw.kind != kind:
                continue
            if raw.expires_at is not None and raw.expires_at <= self._clock():
                self._records.pop(lookup, None)
                raise TokenStoreMiss()
            payload = self._codec.decrypt(kind, key, raw.encrypted)
            try:
                return lookup, model.model_validate_json(payload)
            except (ValueError, TypeError) as exc:
                raise TokenStoreMiss() from exc
        raise TokenStoreMiss()

    async def _get(self, kind: str, key: str, model: type[RecordT]) -> RecordT:
        async with self._lock:
            return self._get_locked(kind, key, model)[1]

    async def _consume(self, kind: str, key: str, model: type[RecordT]) -> RecordT:
        async with self._lock:
            lookup, record = self._get_locked(kind, key, model)
            self._records.pop(lookup, None)
            return record

    async def put_client(self, record: OAuthClientRecord) -> None:
        async with self._lock:
            existing = None
            try:
                existing = self._get_locked("client", record.client_id, OAuthClientRecord)[1]
            except TokenStoreMiss:
                pass
            if existing is None:
                source_hash = hashlib.sha256(record.registration_source.encode()).hexdigest()
                members = self._client_sources.setdefault(source_hash, set())
                active: set[str] = set()
                for member in members:
                    raw = self._records.get(member)
                    if isinstance(raw, _StoredRecord) and (
                        raw.expires_at is None or raw.expires_at > self._clock()
                    ):
                        active.add(member)
                members.intersection_update(active)
                if len(members) >= self._registration_cap:
                    raise ConfigurationError("OAuth client registration capacity reached.")
                members.add(self._lookup_candidates("client", record.client_id)[0])
            self._put_locked("client", record.client_id, record)

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
        async with self._lock:
            self._put_locked("access-token", access_token, access_record)
            self._put_locked("refresh-token", refresh_token, refresh_record)

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
        async with self._lock:
            lookup, old_record = self._get_locked(
                "refresh-token", old_refresh_token, RefreshTokenRecord
            )
            self._records.pop(lookup, None)
            if old_record.access_token:
                for candidate in self._lookup_candidates("access-token", old_record.access_token):
                    self._records.pop(candidate, None)
            self._put_locked("refresh-token", new_refresh_token, new_refresh_record)
            self._put_locked("access-token", new_access_token, new_access_record)
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
        async with self._lock:
            for kind, token in (
                ("access-token", access_token),
                ("refresh-token", refresh_token),
            ):
                if token:
                    for lookup in self._lookup_candidates(kind, token):
                        self._records.pop(lookup, None)

    async def put_downstream(self, principal_id: str, record: DownstreamCredentialRecord) -> None:
        _validate_downstream_record(principal_id, record)
        async with self._lock:
            self._put_downstream_locked(principal_id, record)

    def _put_downstream_locked(self, principal_id: str, record: DownstreamCredentialRecord) -> None:
        self._put_locked("downstream", principal_id, record)
        self._delete_refresh_schedule_locked(principal_id)
        if record.refresh_token and record.refresh_after is not None:
            member = self._lookup_candidates(_DOWNSTREAM_REFRESH_KIND, principal_id)[0]
            locator = _DownstreamRefreshLocator(
                principal_id=principal_id, expires_at=record.expires_at
            )
            self._records[member] = _StoredRecord(
                kind=_DOWNSTREAM_REFRESH_KIND,
                encrypted=self._codec.encrypt(
                    _DOWNSTREAM_REFRESH_KIND, member, locator.model_dump_json().encode()
                ),
                expires_at=record.expires_at,
                scheduled_at=record.refresh_after,
            )

    async def get_downstream(self, principal_id: str) -> DownstreamCredentialRecord:
        return await self._get("downstream", principal_id, DownstreamCredentialRecord)

    async def delete_downstream(self, principal_id: str) -> None:
        async with self._lock:
            self._delete_downstream_locked(principal_id)

    def _delete_downstream_locked(self, principal_id: str) -> None:
        for lookup in self._lookup_candidates("downstream", principal_id):
            self._records.pop(lookup, None)
        self._delete_refresh_schedule_locked(principal_id)

    async def replace_downstream(
        self,
        principal_id: str,
        expected: DownstreamCredentialRecord,
        replacement: DownstreamCredentialRecord,
    ) -> bool:
        """Replace only the expected current grant; a revoked grant is never recreated."""
        _validate_downstream_record(principal_id, replacement)
        async with self._lock:
            if not self._matches_downstream_locked(principal_id, expected):
                return False
            self._put_downstream_locked(principal_id, replacement)
            return True

    async def delete_downstream_if_current(
        self, principal_id: str, expected: DownstreamCredentialRecord
    ) -> bool:
        """Delete only the expected current grant, preserving any newer authorization."""
        async with self._lock:
            if not self._matches_downstream_locked(principal_id, expected):
                return False
            self._delete_downstream_locked(principal_id)
            return True

    def _matches_downstream_locked(
        self, principal_id: str, expected: DownstreamCredentialRecord
    ) -> bool:
        try:
            return (
                self._get_locked("downstream", principal_id, DownstreamCredentialRecord)[1]
                == expected
            )
        except TokenStoreMiss:
            return False

    def _delete_refresh_schedule_locked(self, principal_id: str) -> None:
        for member in self._lookup_candidates(_DOWNSTREAM_REFRESH_KIND, principal_id):
            self._records.pop(member, None)

    async def list_due_downstream(self, *, limit: int = 100) -> list[str]:
        """Atomically lease due refresh jobs for 300 seconds; cap each claim at 1,000."""
        limit = min(max(limit, 0), _MAX_REFRESH_CLAIM_LIMIT)
        async with self._lock:
            if self._closed:
                raise TokenStoreMiss()
            now = self._clock()
            due = sorted(
                (
                    (raw.scheduled_at, member, raw)
                    for member, raw in self._records.items()
                    if isinstance(raw, _StoredRecord)
                    and raw.kind == _DOWNSTREAM_REFRESH_KIND
                    and raw.scheduled_at is not None
                    and raw.scheduled_at <= now
                ),
                key=lambda item: (item[0], item[1]),
            )[:limit]
            principals: list[str] = []
            for _, member, raw in due:
                try:
                    if raw.expires_at is not None and raw.expires_at <= now:
                        raise TokenStoreMiss()
                    locator = _DownstreamRefreshLocator.model_validate_json(
                        self._codec.decrypt(_DOWNSTREAM_REFRESH_KIND, member, raw.encrypted)
                    )
                    if member not in self._lookup_candidates(
                        _DOWNSTREAM_REFRESH_KIND, locator.principal_id
                    ):
                        raise TokenStoreMiss()
                    record = self._get_locked(
                        "downstream", locator.principal_id, DownstreamCredentialRecord
                    )[1]
                    if not record.refresh_token or record.refresh_after is None:
                        raise TokenStoreMiss()
                except (TokenStoreMiss, ValueError, TypeError):
                    self._records.pop(member, None)
                    continue
                self._records[member] = replace(raw, scheduled_at=now + _REFRESH_CLAIM_SECONDS)
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
        async with self._lock:
            if self._closed:
                return
            self._closed = True
            self._records.clear()
