"""Bounded, read-only recovery of encrypted OAuth clients from a Redis AOF."""

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..models.errors import ConfigurationError

_MAX_AOF_BYTES = 64 * 1024 * 1024
_MAX_BULK_BYTES = 1024 * 1024
_MAX_RECORDS = 10_000
_MAX_ARGUMENTS = 10_000
_SAFE_ERROR_MESSAGE = "Legacy OAuth client migration source is invalid."
_HEX_DIGEST = re.compile(rb"[0-9a-fA-F]{64}")
_SINGLE_KEY_MUTATIONS = frozenset(
    b"APPEND DECR DECRBY EXPIRE EXPIREAT GETDEL GETEX GETSET HDEL HINCRBY HINCRBYFLOAT "
    b"HMSET HSET HSETNX INCR INCRBY INCRBYFLOAT LINSERT LPOP LPUSH LPUSHX LREM LSET "
    b"LTRIM PERSIST PEXPIRE PEXPIREAT PSETEX RESTORE RPOP RPUSH RPUSHX SADD SDIFFSTORE "
    b"SETBIT SETEX SETRANGE SINTERSTORE SPOP SREM SUNIONSTORE XACK XADD XAUTOCLAIM "
    b"XCLAIM XDEL XSETID XTRIM "
    b"ZADD ZDIFFSTORE ZINCRBY ZINTERSTORE ZPOPMAX ZPOPMIN ZREM ZREMRANGEBYLEX "
    b"ZREMRANGEBYRANK ZREMRANGEBYSCORE ZUNIONSTORE".split()
)


@dataclass(frozen=True, slots=True)
class LegacyClientValue:
    """An opaque encrypted client value and its original expiry, or None for no TTL."""

    redis_key: bytes = field(repr=False)
    payload: bytes = field(repr=False)
    expires_at: float | None


class _InvalidAof(Exception):
    pass


class _IncompleteTail(Exception):
    pass


def _unsigned_decimal(value: bytes) -> int:
    if not value or len(value) > 20 or not value.isdigit():
        raise _InvalidAof()
    return int(value)


def _read_length(data: bytes, position: int, marker: bytes) -> tuple[int, int]:
    if position == len(data):
        raise _IncompleteTail()
    if data[position : position + 1] != marker:
        raise _InvalidAof()
    position += 1
    end = data.find(b"\r\n", position, position + 22)
    if end < 0:
        tail = data[position:]
        if tail.endswith(b"\r"):
            tail = tail[:-1]
        if len(tail) > 20 or (tail and not tail.isdigit()):
            raise _InvalidAof()
        raise _IncompleteTail()
    return _unsigned_decimal(data[position:end]), end + 2


def _read_command(data: bytes, position: int) -> tuple[tuple[bytes, ...], int]:
    count, position = _read_length(data, position, b"*")
    if not 1 <= count <= _MAX_ARGUMENTS:
        raise _InvalidAof()
    arguments: list[bytes] = []
    for _ in range(count):
        length, position = _read_length(data, position, b"$")
        if length > _MAX_BULK_BYTES:
            raise _InvalidAof()
        end = position + length
        if end + 2 > len(data):
            if end <= len(data) and not b"\r\n".startswith(data[end:]):
                raise _InvalidAof()
            raise _IncompleteTail()
        if data[end : end + 2] != b"\r\n":
            raise _InvalidAof()
        arguments.append(data[position:end])
        position = end + 2
    if not arguments[0]:
        raise _InvalidAof()
    return tuple(arguments), position


class _ClientReplay:
    def __init__(self, prefix: str, db: int, *, include_permanent: bool = False) -> None:
        self.namespace = prefix.encode() + b":client:"
        self.target_db = db
        self.current_db = 0
        self.include_permanent = include_permanent
        self.clients: dict[bytes, LegacyClientValue] = {}
        self.known: dict[tuple[int, bytes], LegacyClientValue] = {}

    @staticmethod
    def _client_digest(key: bytes) -> bytes | None:
        namespace, separator, digest = key.rpartition(b":client:")
        if namespace and separator and _HEX_DIGEST.fullmatch(digest):
            return digest
        return None

    def _is_client_key(self, key: bytes) -> bool:
        return key.startswith(self.namespace) and bool(
            _HEX_DIGEST.fullmatch(key[len(self.namespace) :])
        )

    def _exclude(self, keys: tuple[bytes, ...], *, db: int | None = None) -> None:
        database = self.current_db if db is None else db
        for key in keys:
            self.known.pop((database, key), None)
            if database == self.target_db and self._is_client_key(key):
                self.clients.pop(key, None)

    def _flush_databases(self, databases: set[int]) -> None:
        self.known = {key: value for key, value in self.known.items() if key[0] not in databases}
        if self.target_db in databases:
            self.clients.clear()

    def apply(self, arguments: tuple[bytes, ...]) -> None:
        command = arguments[0].upper()
        if command == b"SELECT":
            if len(arguments) != 2:
                raise _InvalidAof()
            self.current_db = _unsigned_decimal(arguments[1])
            return
        if command in {b"FLUSHALL", b"FLUSHDB"}:
            if len(arguments) > 2 or (
                len(arguments) == 2 and arguments[1].upper() not in {b"SYNC", b"ASYNC"}
            ):
                raise _InvalidAof()
            if command == b"FLUSHALL":
                self.clients.clear()
                self.known.clear()
            else:
                self._flush_databases({self.current_db})
            return
        if command == b"SWAPDB":
            if len(arguments) != 3:
                raise _InvalidAof()
            databases = {_unsigned_decimal(value) for value in arguments[1:]}
            self._flush_databases(databases)
            return
        if command == b"MOVE":
            if len(arguments) != 3:
                raise _InvalidAof()
            destination_db = _unsigned_decimal(arguments[2])
            self._exclude(arguments[1:2])
            self._exclude(arguments[1:2], db=destination_db)
            return
        if command == b"COPY":
            if len(arguments) < 3:
                raise _InvalidAof()
            destination_db = self.current_db
            options = arguments[3:]
            seen: set[bytes] = set()
            while options:
                option = options[0].upper()
                if option in seen:
                    raise _InvalidAof()
                seen.add(option)
                if option == b"DB" and len(options) >= 2:
                    destination_db = _unsigned_decimal(options[1])
                    options = options[2:]
                elif option == b"REPLACE":
                    options = options[1:]
                else:
                    raise _InvalidAof()
            source, destination = arguments[1:3]
            known = self.known.get((self.current_db, source))
            source_digest = self._client_digest(source)
            destination_digest = self._client_digest(destination)
            self._exclude((destination,), db=destination_db)
            if (
                known is not None
                and source_digest is not None
                and source_digest == destination_digest
            ):
                copied = LegacyClientValue(destination, known.payload, known.expires_at)
                self.known[(destination_db, destination)] = copied
                if destination_db == self.target_db and self._is_client_key(destination):
                    self.clients[destination] = copied
            return
        if command in {b"RENAME", b"RENAMENX"} and len(arguments) != 3:
            raise _InvalidAof()
        if command == b"DEL":
            if len(arguments) < 2:
                raise _InvalidAof()
            # Redis emits DEL on expiry; candidate eligibility is checked separately by the caller.
            for key in arguments[1:]:
                self.known.pop((self.current_db, key), None)
            return
        if command == b"SET":
            if len(arguments) < 3:
                raise _InvalidAof()
            key = arguments[1]
            expires_at = None
            if len(arguments) == 5 and arguments[3].upper() == b"PXAT":
                expires_at = _unsigned_decimal(arguments[4]) / 1000
            self._exclude((key,))
            permanent = self.include_permanent and len(arguments) == 3
            if (expires_at is not None or permanent) and self._client_digest(key) is not None:
                value = LegacyClientValue(key, arguments[2], expires_at)
                self.known[(self.current_db, key)] = value
                if self.current_db == self.target_db and self._is_client_key(key):
                    self.clients[key] = value
            return
        if command in _SINGLE_KEY_MUTATIONS:
            if len(arguments) < 2:
                raise _InvalidAof()
            self._exclude(arguments[1:2])
            return
        if command in {b"MSET", b"MSETNX"}:
            if len(arguments) < 3 or len(arguments) % 2 != 1:
                raise _InvalidAof()
            self._exclude(arguments[1::2])
            return
        if command in {b"SMOVE", b"LMOVE", b"BLMOVE", b"RPOPLPUSH", b"BRPOPLPUSH"}:
            if len(arguments) < 3:
                raise _InvalidAof()
            self._exclude(arguments[1:3])
            return
        if command == b"BITOP":
            if len(arguments) < 4:
                raise _InvalidAof()
            self._exclude(arguments[2:3])
            return
        if command == b"XGROUP":
            if len(arguments) < 3:
                raise _InvalidAof()
            self._exclude(arguments[2:3])
            return
        # Unknown writes and ambiguous moves must never leave a stale recovery candidate.
        self._exclude(arguments[1:])


def read_legacy_client_aof(
    path: Path, *, prefix: str, db: int, include_permanent: bool = False
) -> dict[bytes, LegacyClientValue]:
    """Read at most 64 MiB/10,000 commands, recovering SET PXAT values and exact known copies.

    Bulk strings are capped at 1 MiB. A truncated final command and any unfinished
    transaction are ignored. This parser never connects to Redis or changes the source file;
    callers must separately verify candidate eligibility. Permanent SET values are included
    only when include_permanent=True, for recovery restricted by an explicit operator allowlist.
    """
    try:
        if not isinstance(db, int) or db < 0:
            raise _InvalidAof()
        with path.open("rb") as source:
            data = source.read(_MAX_AOF_BYTES + 1)
        if len(data) > _MAX_AOF_BYTES:
            raise _InvalidAof()
        replay = _ClientReplay(prefix, db, include_permanent=include_permanent)
        pending: list[tuple[bytes, ...]] | None = None
        position = 0
        count = 0
        while position < len(data):
            if data[position : position + 1] == b"#":
                end = data.find(b"\n", position)
                if end < 0:
                    tail = data[position:]
                    if tail.endswith(b"\r"):
                        tail = tail[:-1]
                    if b"#TS:".startswith(tail):
                        break
                    if not tail.startswith(b"#TS:") or (
                        len(tail[4:]) > 20 or not tail[4:].isdigit()
                    ):
                        raise _InvalidAof()
                    break
                comment = data[position:end].removesuffix(b"\r")
                if not comment.startswith(b"#TS:"):
                    raise _InvalidAof()
                _unsigned_decimal(comment[4:])
                position = end + 1
                continue
            try:
                arguments, position = _read_command(data, position)
            except _IncompleteTail:
                break
            count += 1
            if count > _MAX_RECORDS:
                raise _InvalidAof()
            command = arguments[0].upper()
            if command in {b"MULTI", b"EXEC", b"DISCARD"}:
                if len(arguments) != 1:
                    raise _InvalidAof()
                if command == b"MULTI":
                    if pending is not None:
                        raise _InvalidAof()
                    pending = []
                else:
                    if pending is None:
                        raise _InvalidAof()
                    if command == b"EXEC":
                        for queued in pending:
                            replay.apply(queued)
                    pending = None
            elif pending is not None:
                pending.append(arguments)
            else:
                replay.apply(arguments)
        return replay.clients
    except (OSError, ValueError, _InvalidAof):
        raise ConfigurationError(_SAFE_ERROR_MESSAGE) from None
