from pathlib import Path

import pytest

from yandex_workspace_mcp.auth import client_migration
from yandex_workspace_mcp.auth.client_migration import LegacyClientValue, read_legacy_client_aof
from yandex_workspace_mcp.models.errors import ConfigurationError

PREFIX = "synthetic:disk:auth"
KEY = f"{PREFIX}:client:{'a' * 64}".encode()
SECOND_KEY = f"{PREFIX}:client:{'b' * 64}".encode()
LEGACY_KEY = f"synthetic:legacy:auth:client:{'a' * 64}".encode()
INTERMEDIATE_KEY = f"synthetic:intermediate:auth:client:{'a' * 64}".encode()
SOURCE_INDEX = f"{PREFIX}:registration-source:{'c' * 64}".encode()
PAYLOAD = b'{"ciphertext":"synthetic-encrypted-client"}'


def resp(*arguments: bytes | str | float) -> bytes:
    values = [value if isinstance(value, bytes) else str(value).encode() for value in arguments]
    return f"*{len(values)}\r\n".encode() + b"".join(
        f"${len(value)}\r\n".encode() + value + b"\r\n" for value in values
    )


def set_expiring(key: bytes = KEY, payload: bytes = PAYLOAD, expiry: int = 1234567) -> bytes:
    return resp("SET", key, payload, "PXAT", expiry)


def parse(tmp_path: Path, data: bytes, *, db: int = 0) -> dict[bytes, LegacyClientValue]:
    source = tmp_path / "synthetic.aof"
    source.write_bytes(data)
    result = read_legacy_client_aof(source, prefix=PREFIX, db=db)
    assert source.read_bytes() == data
    return result


def test_recovery_isolates_database_and_exact_hmac_namespace(tmp_path: Path) -> None:
    other_prefix = f"synthetic:mail:auth:client:{'a' * 64}".encode()
    data = b"".join(
        (
            set_expiring(KEY, b"wrong-db"),
            resp("SELECT", 2),
            set_expiring(KEY),
            set_expiring(other_prefix),
            set_expiring(KEY + b"extra"),
            set_expiring(KEY[:-1]),
            set_expiring(f"{PREFIX}:client:{'g' * 64}".encode()),
            set_expiring(f"{PREFIX}:access-token:{'a' * 64}".encode()),
            resp("SELECT", 3),
            set_expiring(KEY, b"another-wrong-db"),
        )
    )
    assert parse(tmp_path, data, db=2) == {KEY: LegacyClientValue(KEY, PAYLOAD, 1234.567)}


def test_last_set_wins_and_expiry_del_keeps_the_candidate(tmp_path: Path) -> None:
    data = (
        set_expiring(KEY, b"old-ciphertext")
        + resp("set", KEY, PAYLOAD, "pxat", 2000001)
        + resp("DEL", KEY)
    )
    assert parse(tmp_path, data) == {KEY: LegacyClientValue(KEY, PAYLOAD, 2000.001)}


@pytest.mark.parametrize(
    "replacement",
    [
        resp("SET", KEY, PAYLOAD),
        resp("SET", KEY, PAYLOAD, "EX", 300),
        resp("SET", KEY, PAYLOAD, "PXAT", 2000, "NX"),
        resp("PERSIST", KEY),
        resp("PEXPIREAT", KEY, 2000000),
        resp("UNLINK", KEY),
    ],
)
def test_other_writes_exclude_a_stale_expiring_value(tmp_path: Path, replacement: bytes) -> None:
    assert parse(tmp_path, set_expiring() + replacement) == {}


def test_committed_transaction_applies_select_and_writes_together(tmp_path: Path) -> None:
    data = (
        set_expiring(KEY, b"old-ciphertext")
        + resp("MULTI")
        + set_expiring(KEY, PAYLOAD)
        + resp("SELECT", 1)
        + set_expiring(SECOND_KEY)
        + resp("EXEC")
        + set_expiring(KEY, b"wrong-db")
    )
    assert parse(tmp_path, data) == {KEY: LegacyClientValue(KEY, PAYLOAD, 1234.567)}
    assert set(parse(tmp_path, data, db=1)) == {KEY, SECOND_KEY}


@pytest.mark.parametrize("ending", [b"", resp("DISCARD"), b"*1\r\n$4\r\nEX"])
def test_discarded_or_unfinished_transaction_never_changes_candidates(
    tmp_path: Path, ending: bytes
) -> None:
    data = set_expiring() + resp("MULTI") + resp("FLUSHALL") + set_expiring(SECOND_KEY) + ending
    assert parse(tmp_path, data) == {KEY: LegacyClientValue(KEY, PAYLOAD, 1234.567)}


def test_discard_also_discards_database_selection(tmp_path: Path) -> None:
    data = resp("MULTI") + resp("SELECT", 1) + resp("DISCARD") + set_expiring()
    assert parse(tmp_path, data) == {KEY: LegacyClientValue(KEY, PAYLOAD, 1234.567)}


@pytest.mark.parametrize(
    "tail",
    [
        b"*",
        b"*3\r\n$3\r\nSET\r\n$",
        set_expiring(SECOND_KEY)[:-1],
        set_expiring(SECOND_KEY)[:-5],
        b"#T",
        b"#TS:1234567",
    ],
)
def test_incomplete_final_command_is_ignored(tmp_path: Path, tail: bytes) -> None:
    assert parse(tmp_path, set_expiring() + tail) == {
        KEY: LegacyClientValue(KEY, PAYLOAD, 1234.567)
    }


def test_aof_timestamp_comments_are_ignored_at_command_boundaries(tmp_path: Path) -> None:
    data = (
        b"#TS:100\n"
        + resp("MULTI")
        + b"#TS:200\r\n"
        + set_expiring()
        + resp("EXEC")
        + b"#TS:300\r\n"
    )
    assert parse(tmp_path, data) == {KEY: LegacyClientValue(KEY, PAYLOAD, 1234.567)}


@pytest.mark.parametrize("command", ["RENAME", "RENAMENX"])
def test_ambiguous_renames_exclude_both_targeted_keys(tmp_path: Path, command: str) -> None:
    data = set_expiring() + set_expiring(SECOND_KEY) + resp(command, KEY, SECOND_KEY)
    assert parse(tmp_path, data) == {}
    # A later unambiguous SET provides a new candidate.
    assert set(parse(tmp_path, data + set_expiring())) == {KEY}


def test_known_legacy_copy_survives_expiry_del_and_registration_index_write(tmp_path: Path) -> None:
    data = (
        set_expiring(LEGACY_KEY)
        + resp("MULTI")
        + resp("COPY", LEGACY_KEY, KEY, "REPLACE")
        + resp("ZADD", SOURCE_INDEX, 1234.567, KEY)
        + resp("EXEC")
        + resp("DEL", KEY, LEGACY_KEY)
    )
    assert parse(tmp_path, data) == {KEY: LegacyClientValue(KEY, PAYLOAD, 1234.567)}


def test_registration_transaction_does_not_treat_zadd_member_as_a_key(tmp_path: Path) -> None:
    data = (
        resp("MULTI")
        + resp("DEL", KEY)
        + set_expiring()
        + resp("ZADD", SOURCE_INDEX, 1234.567, KEY)
        + resp("EXEC")
        + resp("DEL", KEY)
    )
    assert parse(tmp_path, data) == {KEY: LegacyClientValue(KEY, PAYLOAD, 1234.567)}


@pytest.mark.parametrize(
    "index_command",
    [
        resp("ZADD", SOURCE_INDEX, 1234.567, LEGACY_KEY),
        resp("ZREM", SOURCE_INDEX, LEGACY_KEY),
        resp("ZREMRANGEBYSCORE", SOURCE_INDEX, "-inf", LEGACY_KEY),
        resp("HSET", b"synthetic:hash", b"field", LEGACY_KEY),
        resp("LPUSH", b"synthetic:list", LEGACY_KEY),
        resp("SADD", b"synthetic:set", LEGACY_KEY),
        resp("MSET", b"synthetic:string", LEGACY_KEY),
        resp("XGROUP", "CREATE", b"synthetic:stream", LEGACY_KEY, "$"),
    ],
)
def test_known_data_operands_do_not_invalidate_client_values(
    tmp_path: Path, index_command: bytes
) -> None:
    data = set_expiring(LEGACY_KEY) + index_command + resp("COPY", LEGACY_KEY, KEY)
    assert parse(tmp_path, data) == {KEY: LegacyClientValue(KEY, PAYLOAD, 1234.567)}


@pytest.mark.parametrize(
    "mutation",
    [
        resp("ZADD", LEGACY_KEY, 1, b"synthetic-member"),
        resp("ZREM", LEGACY_KEY, b"synthetic-member"),
        resp("ZREMRANGEBYSCORE", LEGACY_KEY, "-inf", "+inf"),
        resp("HSET", LEGACY_KEY, b"field", b"value"),
        resp("MSET", LEGACY_KEY, b"value"),
    ],
)
def test_a_client_key_used_as_another_data_type_is_excluded_from_known_values(
    tmp_path: Path, mutation: bytes
) -> None:
    data = set_expiring(LEGACY_KEY) + mutation + resp("COPY", LEGACY_KEY, KEY)
    assert parse(tmp_path, data) == {}


def test_known_copies_can_form_a_chain_without_removing_the_source(tmp_path: Path) -> None:
    data = (
        set_expiring(LEGACY_KEY)
        + resp("COPY", LEGACY_KEY, INTERMEDIATE_KEY)
        + resp("DEL", LEGACY_KEY)
        + resp("COPY", INTERMEDIATE_KEY, KEY)
    )
    assert parse(tmp_path, data) == {KEY: LegacyClientValue(KEY, PAYLOAD, 1234.567)}


def test_copy_with_different_hmac_excludes_destination_and_preserves_source(tmp_path: Path) -> None:
    data = set_expiring() + set_expiring(SECOND_KEY) + resp("COPY", KEY, SECOND_KEY, "REPLACE")
    assert parse(tmp_path, data) == {KEY: LegacyClientValue(KEY, PAYLOAD, 1234.567)}


@pytest.mark.parametrize(
    "source_history",
    [
        b"",
        set_expiring(LEGACY_KEY) + resp("DEL", LEGACY_KEY),
        set_expiring(LEGACY_KEY) + resp("SET", LEGACY_KEY, PAYLOAD),
        resp("SELECT", 1) + set_expiring(LEGACY_KEY) + resp("SELECT", 0),
    ],
)
def test_unknown_or_no_longer_live_copy_source_excludes_destination(
    tmp_path: Path, source_history: bytes
) -> None:
    data = set_expiring() + source_history + resp("COPY", LEGACY_KEY, KEY, "REPLACE")
    assert parse(tmp_path, data) == {}


def test_known_cross_database_copy_preserves_payload_and_absolute_expiry(tmp_path: Path) -> None:
    data = resp("SELECT", 1) + set_expiring(LEGACY_KEY) + resp("COPY", LEGACY_KEY, KEY, "DB", 0)
    assert parse(tmp_path, data) == {KEY: LegacyClientValue(KEY, PAYLOAD, 1234.567)}
    assert parse(tmp_path, data, db=2) == {}


def test_copy_into_another_database_does_not_replace_current_database_candidate(
    tmp_path: Path,
) -> None:
    data = (
        set_expiring(KEY, b"synthetic-original")
        + set_expiring(LEGACY_KEY)
        + resp("COPY", LEGACY_KEY, KEY, "DB", 1)
    )
    assert parse(tmp_path, data) == {KEY: LegacyClientValue(KEY, b"synthetic-original", 1234.567)}
    assert parse(tmp_path, data, db=1) == {KEY: LegacyClientValue(KEY, PAYLOAD, 1234.567)}


@pytest.mark.parametrize(
    "mutation",
    [
        resp("RENAME", LEGACY_KEY, INTERMEDIATE_KEY),
        resp("RENAMENX", LEGACY_KEY, INTERMEDIATE_KEY),
        resp("MOVE", LEGACY_KEY, 1),
        resp("FLUSHDB"),
        resp("FLUSHALL"),
        resp("SWAPDB", 0, 1),
    ],
)
def test_ambiguous_moves_and_flushes_never_leave_stale_known_sources(
    tmp_path: Path, mutation: bytes
) -> None:
    data = set_expiring(LEGACY_KEY) + mutation + resp("COPY", LEGACY_KEY, KEY)
    assert parse(tmp_path, data) == {}


def test_discarded_transaction_does_not_populate_known_copy_sources(tmp_path: Path) -> None:
    data = (
        resp("MULTI") + set_expiring(LEGACY_KEY) + resp("DISCARD") + resp("COPY", LEGACY_KEY, KEY)
    )
    assert parse(tmp_path, data) == {}


@pytest.mark.parametrize(
    "mutation",
    [
        resp("MOVE", KEY, 0),
        resp("COPY", b"outside-namespace", KEY, "DB", 0, "REPLACE"),
    ],
)
def test_cross_database_moves_or_copies_into_target_db_exclude_candidates(
    tmp_path: Path, mutation: bytes
) -> None:
    assert parse(tmp_path, set_expiring() + resp("SELECT", 1) + mutation) == {}


def test_ambiguous_operations_in_another_database_are_isolated(tmp_path: Path) -> None:
    data = (
        set_expiring()
        + resp("SELECT", 1)
        + resp("RENAME", KEY, SECOND_KEY)
        + resp("COPY", KEY, SECOND_KEY, "DB", 2)
        + resp("MOVE", KEY, 2)
        + resp("FLUSHDB")
    )
    assert parse(tmp_path, data) == {KEY: LegacyClientValue(KEY, PAYLOAD, 1234.567)}


@pytest.mark.parametrize("flush", [resp("FLUSHDB"), resp("FLUSHALL", "ASYNC")])
def test_flush_commands_remove_prior_candidates(tmp_path: Path, flush: bytes) -> None:
    assert parse(tmp_path, set_expiring() + flush) == {}


def test_flushall_removes_candidates_from_any_selected_database(tmp_path: Path) -> None:
    assert parse(tmp_path, set_expiring() + resp("SELECT", 2) + resp("FLUSHALL")) == {}


def test_swapping_target_database_excludes_prior_candidates(tmp_path: Path) -> None:
    assert parse(tmp_path, set_expiring() + resp("SWAPDB", 0, 1)) == {}
    assert set(parse(tmp_path, set_expiring() + resp("SWAPDB", 1, 2))) == {KEY}


def test_bulk_payload_is_opaque_binary_data(tmp_path: Path) -> None:
    payload = b"\x00\xff\r\n*1\r\n$8\r\nFLUSHALL\r\n#TS:100\n"
    assert parse(tmp_path, set_expiring(payload=payload)) == {
        KEY: LegacyClientValue(KEY, payload, 1234.567)
    }


@pytest.mark.parametrize(
    "bad_data",
    [
        b"not-resp-synthetic-secret",
        b"*1\n$4\r\nPING\r\n",
        b"*-1\r\n",
        b"*0\r\n",
        b"*1\r\n$-1\r\n",
        b"*1\r\n+PING\r\n",
        b"*1\r\n$4\r\nPINGxx",
        b"#unsupported-comment\r\n",
        resp("SELECT", "not-a-database"),
        resp("SET", KEY, PAYLOAD, "PXAT", "invalid-expiry"),
        resp("EXEC"),
        resp("MULTI") + resp("MULTI"),
        resp("COPY", KEY, SECOND_KEY, "DB"),
    ],
)
def test_invalid_input_raises_only_a_fixed_safe_error(tmp_path: Path, bad_data: bytes) -> None:
    with pytest.raises(ConfigurationError) as error:
        parse(tmp_path, set_expiring() + bad_data)
    assert str(error.value) == "Legacy OAuth client migration source is invalid."
    assert "synthetic" not in str(error.value)
    assert error.value.__suppress_context__


def test_snapshot_size_limit_is_enforced(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(client_migration, "_MAX_AOF_BYTES", 32)
    with pytest.raises(ConfigurationError, match="source is invalid"):
        parse(tmp_path, b"x" * 33)


def test_bulk_and_array_limits_reject_declared_oversize_even_in_a_truncated_tail(
    tmp_path: Path,
) -> None:
    for data in (
        f"*1\r\n${1024 * 1024 + 1}\r\n".encode(),
        b"*10001\r\n",
    ):
        with pytest.raises(ConfigurationError, match="source is invalid"):
            parse(tmp_path, data)


def test_record_limit_counts_ignored_databases_and_namespaces(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(client_migration, "_MAX_RECORDS", 2)
    with pytest.raises(ConfigurationError, match="source is invalid"):
        parse(tmp_path, resp("SELECT", 2) + resp("PING") + resp("PING"))


def test_unreadable_source_has_no_path_in_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError) as error:
        read_legacy_client_aof(tmp_path / "synthetic-private-name.aof", prefix=PREFIX, db=0)
    assert str(error.value) == "Legacy OAuth client migration source is invalid."


def test_values_hide_payload_and_key_from_representation() -> None:
    value = LegacyClientValue(KEY, PAYLOAD, 1234.567)
    assert "synthetic" not in repr(value)
    with pytest.raises(AttributeError):
        value.expires_at = 1.0  # type: ignore[misc]
