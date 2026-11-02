import asyncio
from dataclasses import replace

import pytest

from yandex_workspace_mcp.auth.models import DownstreamCredentialRecord
from yandex_workspace_mcp.auth.stores import InMemoryTokenStore, TokenStoreMiss, _StoredRecord
from yandex_workspace_mcp.models.errors import ConfigurationError


def credential(principal_id: str = "synthetic-account", **changes) -> DownstreamCredentialRecord:
    return DownstreamCredentialRecord(
        **{
            "principal_id": principal_id,
            "access_token": "synthetic-access-secret",
            "refresh_token": "synthetic-refresh-secret",
            "refresh_after": 100.0,
            **changes,
        }
    )


@pytest.mark.asyncio
async def test_refresh_claim_waits_until_due_and_retries_after_lease() -> None:
    now = [99.0]
    store = InMemoryTokenStore((b"k" * 32,), clock=lambda: now[0])
    await store.put_downstream("synthetic-account", credential())
    assert await store.list_due_downstream() == []
    now[0] = 100.0
    assert await store.list_due_downstream() == ["synthetic-account"]
    assert await store.list_due_downstream() == []
    now[0] = 399.999
    assert await store.list_due_downstream() == []
    now[0] = 400.0
    assert await store.list_due_downstream() == ["synthetic-account"]
    assert (await store.get_downstream("synthetic-account")).refresh_token


@pytest.mark.asyncio
async def test_successful_refresh_reschedules_and_can_survive_long_inactivity() -> None:
    now = [100.0]
    store = InMemoryTokenStore((b"k" * 32,), clock=lambda: now[0])
    await store.put_downstream("synthetic-account", credential())
    assert await store.list_due_downstream() == ["synthetic-account"]
    refreshed = credential(access_token="synthetic-updated-access", refresh_after=1000.0)
    await store.put_downstream("synthetic-account", refreshed)
    now[0] = 400.0
    assert await store.list_due_downstream() == []
    now[0] = 1000.0
    assert await store.list_due_downstream() == ["synthetic-account"]
    now[0] += 400 * 24 * 3600
    assert await store.get_downstream("synthetic-account") == refreshed
    assert await store.list_due_downstream() == ["synthetic-account"]


@pytest.mark.asyncio
async def test_refresh_claim_is_atomic_and_honors_limit() -> None:
    store = InMemoryTokenStore((b"k" * 32,), clock=lambda: 100.0)
    await store.put_downstream("synthetic-account", credential())
    claims = await asyncio.gather(*[store.list_due_downstream() for _ in range(8)])
    assert sum(claim == ["synthetic-account"] for claim in claims) == 1
    assert sum(claim == [] for claim in claims) == 7
    for index in range(3):
        principal = f"synthetic-account-{index}"
        await store.put_downstream(principal, credential(principal))
    assert await store.list_due_downstream(limit=0) == []
    assert await store.list_due_downstream(limit=-1) == []
    assert len(await store.list_due_downstream(limit=2)) == 2
    assert len(await store.list_due_downstream(limit=2)) == 1


@pytest.mark.asyncio
async def test_refresh_claim_batch_size_is_bounded() -> None:
    store = InMemoryTokenStore((b"k" * 32,), clock=lambda: 100.0)
    for index in range(1001):
        principal = f"synthetic-account-{index}"
        await store.put_downstream(principal, credential(principal))
    assert len(await store.list_due_downstream(limit=100_000)) == 1000
    assert len(await store.list_due_downstream()) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("changes", [{"refresh_token": None}, {"refresh_after": None}])
async def test_unschedulable_grant_removes_existing_job(changes) -> None:
    records: dict[str, object] = {}
    store = InMemoryTokenStore((b"k" * 32,), records=records, clock=lambda: 100.0)
    await store.put_downstream("synthetic-account", credential())
    await store.put_downstream("synthetic-account", credential(**changes))
    assert await store.list_due_downstream() == []
    assert len(records) == 1


@pytest.mark.asyncio
async def test_delete_removes_credential_and_encrypted_locator() -> None:
    records: dict[str, object] = {}
    store = InMemoryTokenStore((b"k" * 32,), records=records, clock=lambda: 100.0)
    await store.put_downstream("synthetic-account", credential())
    assert len(records) == 2
    await store.delete_downstream("synthetic-account")
    assert records == {}
    assert await store.list_due_downstream() == []
    with pytest.raises(TokenStoreMiss):
        await store.get_downstream("synthetic-account")


@pytest.mark.asyncio
async def test_refresh_locator_is_encrypted_and_survives_key_rotation() -> None:
    records: dict[str, object] = {}
    old = InMemoryTokenStore((b"o" * 32,), records=records, clock=lambda: 100.0)
    await old.put_downstream("synthetic-account", credential())
    for secret in ("synthetic-account", "synthetic-access-secret", "synthetic-refresh-secret"):
        assert secret not in repr(records)
    old_members = set(records)
    rotated = InMemoryTokenStore((b"n" * 32, b"o" * 32), records=records, clock=lambda: 100.0)
    assert await rotated.list_due_downstream() == ["synthetic-account"]
    await rotated.put_downstream("synthetic-account", credential(refresh_after=500.0))
    assert not old_members.intersection(records)
    assert len(records) == 2
    assert await rotated.list_due_downstream() == []
    await rotated.delete_downstream("synthetic-account")
    assert records == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["expired", "missing-grant", "invalid-locator"])
async def test_unusable_refresh_jobs_are_removed(failure: str) -> None:
    now = [100.0]
    records: dict[str, object] = {}
    store = InMemoryTokenStore((b"k" * 32,), records=records, clock=lambda: now[0])
    await store.put_downstream("synthetic-account", credential(expires_at=200.0))
    member = store._lookup_candidates("downstream-refresh", "synthetic-account")[0]
    if failure == "expired":
        now[0] = 200.0
    elif failure == "missing-grant":
        records.pop(store._lookup_candidates("downstream", "synthetic-account")[0])
    else:
        raw = records[member]
        assert isinstance(raw, _StoredRecord)
        records[member] = replace(raw, encrypted=replace(raw.encrypted, ciphertext="broken"))
    assert await store.list_due_downstream() == []
    assert member not in records
    assert await store.list_due_downstream() == []


@pytest.mark.asyncio
async def test_locator_ciphertext_cannot_be_swapped_between_members() -> None:
    records: dict[str, object] = {}
    store = InMemoryTokenStore((b"k" * 32,), records=records, clock=lambda: 100.0)
    for principal in ("synthetic-a", "synthetic-b"):
        await store.put_downstream(principal, credential(principal))
    first, second = (
        store._lookup_candidates("downstream-refresh", principal)[0]
        for principal in ("synthetic-a", "synthetic-b")
    )
    first_record, second_record = records[first], records[second]
    assert isinstance(first_record, _StoredRecord)
    assert isinstance(second_record, _StoredRecord)
    records[first] = replace(first_record, encrypted=second_record.encrypted)
    assert await store.list_due_downstream() == ["synthetic-b"]
    assert first not in records


@pytest.mark.asyncio
@pytest.mark.parametrize("refresh_after", [float("inf"), float("nan")])
async def test_invalid_schedule_does_not_replace_existing_grant(refresh_after: float) -> None:
    store = InMemoryTokenStore((b"k" * 32,), clock=lambda: 100.0)
    original = credential()
    await store.put_downstream("synthetic-account", original)
    with pytest.raises(ConfigurationError, match="finite"):
        await store.put_downstream("synthetic-account", credential(refresh_after=refresh_after))
    assert await store.get_downstream("synthetic-account") == original


@pytest.mark.asyncio
async def test_conditional_refresh_mutations_update_schedule_and_preserve_newer_grants() -> None:
    records: dict[str, object] = {}
    store = InMemoryTokenStore((b"k" * 32,), records=records, clock=lambda: 100.0)
    original = credential()
    refreshed = credential(access_token="synthetic-new-access", refresh_after=1000.0)
    await store.put_downstream(original.principal_id, original)
    assert await store.replace_downstream(original.principal_id, original.model_copy(), refreshed)
    assert await store.list_due_downstream() == []
    assert not await store.replace_downstream(original.principal_id, original, credential())
    assert not await store.delete_downstream_if_current(original.principal_id, original)
    assert await store.get_downstream(original.principal_id) == refreshed
    assert await store.delete_downstream_if_current(original.principal_id, refreshed)
    assert records == {}
    assert not await store.replace_downstream(original.principal_id, refreshed, original)
    assert not await store.delete_downstream_if_current(original.principal_id, refreshed)
    assert records == {}


@pytest.mark.asyncio
async def test_concurrent_refresh_replacements_have_one_winner_and_cannot_revive_revocation() -> (
    None
):
    records: dict[str, object] = {}
    store = InMemoryTokenStore((b"k" * 32,), records=records, clock=lambda: 100.0)
    original = credential()
    await store.put_downstream(original.principal_id, original)
    replacements = [credential(access_token=f"synthetic-access-{index}") for index in range(8)]
    outcomes = await asyncio.gather(
        *[
            store.replace_downstream(original.principal_id, original, replacement)
            for replacement in replacements
        ]
    )
    assert sum(outcomes) == 1
    current = await store.get_downstream(original.principal_id)
    assert current == replacements[outcomes.index(True)]
    await store.delete_downstream(original.principal_id)
    assert not await store.replace_downstream(original.principal_id, current, original)
    assert records == {}


@pytest.mark.asyncio
async def test_conditional_refresh_mutations_support_rotated_keys() -> None:
    records: dict[str, object] = {}
    old = InMemoryTokenStore((b"o" * 32,), records=records, clock=lambda: 100.0)
    rotated = InMemoryTokenStore((b"n" * 32, b"o" * 32), records=records, clock=lambda: 100.0)
    original = credential()
    refreshed = credential(access_token="synthetic-new-access", refresh_after=1000.0)
    await old.put_downstream(original.principal_id, original)
    old_members = set(records)
    assert await rotated.replace_downstream(original.principal_id, original, refreshed)
    assert not old_members.intersection(records)
    assert not await rotated.delete_downstream_if_current(original.principal_id, original)
    assert await rotated.delete_downstream_if_current(original.principal_id, refreshed)
    assert records == {}
