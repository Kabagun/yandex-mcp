import asyncio
import base64
import os
import uuid

import pytest

from yandex_workspace_mcp.auth.models import (
    AccessTokenRecord,
    AuthorizationCodeRecord,
    DownstreamCredentialRecord,
    OAuthStateRecord,
    RefreshTokenRecord,
)
from yandex_workspace_mcp.auth.recovery import SharedRecoveryTokenStore
from yandex_workspace_mcp.auth.stores import TokenStoreMiss
from yandex_workspace_mcp.models.errors import ResourceNotFound

REDIS_URL = os.getenv("TEST_REDIS_URL")
pytestmark = pytest.mark.skipif(
    not REDIS_URL, reason="TEST_REDIS_URL is not configured; Redis contract test is opt-in"
)


@pytest.mark.asyncio
async def test_redis_state_is_encrypted_and_single_use() -> None:
    pytest.importorskip("redis")
    from yandex_workspace_mcp.auth.redis_store import RedisTokenStore

    key = base64.urlsafe_b64decode(base64.urlsafe_b64encode(b"r" * 32))
    store = RedisTokenStore((key,), url=REDIS_URL, prefix=f"ywmcp:test:{uuid.uuid4().hex}")
    await store.open()
    record = OAuthStateRecord(
        client_id="client",
        redirect_uri="http://127.0.0.1/callback",
        scopes=("workspace:read",),
        code_challenge="challenge",
        resource=None,
        expires_at=store._clock() + 30,
    )
    try:
        await store.put_state("state-secret", record)
        assert await store.consume_state("state-secret") == record
        with pytest.raises(TokenStoreMiss):
            await store.consume_state("state-secret")
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_redis_codes_rotation_and_recovery_are_atomic_across_replicas() -> None:
    pytest.importorskip("redis")
    from yandex_workspace_mcp.auth.redis_store import RedisTokenStore

    prefix = f"ywmcp:test:{uuid.uuid4().hex}"
    first = RedisTokenStore((b"r" * 32,), url=REDIS_URL, prefix=prefix, clock=lambda: 100.0)
    second = RedisTokenStore((b"r" * 32,), url=REDIS_URL, prefix=prefix, clock=lambda: 100.0)
    await first.open()
    await second.open()
    try:
        code = AuthorizationCodeRecord(
            client_id="client",
            redirect_uri="https://client.example/callback",
            scopes=("workspace:read",),
            code_challenge="challenge",
            resource="https://mcp.example",
            subject="principal",
            expires_at=200,
        )
        await first.put_authorization_code("code", code)
        code_results = await asyncio.gather(
            first.consume_authorization_code("code"),
            second.consume_authorization_code("code"),
            return_exceptions=True,
        )
        assert sum(result == code for result in code_results) == 1
        assert sum(isinstance(result, TokenStoreMiss) for result in code_results) == 1

        old_access = AccessTokenRecord(
            client_id="client",
            scopes=("workspace:read",),
            subject="principal",
            resource="https://mcp.example",
            expires_at=200,
            refresh_token="refresh-old",
        )
        old_refresh = RefreshTokenRecord(
            client_id="client",
            scopes=("workspace:read",),
            subject="principal",
            expires_at=300,
            access_token="access-old",
        )
        await first.put_token_pair(
            access_token="access-old",
            access_record=old_access,
            refresh_token="refresh-old",
            refresh_record=old_refresh,
        )
        new_access = old_access.model_copy(update={"refresh_token": "refresh-new"})
        new_refresh = old_refresh.model_copy(update={"access_token": "access-new"})
        rotations = await asyncio.gather(
            *[
                store.rotate_token_pair(
                    old_refresh_token="refresh-old",
                    new_refresh_token="refresh-new",
                    new_refresh_record=new_refresh,
                    new_access_token="access-new",
                    new_access_record=new_access,
                )
                for store in (first, second)
            ],
            return_exceptions=True,
        )
        assert sum(result == old_refresh for result in rotations) == 1
        assert sum(isinstance(result, TokenStoreMiss) for result in rotations) == 1
        with pytest.raises(TokenStoreMiss):
            await first.get_access_token("access-old")
        assert await second.get_access_token("access-new") == new_access

        recovery_a = SharedRecoveryTokenStore(first, clock=lambda: 100.0)
        recovery_b = SharedRecoveryTokenStore(second, clock=lambda: 100.0)
        handle = await recovery_a.put(
            upstream_token="upstream",
            principal_id="principal",
            normalized_locator="Team/Page",
        )
        with pytest.raises(ResourceNotFound):
            await recovery_b.consume(handle, principal_id="other")
        assert (
            await recovery_b.consume(handle, principal_id="principal")
        ).upstream_token == "upstream"
    finally:
        await first.close()
        await second.close()


@pytest.mark.asyncio
async def test_redis_key_rotation_reads_old_ciphertext() -> None:
    pytest.importorskip("redis")
    from yandex_workspace_mcp.auth.redis_store import RedisTokenStore

    prefix = f"ywmcp:test:{uuid.uuid4().hex}"
    old = RedisTokenStore((b"o" * 32,), url=REDIS_URL, prefix=prefix, clock=lambda: 100.0)
    rotated = RedisTokenStore(
        (b"n" * 32, b"o" * 32), url=REDIS_URL, prefix=prefix, clock=lambda: 100.0
    )
    await old.open()
    await rotated.open()
    state = OAuthStateRecord(
        client_id="client",
        redirect_uri="https://client.example/callback",
        scopes=("workspace:read",),
        code_challenge="challenge",
        resource=None,
        expires_at=200,
    )
    try:
        await old.put_state("state", state)
        assert await rotated.consume_state("state") == state
    finally:
        await old.close()
        await rotated.close()


@pytest.mark.asyncio
async def test_dedicated_profiles_isolate_every_record_kind_even_with_same_key() -> None:
    pytest.importorskip("redis")
    from yandex_workspace_mcp.auth.models import (
        DownstreamCredentialRecord,
        OAuthClientRecord,
        RecoveryHandleRecord,
    )
    from yandex_workspace_mcp.auth.redis_store import RedisTokenStore
    from yandex_workspace_mcp.config import Settings

    stores = []
    suffix = uuid.uuid4().hex
    for profile in ("disk", "mail"):
        settings = Settings(
            mcp_profile=profile,
            mcp_transport="streamable-http",
            mcp_auth_mode="multi-user",
            yandex_auth_mode="multi-user",
            yandex_oauth_client_id=f"{profile}-client",
            yandex_oauth_client_secret="test-secret",
            mcp_issuer_url=f"https://{profile}.example",
            mcp_oauth_callback_url=f"https://{profile}.example/oauth/yandex/callback",
        )
        stores.append(
            RedisTokenStore(
                (b"p" * 32,),
                url=REDIS_URL,
                prefix=f"{settings.auth_storage_prefix}:test:{suffix}",
            )
        )
    disk, mail = stores
    await disk.open()
    await mail.open()
    expiry = disk._clock() + 30
    try:
        await disk.put_client(
            OAuthClientRecord(
                client_id="shared",
                redirect_uris=("https://client.example/cb",),
                expires_at=expiry,
            )
        )
        await disk.put_state(
            "shared",
            OAuthStateRecord(
                client_id="shared",
                redirect_uri="https://client.example/cb",
                scopes=("workspace:read",),
                code_challenge="challenge",
                resource="https://disk.example/mcp",
                expires_at=expiry,
            ),
        )
        await disk.put_authorization_code(
            "shared",
            AuthorizationCodeRecord(
                client_id="shared",
                redirect_uri="https://client.example/cb",
                scopes=("workspace:read",),
                code_challenge="challenge",
                resource="https://disk.example/mcp",
                subject="shared",
                expires_at=expiry,
            ),
        )
        await disk.put_token_pair(
            access_token="shared",
            access_record=AccessTokenRecord(
                client_id="shared",
                scopes=("workspace:read",),
                subject="shared",
                resource="https://disk.example/mcp",
                expires_at=expiry,
                refresh_token="shared",
            ),
            refresh_token="shared",
            refresh_record=RefreshTokenRecord(
                client_id="shared",
                scopes=("workspace:read",),
                subject="shared",
                expires_at=expiry,
                access_token="shared",
            ),
        )
        await disk.put_downstream(
            "shared",
            DownstreamCredentialRecord(
                principal_id="shared",
                access_token="disk-secret",
                expires_at=expiry,
            ),
        )
        await disk.put_recovery(
            "shared",
            "shared",
            RecoveryHandleRecord(
                principal_id="shared",
                upstream_token="recovery-secret",
                normalized_locator="/item",
                expires_at=expiry,
            ),
        )
        for method in (
            "get_client",
            "consume_state",
            "get_authorization_code",
            "get_access_token",
            "get_refresh_token",
            "get_downstream",
        ):
            with pytest.raises(TokenStoreMiss):
                await getattr(mail, method)("shared")
        with pytest.raises(TokenStoreMiss):
            await mail.consume_recovery("shared", "shared")
        await mail.delete_downstream("shared")
        await mail.revoke_token_pair(access_token="shared", refresh_token="shared")
        assert (await disk.get_downstream("shared")).access_token == "disk-secret"
        assert (await disk.get_access_token("shared")).subject == "shared"
    finally:
        await disk.close()
        await mail.close()


async def _clear_test_prefix(store) -> None:
    keys = [key async for key in store._client.scan_iter(match=f"{store._prefix}:*")]
    if keys:
        await store._client.delete(*keys)


@pytest.mark.asyncio
async def test_redis_refresh_claims_are_shared_encrypted_and_isolated() -> None:
    pytest.importorskip("redis")
    from yandex_workspace_mcp.auth.redis_store import RedisTokenStore

    prefix = f"ywmcp:test:{uuid.uuid4().hex}"
    now = [100.0]
    first = RedisTokenStore((b"r" * 32,), url=REDIS_URL, prefix=prefix, clock=lambda: now[0])
    second = RedisTokenStore((b"r" * 32,), url=REDIS_URL, prefix=prefix, clock=lambda: now[0])
    isolated = RedisTokenStore(
        (b"r" * 32,), url=REDIS_URL, prefix=f"{prefix}:other", clock=lambda: now[0]
    )
    record = DownstreamCredentialRecord(
        principal_id="synthetic-account",
        access_token="synthetic-access-secret",
        refresh_token="synthetic-refresh-secret",
        refresh_after=101.0,
    )
    try:
        await first.put_downstream(record.principal_id, record)
        assert await first.list_due_downstream() == []
        keys = [key async for key in first._client.scan_iter(match=f"{prefix}:*")]
        assert len(keys) == 3
        for key in keys:
            payload = key + (await first._client.dump(key))
            for secret in (
                b"synthetic-account",
                b"synthetic-access-secret",
                b"synthetic-refresh-secret",
            ):
                assert secret not in payload
        assert await isolated.list_due_downstream() == []
        now[0] = 101.0
        claims = await asyncio.gather(first.list_due_downstream(), second.list_due_downstream())
        assert sorted(claims) == [[], [record.principal_id]]
        now[0] = 400.999
        assert await second.list_due_downstream() == []
        now[0] = 401.0
        assert await second.list_due_downstream() == [record.principal_id]
        refreshed = record.model_copy(update={"refresh_after": 1000.0})
        await second.put_downstream(record.principal_id, refreshed)
        now[0] = 701.0
        assert await first.list_due_downstream() == []
        now[0] = 1000.0
        assert await first.list_due_downstream(limit=0) == []
        assert await first.list_due_downstream(limit=100_000) == [record.principal_id]
        await isolated.delete_downstream(record.principal_id)
        assert await first.get_downstream(record.principal_id) == refreshed
        await first.delete_downstream(record.principal_id)
        assert await second.list_due_downstream() == []
        assert await first._client.zcard(first._refresh_schedule_key) == 0
        with pytest.raises(TokenStoreMiss):
            await second.get_downstream(record.principal_id)
    finally:
        await _clear_test_prefix(first)
        await first.close()
        await second.close()
        await isolated.close()


@pytest.mark.asyncio
async def test_redis_refresh_schedule_survives_key_rotation_and_cleans_old_members() -> None:
    pytest.importorskip("redis")
    from yandex_workspace_mcp.auth.redis_store import RedisTokenStore

    prefix = f"ywmcp:test:{uuid.uuid4().hex}"
    old = RedisTokenStore((b"o" * 32,), url=REDIS_URL, prefix=prefix, clock=lambda: 100.0)
    rotated = RedisTokenStore(
        (b"n" * 32, b"o" * 32), url=REDIS_URL, prefix=prefix, clock=lambda: 100.0
    )
    record = DownstreamCredentialRecord(
        principal_id="synthetic-account",
        access_token="synthetic-access-secret",
        refresh_token="synthetic-refresh-secret",
        refresh_after=100.0,
    )
    try:
        await old.put_downstream(record.principal_id, record)
        assert await rotated.list_due_downstream() == [record.principal_id]
        old_locator = old._redis_keys("downstream-refresh", record.principal_id)[0]
        await rotated.put_downstream(
            record.principal_id, record.model_copy(update={"refresh_after": 500.0})
        )
        assert await old._client.get(old_locator) is None
        assert (
            await old._client.zscore(old._refresh_schedule_key, old_locator.rsplit(":", 1)[1])
            is None
        )
        assert await rotated._client.zcard(rotated._refresh_schedule_key) == 1
        assert await rotated.list_due_downstream() == []
        await rotated.delete_downstream(record.principal_id)
        assert await rotated._client.zcard(rotated._refresh_schedule_key) == 0
        assert not [key async for key in old._client.scan_iter(match=f"{prefix}:*")]
    finally:
        await _clear_test_prefix(old)
        await old.close()
        await rotated.close()


@pytest.mark.asyncio
async def test_redis_refresh_schedule_removes_unusable_jobs() -> None:
    pytest.importorskip("redis")
    from yandex_workspace_mcp.auth.redis_store import RedisTokenStore

    prefix = f"ywmcp:test:{uuid.uuid4().hex}"
    now = [100.0]
    store = RedisTokenStore((b"r" * 32,), url=REDIS_URL, prefix=prefix, clock=lambda: now[0])
    try:
        for failure in ("missing-locator", "invalid-locator", "missing-grant", "expired"):
            principal = f"synthetic-account-{failure}"
            record = DownstreamCredentialRecord(
                principal_id=principal,
                access_token="synthetic-access-secret",
                refresh_token="synthetic-refresh-secret",
                refresh_after=100.0,
                expires_at=150.0 if failure == "expired" else None,
            )
            await store.put_downstream(principal, record)
            locator = store._redis_keys("downstream-refresh", principal)[0]
            if failure == "missing-locator":
                await store._client.delete(locator)
            elif failure == "invalid-locator":
                await store._client.set(locator, b'{"invalid":"ciphertext"}')
            elif failure == "missing-grant":
                await store._client.delete(*store._redis_keys("downstream", principal))
        now[0] = 200.0
        assert await store.list_due_downstream() == []
        assert await store._client.zcard(store._refresh_schedule_key) == 0
        assert not [
            key async for key in store._client.scan_iter(match=f"{prefix}:downstream-refresh:*")
        ]
    finally:
        await _clear_test_prefix(store)
        await store.close()


@pytest.mark.asyncio
async def test_redis_invalid_locator_cleanup_preserves_concurrent_reschedule(monkeypatch) -> None:
    pytest.importorskip("redis")
    from yandex_workspace_mcp.auth.redis_store import RedisTokenStore

    prefix = f"ywmcp:test:{uuid.uuid4().hex}"
    store = RedisTokenStore((b"r" * 32,), url=REDIS_URL, prefix=prefix, clock=lambda: 100.0)
    record = DownstreamCredentialRecord(
        principal_id="synthetic-account",
        access_token="synthetic-access-secret",
        refresh_token="synthetic-refresh-secret",
        refresh_after=100.0,
    )
    try:
        await store.put_downstream(record.principal_id, record)
        locator = store._redis_keys("downstream-refresh", record.principal_id)[0]
        await store._client.set(locator, b"invalid-ciphertext")
        original_get = store._client.get

        async def reschedule_after_read(key):
            payload = await original_get(key)
            if key == locator:
                await store.put_downstream(
                    record.principal_id, record.model_copy(update={"refresh_after": 1000.0})
                )
            return payload

        monkeypatch.setattr(store._client, "get", reschedule_after_read)
        assert await store.list_due_downstream() == []
        assert (
            await store._client.zscore(store._refresh_schedule_key, locator.rsplit(":", 1)[1])
            == 1000.0
        )
        assert await original_get(locator) is not None
    finally:
        await _clear_test_prefix(store)
        await store.close()


@pytest.mark.asyncio
async def test_redis_conditional_refresh_mutations_are_atomic_between_replicas() -> None:
    pytest.importorskip("redis")
    from yandex_workspace_mcp.auth.redis_store import RedisTokenStore

    prefix = f"ywmcp:test:{uuid.uuid4().hex}"
    first = RedisTokenStore((b"r" * 32,), url=REDIS_URL, prefix=prefix, clock=lambda: 100.0)
    second = RedisTokenStore((b"r" * 32,), url=REDIS_URL, prefix=prefix, clock=lambda: 100.0)
    original = DownstreamCredentialRecord(
        principal_id="synthetic-account",
        access_token="synthetic-access-secret",
        refresh_token="synthetic-refresh-secret",
        refresh_after=100.0,
    )
    replacements = [
        original.model_copy(
            update={"access_token": f"synthetic-new-access-{index}", "refresh_after": 1000.0}
        )
        for index in range(2)
    ]
    try:
        await first.put_downstream(original.principal_id, original)
        outcomes = await asyncio.gather(
            *[
                store.replace_downstream(original.principal_id, original, replacement)
                for store, replacement in zip((first, second), replacements, strict=True)
            ]
        )
        assert sum(outcomes) == 1
        current = await first.get_downstream(original.principal_id)
        assert current == replacements[outcomes.index(True)]
        assert await second.list_due_downstream() == []
        assert not await second.delete_downstream_if_current(original.principal_id, original)
        deletes = await asyncio.gather(
            *[
                store.delete_downstream_if_current(original.principal_id, current)
                for store in (first, second)
            ]
        )
        assert sum(deletes) == 1
        assert not await first.replace_downstream(original.principal_id, current, original)
        assert await first._client.zcard(first._refresh_schedule_key) == 0
        assert not [key async for key in first._client.scan_iter(match=f"{prefix}:*")]
    finally:
        await _clear_test_prefix(first)
        await first.close()
        await second.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["replace", "delete"])
@pytest.mark.parametrize("conflict", ["revoke", "reauthorize"])
async def test_redis_conditional_refresh_detects_conflicts_across_key_ring(
    monkeypatch, mutation: str, conflict: str
) -> None:
    pytest.importorskip("redis")
    from yandex_workspace_mcp.auth.redis_store import RedisTokenStore

    prefix = f"ywmcp:test:{uuid.uuid4().hex}"
    old = RedisTokenStore((b"o" * 32,), url=REDIS_URL, prefix=prefix, clock=lambda: 100.0)
    reader = RedisTokenStore(
        (b"n" * 32, b"o" * 32), url=REDIS_URL, prefix=prefix, clock=lambda: 100.0
    )
    writer = RedisTokenStore(
        (b"n" * 32, b"o" * 32), url=REDIS_URL, prefix=prefix, clock=lambda: 100.0
    )
    original = DownstreamCredentialRecord(
        principal_id="synthetic-account",
        access_token="synthetic-access-secret",
        refresh_token="synthetic-refresh-secret",
        refresh_after=100.0,
    )
    newer = original.model_copy(
        update={"access_token": "synthetic-newer-access", "refresh_after": 1000.0}
    )
    attempted = original.model_copy(
        update={"access_token": "synthetic-stale-refresh", "refresh_after": 2000.0}
    )
    try:
        await old.put_downstream(original.principal_id, original)
        original_pipeline = reader._client.pipeline

        def conflict_pipeline(*args, **kwargs):
            pipeline = original_pipeline(*args, **kwargs)
            original_mget = pipeline.mget

            async def conflict_after_read(*keys):
                values = await original_mget(*keys)
                if conflict == "revoke":
                    await writer.delete_downstream(original.principal_id)
                else:
                    await writer.put_downstream(original.principal_id, newer)
                return values

            monkeypatch.setattr(pipeline, "mget", conflict_after_read)
            return pipeline

        monkeypatch.setattr(reader._client, "pipeline", conflict_pipeline)
        if mutation == "replace":
            assert not await reader.replace_downstream(original.principal_id, original, attempted)
        else:
            assert not await reader.delete_downstream_if_current(original.principal_id, original)
        if conflict == "revoke":
            with pytest.raises(TokenStoreMiss):
                await writer.get_downstream(original.principal_id)
            assert await writer._client.zcard(writer._refresh_schedule_key) == 0
        else:
            assert await writer.get_downstream(original.principal_id) == newer
            assert await writer.list_due_downstream() == []
            assert (
                await writer._client.get(old._redis_keys("downstream", original.principal_id)[0])
                is None
            )
    finally:
        await _clear_test_prefix(old)
        await old.close()
        await reader.close()
        await writer.close()
