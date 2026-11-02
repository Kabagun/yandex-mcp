"""Legacy DCR recovery checks use an opt-in Redis and synthetic encrypted AOF only."""

import os
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

import httpx
import pytest
from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyUrl

from yandex_workspace_mcp.auth.models import OAuthClientRecord
from yandex_workspace_mcp.auth.oauth import YandexMcpOAuthProvider
from yandex_workspace_mcp.auth.redis_store import RedisTokenStore
from yandex_workspace_mcp.auth.stores import InMemoryTokenStore, TokenStoreMiss
from yandex_workspace_mcp.config import Settings
from yandex_workspace_mcp.models.errors import ConfigurationError
from yandex_workspace_mcp.server import ApplicationDependencies, create_application, create_http_app

REDIS_URL = os.getenv("TEST_REDIS_URL")
pytestmark = pytest.mark.skipif(
    not REDIS_URL, reason="TEST_REDIS_URL is not configured; Redis migration test is opt-in"
)
KEY = b"m" * 32
SENTINEL = 9_999_999_999.0


@pytest.fixture
async def namespace():
    redis = pytest.importorskip("redis.asyncio")
    client = redis.Redis.from_url(REDIS_URL, decode_responses=False)
    await client.ping()
    prefix = f"ywmcp:test:client-migration:{uuid4().hex}"
    try:
        yield client, prefix
    finally:
        keys = [key async for key in client.scan_iter(match=f"{prefix}:*")]
        if keys:
            await client.delete(*keys)
        await client.aclose()


def _resp(*parts: str | bytes) -> bytes:
    values = [part.encode() if isinstance(part, str) else part for part in parts]
    return (
        b"*"
        + str(len(values)).encode()
        + b"\r\n"
        + b"".join(b"$" + str(len(value)).encode() + b"\r\n" + value + b"\r\n" for value in values)
    )


def _record(
    expiry: float | None,
    scope: str = "workspace:read",
    *,
    client_id="cached-client",
    secret="original-secret",
) -> OAuthClientRecord:
    metadata = OAuthClientInformationFull(
        client_id=client_id,
        client_secret=secret,
        client_secret_expires_at=int(expiry) if expiry else 0,
        redirect_uris=[AnyUrl("https://client.example/callback")],
        scope=scope,
        token_endpoint_auth_method="client_secret_post",
    ).model_dump(mode="json")
    return OAuthClientRecord(
        client_id=client_id,
        client_secret=secret,
        redirect_uris=("https://client.example/callback",),
        allowed_scopes=(scope,),
        client_secret_expires_at=expiry,
        expires_at=expiry,
        registration_source="synthetic-registration-peer",
        metadata=metadata,
    )


@dataclass
class LegacyClient:
    record: OAuthClientRecord
    key: str
    source_key: bytes
    aof: Path
    now: float


async def _expired_client(
    namespace, tmp_path, scope="workspace:read", history="set"
) -> LegacyClient:
    redis, prefix = namespace
    now = time.time()
    old = RedisTokenStore((KEY,), client=redis, prefix=prefix, clock=lambda: now)
    await old.put_client(_record(now + 120, scope))
    record = _record(now - 60, scope)
    assert record.expires_at is not None
    key = old._redis_keys("client", record.client_id)[0]
    sources = [key async for key in redis.scan_iter(match=f"{prefix}:registration-source:*")]
    assert len(sources) == 1
    source = sources[0]
    await redis.zadd(source, {key: record.expires_at})
    await redis.delete(key)
    aof = tmp_path / "synthetic-clients.aof"
    payload_key = f"legacy:{key}" if history == "copy" else key
    write_payload = _resp(
        "SET",
        payload_key,
        old._encode("client", record.client_id, record),
        "PXAT",
        str(int(record.expires_at * 1000)),
    )
    commands = write_payload if history == "copy" else b""
    commands += _resp("MULTI") + _resp("DEL", key)
    commands += _resp("COPY", payload_key, key) if history == "copy" else write_payload
    commands += _resp("ZADD", source, str(record.expires_at), key) + _resp("EXEC")
    if history == "copy":
        commands += _resp("DEL", payload_key)
    commands += _resp("DEL", key)
    aof.write_bytes(commands)
    return LegacyClient(record, key, source, aof, now)


def _store(namespace, legacy: LegacyClient, **overrides) -> RedisTokenStore:
    redis, prefix = namespace
    options = {
        "client": redis,
        "prefix": prefix,
        "clock": lambda: legacy.now,
        "permanent_clients": True,
        "legacy_client_aof_path": legacy.aof,
    }
    options.update(overrides)
    return RedisTokenStore((KEY,), **options)


def _settings(profile="disk", **updates) -> Settings:
    values = {
        "_env_file": None,
        "mcp_profile": profile,
        "mcp_transport": "streamable-http",
        "mcp_auth_mode": "multi-user",
        "yandex_auth_mode": "multi-user",
        "yandex_oauth_client_id": "synthetic-yandex-client",
        "yandex_oauth_client_secret": "synthetic-yandex-secret",
        "mcp_issuer_url": f"https://{profile}.example",
        "mcp_resource_server_url": f"https://{profile}.example/mcp",
        "mcp_oauth_callback_url": f"https://{profile}.example/oauth/yandex/callback",
        "disk_allowed_roots": ["/"],
    }
    values.update(updates)
    return Settings(**values)


@pytest.mark.parametrize("profile,scope", [("disk", "workspace:read"), ("mail", "mail:read")])
@pytest.mark.parametrize("history", ["set", "copy"])
async def test_cached_clients_authorize_with_original_secret_after_expired_key_recovery(
    namespace, tmp_path, profile, scope, history
) -> None:
    legacy = await _expired_client(namespace, tmp_path, scope, history)
    redis, prefix = namespace
    store = _store(namespace, legacy)

    def no_upstream(_request):
        raise AssertionError("No live OAuth exchange is needed to authenticate the cached client.")

    application = create_application(
        _settings(profile),
        ApplicationDependencies(
            auth_store_factory=lambda: store,
            oauth_http_client_factory=lambda: httpx.AsyncClient(
                transport=httpx.MockTransport(no_upstream)
            ),
        ),
    )
    async with (
        application.lifespan(),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_http_app(application)),
            base_url=f"https://{profile}.example",
        ) as http,
    ):
        params = {
            "client_id": legacy.record.client_id,
            "redirect_uri": legacy.record.redirect_uris[0],
            "response_type": "code",
            "code_challenge": "synthetic-pkce-challenge",
            "code_challenge_method": "S256",
            "scope": scope,
            "resource": f"https://{profile}.example/mcp",
        }
        authorized = await http.get("/authorize", params=params)
        assert authorized.status_code == 302
        assert urlsplit(authorized.headers["location"]).hostname == "oauth.yandex.ru"
        assert await redis.ttl(legacy.key) == -1
        assert await redis.zscore(legacy.source_key, legacy.key) == SENTINEL
        assert await redis.exists(f"{prefix}:client-migration:v1")

        credentials = {
            "grant_type": "synthetic-unsupported-grant",
            "client_id": legacy.record.client_id,
            "client_secret": legacy.record.client_secret,
        }
        accepted_client = await http.post("/token", data=credentials)
        assert accepted_client.status_code == 400
        assert accepted_client.json()["error"] != "invalid_client"
        rejected_client = await http.post(
            "/token", data={**credentials, "client_secret": "incorrect-secret"}
        )
        assert rejected_client.status_code == 401
        assert rejected_client.json()["error"] == "invalid_client"
        wrong_redirect = await http.get(
            "/authorize", params={**params, "redirect_uri": "https://untrusted.example/callback"}
        )
        assert wrong_redirect.status_code == 400
        assert "location" not in wrong_redirect.headers
        wrong_scope = await http.get("/authorize", params={**params, "scope": "unregistered:scope"})
        assert wrong_scope.status_code == 302
        assert parse_qs(urlsplit(wrong_scope.headers["location"]).query)["error"] == [
            "invalid_scope"
        ]
        unknown = await http.get("/authorize", params={**params, "client_id": "unknown-client"})
        assert unknown.status_code == 400
        assert "location" not in unknown.headers
        assert application.oauth_provider is not None
        client = await application.oauth_provider.get_client(legacy.record.client_id)
        assert client is not None and client.redirect_uris is not None
        assert client.client_secret == legacy.record.client_secret
        assert client.client_secret_expires_at == 0
        assert tuple(map(str, client.redirect_uris)) == legacy.record.redirect_uris
        assert client.scope == scope


@pytest.mark.parametrize("invalid_proof", ["absent-index", "score-mismatch", "other-namespace"])
async def test_missing_clients_require_matching_current_registration_index(
    namespace, tmp_path, invalid_proof
) -> None:
    legacy = await _expired_client(namespace, tmp_path)
    assert legacy.record.expires_at is not None
    redis, _ = namespace
    if invalid_proof == "absent-index":
        await redis.zrem(legacy.source_key, legacy.key)
    elif invalid_proof == "score-mismatch":
        await redis.zadd(legacy.source_key, {legacy.key: legacy.record.expires_at - 10})
    else:
        foreign_key = legacy.key.replace(":client:", ":foreign:client:")
        store = _store(namespace, legacy)
        legacy.aof.write_bytes(
            _resp(
                "SET",
                foreign_key,
                store._encode("client", legacy.record.client_id, legacy.record),
                "PXAT",
                str(int(legacy.record.expires_at * 1000)),
            )
        )
    store = _store(namespace, legacy)
    await store.open()
    assert not await redis.exists(legacy.key)
    with pytest.raises(TokenStoreMiss):
        await store.get_client(legacy.record.client_id)
    if invalid_proof == "other-namespace":
        assert not await redis.exists(foreign_key)


async def test_finite_policy_does_not_restore_missing_keys_or_persist_live_keys(
    namespace, tmp_path
) -> None:
    legacy = await _expired_client(namespace, tmp_path)
    redis, prefix = namespace
    finite = _store(namespace, legacy, permanent_clients=False)
    live = _record(legacy.now + 120, client_id="live-finite-client")
    await finite.put_client(live)
    # put_client cleans old source scores; keep this candidate's original proof for the test.
    await redis.zadd(legacy.source_key, {legacy.key: legacy.record.expires_at})
    live_key = finite._redis_keys("client", live.client_id)[0]
    await finite.open()
    assert not await redis.exists(legacy.key)
    assert await redis.ttl(live_key) > 0
    assert not await redis.exists(f"{prefix}:client-migration:v1")


async def test_migration_preserves_a_newer_live_registration_payload(namespace, tmp_path) -> None:
    legacy = await _expired_client(namespace, tmp_path)
    redis, _ = namespace
    store = _store(namespace, legacy)
    current = _record(legacy.now + 120, secret="new-current-secret")
    await store.put_client(current)
    encrypted_before = await redis.get(legacy.key)
    await store.open()
    assert await redis.get(legacy.key) == encrypted_before
    assert (await store.get_client(current.client_id)).client_secret == current.client_secret


async def test_completed_migration_does_not_revive_later_deleted_client(
    namespace, tmp_path
) -> None:
    legacy = await _expired_client(namespace, tmp_path)
    redis, prefix = namespace
    await _store(namespace, legacy).open()
    assert await redis.exists(legacy.key)
    assert await redis.exists(f"{prefix}:client-migration:v1")
    await redis.delete(legacy.key)
    await _store(namespace, legacy).open()
    assert not await redis.exists(legacy.key)


@pytest.mark.parametrize("bad_path", ["missing", "malformed"])
async def test_failed_aof_import_never_marks_migration_complete(
    namespace, tmp_path, bad_path
) -> None:
    legacy = await _expired_client(namespace, tmp_path)
    redis, prefix = namespace
    if bad_path == "missing":
        legacy.aof.unlink()
    else:
        legacy.aof.write_bytes(b"not-a-resp-command\r\n")
    with pytest.raises(ConfigurationError):
        await _store(namespace, legacy).open()
    assert not await redis.exists(f"{prefix}:client-migration:v1")


async def test_live_legacy_clients_are_persisted_without_an_aof_path(namespace) -> None:
    redis, prefix = namespace
    now = [time.time()]
    old = RedisTokenStore((KEY,), client=redis, prefix=prefix, clock=lambda: now[0])
    record = _record(now[0] + 120)
    await old.put_client(record)
    key = old._redis_keys("client", record.client_id)[0]
    sources = [key async for key in redis.scan_iter(match=f"{prefix}:registration-source:*")]
    assert await redis.ttl(key) > 0
    store = RedisTokenStore(
        (KEY,), client=redis, prefix=prefix, clock=lambda: now[0], permanent_clients=True
    )
    await store.open()
    assert await redis.ttl(key) == -1
    assert await redis.zscore(sources[0], key) == SENTINEL
    now[0] += 121
    provider = YandexMcpOAuthProvider(
        store=store,
        issuer_url="https://disk.example",
        resource_server_url="https://disk.example/mcp",
        yandex_client_id="synthetic-yandex-client",
        yandex_callback_url="https://disk.example/oauth/yandex/callback",
        valid_scopes=["workspace:read"],
        clock=lambda: now[0],
    )
    client = await provider.get_client(record.client_id)
    assert client is not None
    assert client.client_secret == record.client_secret
    assert client.client_secret_expires_at == 0
    assert (await store.get_client(record.client_id)).expires_at is None


@pytest.mark.parametrize("ttl,permanent", [(0, True), (600, False)])
def test_application_passes_migration_policy_to_redis(
    monkeypatch, tmp_path, ttl, permanent
) -> None:
    captured = {}

    def factory(*_args, **kwargs):
        captured.update(kwargs)
        return InMemoryTokenStore((KEY,))

    monkeypatch.setattr("yandex_workspace_mcp.server.RedisTokenStore", factory)
    path = tmp_path / "synthetic-clients.aof"
    create_application(
        _settings(
            auth_store_backend="redis",
            redis_url="redis://127.0.0.1:6379/15",
            mcp_client_secret_expiry_seconds=ttl,
            mcp_legacy_client_aof_path=path,
        )
    )
    assert captured["permanent_clients"] is permanent
    assert captured["legacy_client_aof_path"] == path
