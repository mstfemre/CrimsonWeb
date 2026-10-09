"""Phase 5A.1: Host allowlist, mandatory API token, backup-before-migrate."""

import asyncio
import sqlite3
from datetime import UTC, datetime

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient

from crimsonweb.api import database
from crimsonweb.api.app import create_app
from crimsonweb.api.database import (
    MigrationBackupError,
    Repository,
    backup_sqlite,
    migration_config,
)
from crimsonweb.api.hosts import HostAllowlist, HostAllowlistMiddleware, split_host

TOKEN = "synthetic-test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
HEAD = ScriptDirectory.from_config(migration_config()).get_current_head()


@pytest.fixture
def default_hosts(monkeypatch):
    monkeypatch.delenv("CRIMSON_API_ALLOWED_HOSTS", raising=False)
    monkeypatch.setenv("CRIMSON_API_TOKEN", TOKEN)


def app_client(base_url, **kwargs):
    return TestClient(
        create_app(repository=Repository("sqlite://")), base_url=base_url, **kwargs
    )


# --- Host allowlist ---------------------------------------------------------


@pytest.mark.parametrize(
    "base_url",
    [
        "http://127.0.0.1",
        "http://127.0.0.1:8000",
        "http://localhost:8000",
        "http://LOCALHOST",
        "http://[::1]:8000",
    ],
)
def test_default_allowlist_accepts_loopback_names(default_hosts, base_url):
    with app_client(base_url) as client:
        assert client.get("/health", headers=AUTH).status_code == 200


@pytest.mark.parametrize(
    "base_url",
    [
        "http://testserver",
        "http://evil.example",
        "http://127.0.0.1.evil.example",
        "http://localhost.evil.example",
    ],
)
@pytest.mark.parametrize(
    "path", ["/health", "/openapi.json", "/docs", "/api/v1/workspaces"]
)
def test_default_allowlist_rejects_other_hosts_on_every_route(
    default_hosts, base_url, path
):
    with app_client(base_url) as client:
        response = client.get(path, headers=AUTH)
    assert response.status_code == 403
    assert response.json() == {"detail": "Host not allowed"}


def test_host_check_applies_in_tokenless_development_mode(dev_tokenless, monkeypatch):
    monkeypatch.delenv("CRIMSON_API_ALLOWED_HOSTS", raising=False)
    with app_client("http://evil.example", client=("127.0.0.1", 1000)) as client:
        assert client.get("/health").status_code == 403
    with app_client("http://127.0.0.1:8000", client=("127.0.0.1", 1000)) as client:
        assert client.get("/health").status_code == 200


def test_configured_port_is_enforced(monkeypatch):
    monkeypatch.setenv("CRIMSON_API_TOKEN", TOKEN)
    monkeypatch.setenv("CRIMSON_API_ALLOWED_HOSTS", "127.0.0.1:8000,[::1]:8443")
    for base_url, expected in [
        ("http://127.0.0.1:8000", 200),
        ("https://127.0.0.1:8000", 200),
        ("http://127.0.0.1:9000", 403),
        ("http://127.0.0.1", 403),
        ("http://[::1]:8443", 200),
        ("http://[::1]:8000", 403),
        ("http://localhost:8000", 403),
    ]:
        with app_client(base_url) as client:
            assert client.get("/health", headers=AUTH).status_code == expected, base_url


@pytest.mark.parametrize(
    "value",
    [
        "",
        "127.0.0.1:",
        "127.0.0.1:abc",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "[::1",
        "[::1]x",
        "::1",
        "[fe80::1%25eth0]",
        "user@127.0.0.1",
        "127.0.0.1/x",
        "exa mple",
        "-bad.example",
        "a..b",
        "*",
    ],
)
def test_malformed_host_values_are_rejected(value):
    with pytest.raises(ValueError):
        split_host(value)
    assert not HostAllowlist.parse(["127.0.0.1"]).allows(value, "http")


@pytest.mark.parametrize("raw", ["*", "", " , ", "http://127.0.0.1", "::1", "*.lab"])
def test_invalid_allowlist_configuration_fails_closed(monkeypatch, raw):
    monkeypatch.setenv("CRIMSON_API_ALLOWED_HOSTS", raw)
    with pytest.raises(ValueError, match="CRIMSON_API_ALLOWED_HOSTS"):
        create_app(repository=Repository("sqlite://"))


async def asgi_status(headers):
    calls = []

    async def inner(scope, receive, send):
        calls.append(scope)
        await send({"type": "http.response.start", "status": 204, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    async def receive():
        return {"type": "http.request", "body": b""}

    sent = []

    async def send(message):
        sent.append(message)

    middleware = HostAllowlistMiddleware(inner, HostAllowlist.parse(["127.0.0.1"]))
    scope = {"type": "http", "scheme": "http", "headers": headers, "path": "/"}
    await middleware(scope, receive, send)
    return sent[0]["status"], bool(calls)


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        ([(b"host", b"127.0.0.1")], (204, True)),
        ([], (403, False)),
        ([(b"host", b"127.0.0.1"), (b"host", b"127.0.0.1")], (403, False)),
        ([(b"host", "127.0.0.ı".encode())], (403, False)),
    ],
)
def test_missing_duplicate_or_non_ascii_host_never_reaches_the_app(headers, expected):
    assert asyncio.run(asgi_status(headers)) == expected


# --- Token policy -----------------------------------------------------------


@pytest.mark.parametrize("token", [None, "   "])
@pytest.mark.parametrize("flag", [None, "true", "0"])
def test_api_refuses_to_start_without_token_or_explicit_dev_flag(
    monkeypatch, token, flag
):
    for name, value in (
        ("CRIMSON_API_TOKEN", token),
        ("CRIMSON_API_DEV_ALLOW_NO_TOKEN", flag),
    ):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    with (
        pytest.raises(RuntimeError, match="CRIMSON_API_TOKEN is required"),
        app_client("http://127.0.0.1", client=("127.0.0.1", 1000)),
    ):
        pass


def test_requests_are_denied_even_if_lifespan_was_bypassed(monkeypatch):
    monkeypatch.delenv("CRIMSON_API_TOKEN", raising=False)
    client = app_client("http://127.0.0.1", client=("127.0.0.1", 1000))
    response = client.get("/health")  # no `with`: lifespan never ran
    assert response.status_code == 403
    assert response.json() == {"detail": "API token required"}


def test_dev_flag_keeps_loopback_only_and_never_overrides_a_token(
    dev_tokenless, monkeypatch
):
    with app_client("http://127.0.0.1", client=("127.0.0.1", 1000)) as client:
        assert client.get("/health").status_code == 200
    with app_client("http://127.0.0.1", client=("192.0.2.1", 1000)) as client:
        assert client.get("/health").status_code == 403
    monkeypatch.setenv("CRIMSON_API_TOKEN", TOKEN)
    with app_client("http://127.0.0.1", client=("127.0.0.1", 1000)) as client:
        assert client.get("/health").status_code == 401
        assert client.get("/health", headers=AUTH).status_code == 200


def test_non_ascii_bearer_is_rejected_as_unauthorized(monkeypatch):
    monkeypatch.setenv("CRIMSON_API_TOKEN", TOKEN)
    with app_client("http://127.0.0.1") as client:
        response = client.get(
            "/health", headers={"Authorization": "Bearer tést".encode()}
        )
    assert response.status_code == 401


# --- Backup before migration ------------------------------------------------


def url(path):
    return f"sqlite:///{path.as_posix()}"


def migrate_to(path, revision):
    repo = Repository(url(path))
    with repo.engine.begin() as connection:
        config = migration_config()
        config.attributes["connection"] = connection
        command.upgrade(config, revision)
    repo.close()


def revision(path):
    connection = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)
    try:
        return connection.execute("select version_num from alembic_version").fetchone()[
            0
        ]
    finally:
        connection.close()


def backups(path):
    return sorted(path.parent.glob(f"{path.name}.*.bak*"))


def test_new_and_empty_databases_migrate_without_backup(tmp_path):
    fresh = tmp_path / "fresh.sqlite"
    empty = tmp_path / "empty.sqlite"
    empty.write_bytes(b"")
    for path in (fresh, empty):
        repo = Repository(url(path))
        repo.initialize()
        repo.close()
        assert repo.backup_paths == [] and backups(path) == []
        assert revision(path) == HEAD


def test_database_at_head_is_not_backed_up_again(tmp_path):
    path = tmp_path / "current.sqlite"
    migrate_to(path, "head")
    repo = Repository(url(path))
    repo.initialize()
    repo.close()
    assert repo.backup_paths == [] and backups(path) == []


def test_outdated_database_is_backed_up_before_upgrade(tmp_path):
    path = tmp_path / "old.sqlite"
    migrate_to(path, "0002_phase3")
    repo = Repository(url(path))
    assert repo.pending_upgrade() is True
    repo.initialize()
    repo.close()
    assert revision(path) == HEAD
    [backup] = repo.backup_paths
    assert backups(path) == [backup]
    assert backup.name.startswith("old.sqlite.") and backup.name.endswith(".bak")
    assert revision(backup) == "0002_phase3"  # the copy is the pre-upgrade state


def test_failed_backup_stops_upgrade_and_leaves_no_partial_copy(tmp_path, monkeypatch):
    path = tmp_path / "old.sqlite"
    migrate_to(path, "0002_phase3")

    def unavailable(source, destination):
        raise OSError("synthetic: backup volume unavailable")

    monkeypatch.setattr(database.shutil, "copy2", unavailable)
    repo = Repository(url(path))
    with pytest.raises(MigrationBackupError, match="migration was not applied"):
        repo.initialize()
    repo.close()
    assert revision(path) == "0002_phase3"
    assert backups(path) == []


def test_truncated_backup_is_removed_and_upgrade_stopped(tmp_path, monkeypatch):
    path = tmp_path / "old.sqlite"
    migrate_to(path, "0002_phase3")

    def truncated(source, destination):
        destination.write_bytes(b"partial")

    monkeypatch.setattr(database.shutil, "copy2", truncated)
    repo = Repository(url(path))
    with pytest.raises(MigrationBackupError):
        repo.initialize()
    repo.close()
    assert revision(path) == "0002_phase3"
    assert backups(path) == []


def test_backup_copies_wal_and_shm_companions_with_sqlite_names(tmp_path):
    path = tmp_path / "db.sqlite"
    contents = {"": b"main", "-wal": b"wal-frames", "-shm": b"shared-index"}
    for suffix, data in contents.items():
        (tmp_path / f"db.sqlite{suffix}").write_bytes(data)
    stamp = datetime(2026, 10, 9, 12, tzinfo=UTC)
    copied = backup_sqlite(path, stamp)
    base = tmp_path / "db.sqlite.20261009T120000000000Z.bak"
    assert copied == [
        base,
        base.with_name(base.name + "-wal"),
        base.with_name(base.name + "-shm"),
    ]
    for suffix, data in contents.items():
        assert (tmp_path / f"{base.name}{suffix}").read_bytes() == data


def test_existing_backup_is_never_overwritten(tmp_path):
    path = tmp_path / "db.sqlite"
    path.write_bytes(b"first")
    stamp = datetime(2026, 10, 9, 12, tzinfo=UTC)
    [first] = backup_sqlite(path, stamp)
    path.write_bytes(b"second")
    with pytest.raises(MigrationBackupError):
        backup_sqlite(path, stamp)
    assert first.read_bytes() == b"first"
