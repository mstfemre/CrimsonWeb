import pytest

# Starlette's TestClient sends ``Host: testserver``. It is added for tests only;
# the production default allowlist excludes it (asserted in test_phase5a1_hardening).
TEST_ALLOWED_HOSTS = "127.0.0.1,localhost,[::1],testserver"


@pytest.fixture(autouse=True)
def isolate_api_database(tmp_path, monkeypatch):
    """Existing tests keep their API contracts without sharing persistent test state."""
    monkeypatch.setenv(
        "CRIMSON_DATABASE_URL", f"sqlite:///{(tmp_path / 'test.sqlite').as_posix()}"
    )
    monkeypatch.setenv("CRIMSON_API_ALLOWED_HOSTS", TEST_ALLOWED_HOSTS)
    # Token-required is the default; tokenless tests must opt in explicitly.
    monkeypatch.delenv("CRIMSON_API_DEV_ALLOW_NO_TOKEN", raising=False)


@pytest.fixture
def dev_tokenless(monkeypatch):
    """Explicit loopback development mode without an API token."""
    monkeypatch.delenv("CRIMSON_API_TOKEN", raising=False)
    monkeypatch.setenv("CRIMSON_API_DEV_ALLOW_NO_TOKEN", "1")
