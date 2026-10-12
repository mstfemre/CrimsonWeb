"""Local profile wiring and strict planning; no external network or model required."""

import asyncio
import json
import os
import shutil
import subprocess
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from test_web_top10 import (
    SelectingProvider,
    approve,
    configuration,
    execute_payload,
    lab,
    payload,
)
from verification_helpers import setup

from crimsonweb.api.ai.provider import (
    AIError,
    AISettings,
    OllamaProvider,
    ProviderReply,
)
from crimsonweb.api.ai.service import AIService
from crimsonweb.api.workspaces.store import Conflict

PROFILE_VARIABLES = (
    "CRIMSON_AI_PROFILE", "CRIMSON_AI_ENABLED", "CRIMSON_OLLAMA_MODEL", "CRIMSON_OLLAMA_THINK",
    "CRIMSON_AI_CONTEXT_TOKENS", "CRIMSON_AI_MAX_OUTPUT_TOKENS", "CRIMSON_AI_TIMEOUT",
    "CRIMSON_AI_MAX_CONCURRENCY", "CRIMSON_OLLAMA_URL",
)


@pytest.fixture
def clean_profile_env(monkeypatch):
    for name in PROFILE_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.mark.parametrize("profile,model", [("gemma-web", "gemma4:26b"), ("qwen-web", "qwen3.5:9b")])
def test_profile_is_opt_in_and_wires_exact_local_generation_settings(clean_profile_env, profile, model):
    clean_profile_env.setenv("CRIMSON_AI_PROFILE", profile)
    settings = AISettings.from_env()
    assert settings.enabled is False
    clean_profile_env.setenv("CRIMSON_AI_ENABLED", "true")
    settings = AISettings.from_env()
    assert settings.enabled and settings.timeout_seconds == 300 and settings.max_concurrency == 1
    calls = []

    def handler(request):
        data = json.loads(request.content)
        calls.append(request)
        assert request.url.host == "127.0.0.1" and data["model"] == model
        assert data["think"] is False and data["options"]["num_ctx"] == 8192
        assert data["options"]["num_predict"] == 4096 and "tools" not in data
        return httpx.Response(200, json={"model": model, "done": True,
                                        "message": {"role": "assistant", "content": "{}"}})

    provider = OllamaProvider(settings, httpx.MockTransport(handler))
    asyncio.run(provider.generate("trusted", {}, {"type": "object"}))
    assert len(calls) == 1


def test_no_profile_preserves_legacy_defaults(clean_profile_env):
    assert AISettings.from_env() == AISettings()


def test_explicit_settings_override_profile_without_bypassing_local_boundary(clean_profile_env):
    clean_profile_env.setenv("CRIMSON_AI_PROFILE", "gemma-web")
    clean_profile_env.setenv("CRIMSON_AI_CONTEXT_TOKENS", "4096")
    assert AISettings.from_env().context_tokens == 4096
    clean_profile_env.setenv("CRIMSON_OLLAMA_URL", "https://external.invalid")
    with pytest.raises(AIError, match="invalid_configuration"):
        OllamaProvider(AISettings.from_env())


def test_invalid_profile_disables_service_with_safe_diagnostic(clean_profile_env):
    clean_profile_env.setenv("CRIMSON_AI_PROFILE", "UNKNOWN_SECRET_PROFILE")
    clean_profile_env.setenv("CRIMSON_AI_ENABLED", "true")
    service = AIService(None)
    assert service.descriptor().error_code == "invalid_configuration"
    assert not service.descriptor().enabled and service.provider is None
    assert "SECRET" not in service.descriptor().model_dump_json()


def test_explicit_empty_thinking_does_not_silently_use_profile_defaults(clean_profile_env):
    clean_profile_env.setenv("CRIMSON_AI_PROFILE", "gemma-web")
    clean_profile_env.setenv("CRIMSON_AI_ENABLED", "true")
    clean_profile_env.setenv("CRIMSON_OLLAMA_THINK", "")
    with pytest.raises(ValueError, match="Invalid thinking configuration"):
        AISettings.from_env()
    assert AIService(None).descriptor().error_code == "invalid_configuration"


class BrokenProvider:
    def __init__(self, mode):
        self.mode = mode

    async def generate(self, system, evidence, schema):
        if self.mode == "error":
            raise ValueError("SYNTHETIC_SECRET_MODEL_OUTPUT")
        if self.mode == "forged":
            return ProviderReply(content='{"proposals":[{"catalog_id":"invented_tool"}]}')
        return ProviderReply(content='{"proposals":[]}')


@pytest.mark.parametrize("mode", ["missing", "error", "forged", "empty"])
def test_strict_initial_plan_never_seeds_after_model_failure(mode):
    calls = []
    repo, _, ws, pid, manager = setup(lab("html", calls), configuration=configuration())
    if mode != "missing":
        manager.provider = BrokenProvider(mode)
    try:
        request = payload(pid, ["xss_reflection_probe"]).model_copy(update={"require_model": True})
        with pytest.raises(Conflict, match="Required model planner unavailable") as failure:
            asyncio.run(manager.create_plan(ws.id, request))
        assert "SECRET" not in str(failure.value) and calls == []
        assert manager.store.list_plans(ws.id, 50, 0).total == 0
    finally:
        repo.close()


def test_legacy_operator_fallback_remains_available_and_visible():
    repo, _, ws, pid, manager = setup(configuration=configuration())
    manager.provider = BrokenProvider("error")
    try:
        plan = asyncio.run(manager.create_plan(ws.id, payload(pid, ["xss_reflection_probe"])))
        assert plan.planner == "operator" and plan.require_model is False
        assert "model_planner_unavailable_operator_seeded" in plan.limitations
    finally:
        repo.close()


@pytest.mark.parametrize("mode", ["missing", "error", "forged", "empty"])
def test_strict_follow_up_retains_parent_and_creates_no_operator_child(mode):
    calls = []
    repo, _, ws, pid, manager = setup(lab("html", calls), configuration=configuration())
    manager.provider = SelectingProvider()

    async def scenario():
        request = payload(pid, ["xss_reflection_probe", "web_security_observation"], 1)
        plan = await manager.create_plan(ws.id, request.model_copy(update={"require_model": True}))
        approve(manager, ws, plan)
        assert (await manager.execute_plan(ws.id, plan.id, execute_payload())).status == "completed"
        before = len(calls)
        manager.provider = None if mode == "missing" else BrokenProvider(mode)
        with pytest.raises(Conflict, match="Required model planner unavailable"):
            await manager.next_plan(ws.id, plan.id)
        assert len(calls) == before and manager.store.get_plan(ws.id, plan.id).status == "completed"
        assert manager.store.list_plans(ws.id, 50, 0).total == 1
        manager.provider = SelectingProvider()
        child = await manager.next_plan(ws.id, plan.id)
        assert child.require_model and child.planner == "model" and child.status == "awaiting_approval"
        assert manager.store.get_plan(ws.id, child.id).require_model

    try:
        asyncio.run(scenario())
    finally:
        repo.close()


def test_api_strict_mode_rejects_missing_model_and_non_boolean(clean_profile_env):
    from test_phase4c_api import OPENAPI, client, policy, vbase, workspace

    with client() as c:
        ws = workspace(c)
        pid = policy(c, ws)
        request = {"policy_id": pid, "source": "openapi", "openapi_document": OPENAPI,
                   "require_model": True}
        assert c.post(f"{vbase(ws)}/plans", json=request).status_code == 409
        request["require_model"] = "true"
        rejected = c.post(f"{vbase(ws)}/plans", json=request)
        assert rejected.status_code == 422 and rejected.json() == {"detail": "Invalid verification request"}
        assert c.get(f"{vbase(ws)}/plans").json()["total"] == 0


def test_cli_strict_flag_reaches_model_plan_and_persisted_plan(clean_profile_env, tmp_path, capsys):
    from test_phase4c_api import client, policy, workspace
    from test_web_top10 import SPEC

    from crimsonweb.web_cli import main

    document = tmp_path / "synthetic.json"
    document.write_text(json.dumps(SPEC), encoding="utf-8")
    with client() as c:
        ws = workspace(c)
        pid = policy(c, ws, target_scope=configuration().target_scope.model_dump())
        manager = c.app.state.verification_service
        manager.provider = SelectingProvider()

        def handler(request):
            return c.request(request.method, request.url.path, content=request.content, headers=dict(request.headers))

        assert main(["plan", "--workspace", ws, "--policy", pid, "--openapi", str(document),
                     "--catalog", "xss_reflection_probe", "--require-model"],
                    transport=httpx.MockTransport(handler)) == 0
        response = json.loads(capsys.readouterr().out)
        assert response["planner"] == "model"
        assert manager.store.get_plan(ws, response["plan_id"]).require_model


@pytest.mark.parametrize("changed", [{"require_model": False}, {"planner": "operator"}])
def test_store_rejects_follow_up_that_drops_strict_model_contract(changed):
    repo, _, ws, pid, manager = setup(configuration=configuration())
    manager.provider = SelectingProvider()
    try:
        request = payload(pid, ["web_security_observation"]).model_copy(update={"require_model": True})
        parent = asyncio.run(manager.create_plan(ws.id, request))
        parent = manager.store.set_status(ws.id, parent.id, "completed", manager.clock())
        child = parent.model_copy(update={"id": uuid4(), "parent_plan_id": parent.id,
                                         "round_number": 2, "status": "awaiting_approval", **changed})
        with pytest.raises(Conflict):
            manager.store.create_plan(child)
        assert manager.store.list_plans(ws.id, 50, 0).total == 1
    finally:
        repo.close()


def test_legacy_persisted_plan_without_new_field_remains_readable():
    from crimsonweb.api.verification.models import VerificationPlan

    repo, _, ws, pid, manager = setup(configuration=configuration())
    try:
        plan = asyncio.run(manager.create_plan(ws.id, payload(pid, ["web_security_observation"])))
        stored = plan.model_dump(mode="json")
        stored.pop("require_model")
        assert VerificationPlan.model_validate(stored).require_model is False
    finally:
        repo.close()


@pytest.mark.skipif(os.name != "nt", reason="Windows process profile helper")
@pytest.mark.parametrize("profile,model", [("gemma-web", "gemma4:26b"), ("qwen-web", "qwen3.5:9b")])
def test_powershell_helper_sets_profile_without_secret_output_or_parent_environment_changes(profile, model):
    shell = shutil.which("pwsh") or shutil.which("powershell")
    assert shell, "PowerShell required for Windows profile helper"
    script = Path(__file__).resolve().parents[1] / "scripts" / "Set-LocalAIProfile.ps1"
    before = {name: os.environ.get(name) for name in PROFILE_VARIABLES}
    environment = os.environ.copy()
    environment.update(CRIMSON_API_TOKEN="SYNTHETIC_PROFILE_TOKEN",
                       CRIMSON_OLLAMA_THINK="", CRIMSON_AI_MAX_CONCURRENCY="4")
    completed = subprocess.run([shell, "-NoProfile", "-NonInteractive", "-File", str(script),
                                "-Profile", profile, "-PassThru"], env=environment,
                               capture_output=True, text=True, timeout=30, check=False)
    assert completed.returncode == 0
    assert "SYNTHETIC_PROFILE_TOKEN" not in completed.stdout + completed.stderr
    settings = json.loads(completed.stdout)
    assert settings["model"] == model and settings["thinking"] is False
    assert settings["max_concurrency"] == 1 and settings["context_tokens"] == 8192
    assert settings["max_output_tokens"] == 4096 and settings["timeout_seconds"] == 300
    assert {name: os.environ.get(name) for name in PROFILE_VARIABLES} == before
