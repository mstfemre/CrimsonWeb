"""CLI drives the real local API contract with a fully synthetic target transport."""

import json
from uuid import UUID

import httpx
import pytest
from test_phase4c_api import (
    APPROVAL,
    OPENAPI,
    TOKEN_A,
    TOKEN_B,
    client,
    policy,
    workspace,
)

from crimsonweb import cli
from crimsonweb.web_cli import local_api, main


@pytest.mark.parametrize("url", ["https://outside.invalid", "http://localhost:8000",
                                 "http://user:secret@127.0.0.1", "http://127.0.0.1/private",
                                 "http://127.0.0.1/?token=secret"])
def test_client_rejects_non_loopback_or_credentialed_api_origin(url):
    with pytest.raises(ValueError):
        local_api(url)


def test_cli_plan_approve_execute_report_without_port_scan(tmp_path, capsys):
    spec = tmp_path / "synthetic.json"
    spec.write_text(json.dumps(OPENAPI), encoding="utf-8")
    with client() as c:
        ws = workspace(c)
        pid = policy(c, ws)

        def handler(request):
            assert request.url.host == "127.0.0.1"
            # Forward to the actual API; its target transport is the synthetic lab.
            return c.request(request.method, request.url.path,
                             content=request.content, headers=dict(request.headers))

        transport = httpx.MockTransport(handler)
        common = ["--workspace", ws]
        assert main(["plan", *common, "--policy", pid, "--openapi", str(spec)],
                    transport=transport) == 0
        output = capsys.readouterr()
        plan_id = json.loads(output.out)["plan_id"]
        UUID(plan_id)
        target = ["--base-url", APPROVAL["base_url"], "--binding-field", "owner_id"]
        planned = [*common, "--plan", plan_id]
        assert main(["approve", *planned, *target, "--approved-by", "op",
                     "--scope-source", "synthetic lab", "--private-records-only"],
                    transport=transport) == 0
        capsys.readouterr()
        secrets = iter(["111", TOKEN_A, "222", TOKEN_B])
        assert main(["execute", *planned, *target], transport=transport, interactive=True,
                    secret_reader=lambda prompt: next(secrets)) == 0
        assert main(["report", *planned], transport=transport) == 0
        output = capsys.readouterr()
        assert "tokA-secret" not in output.out + output.err
        assert "tokB-secret" not in output.out + output.err
        report = json.loads(output.out.splitlines()[-1])
        assert report["findings"] == 1 and report["results"][0]["outcome"] == "bola_confirmed"


def test_missing_api_token_never_opens_connection(monkeypatch, capsys):
    monkeypatch.delenv("CRIMSON_API_TOKEN", raising=False)
    ws = "11111111-1111-1111-1111-111111111111"
    calls = []
    assert main(["report", "--workspace", ws, "--plan", ws],
                transport=httpx.MockTransport(lambda r: calls.append(r))) == 2
    assert calls == []
    assert "Web workflow failed" in capsys.readouterr().err


def test_main_dispatches_web_workflow_and_preserves_legacy(monkeypatch):
    import crimsonweb.web_cli

    calls = []
    monkeypatch.setattr(crimsonweb.web_cli, "main", lambda args: calls.append(("web", args)) or 0)
    monkeypatch.setattr(cli, "legacy_main", lambda args: calls.append(("legacy", args)) or 0)
    cli.main(["web", "plan", "--help"])
    cli.main(["scan", "-t", "localhost"])
    cli.main(["web", "http://localhost:8000"])
    assert [kind for kind, _ in calls] == ["web", "legacy", "legacy"]
