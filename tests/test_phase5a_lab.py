import asyncio
import json
import socket
from contextlib import ExitStack

import pytest
from privacy_helpers import request, setup, wait
from privacy_lab_helpers import dns_lab, echo_lab
from workspace_helpers import policy

from crimsonweb.api.scope import ScopeError
from crimsonweb.api.workspaces.dns import SystemResolver


@pytest.mark.parametrize(
    "expected,status",
    [
        ("127.0.0.1", "secure_observed"),
        ("127.0.0.2", "leak_validated"),
    ],
)
def test_controlled_dns_receipts_establish_only_the_application_path(expected, status):
    with dns_lab() as (resolver, receipts):

        async def run():
            repo, _, ws, program, profile, service = setup(
                resolver=resolver,
                profile_changes={
                    "dns_expectations": {
                        "approved_resolvers": [expected],
                        "path": "application",
                    }
                },
            )
            try:
                await service.startup()
                job = await service.start(ws.id, profile.id, request(program.id, "dns"))
                result = await wait(service, ws.id, job.id)
                evidence = service.store.evidence(
                    ws.id, result.evidence_refs[0].split(":")[1]
                )
                assert result.status == status and evidence.path_observed
                assert evidence.path_observation_source == "controlled_packet_capture"
                assert (
                    evidence.observed_resolver_fingerprints
                    == evidence.resolver_fingerprints
                )
                assert evidence.ipv4_answer_count == evidence.ipv6_answer_count == 1
                assert receipts == ["A", "AAAA"]
                assert (
                    not evidence.system_resolution_tested
                    and not evidence.proxy_dns_tested
                )
                assert "127.0.0.1" not in json.dumps(evidence.model_dump(mode="json"))
                assert not result.anonymity_guaranteed
            finally:
                await service.shutdown()
                repo.close()

        asyncio.run(run())


@pytest.mark.parametrize(
    "mode,status,reason",
    [
        ("timeout", "inconclusive", "dns_unavailable"),
        ("inconsistent", "inconclusive", "dns_unavailable"),
    ],
)
def test_controlled_dns_errors_fail_closed(mode, status, reason):
    with dns_lab(mode) as (resolver, receipts):

        async def run():
            repo, _, ws, program, profile, service = setup(resolver=resolver)
            try:
                if mode == "inconsistent":
                    with pytest.raises(ScopeError, match="inconsistent_dns_answers"):
                        await resolver.resolve("lab.test")
                    receipts.clear()
                await service.startup()
                job = await service.start(ws.id, profile.id, request(program.id, "dns"))
                result = await wait(service, ws.id, job.id)
                assert result.status == status and result.reason == reason and receipts
                assert result.requests_made == 0
            finally:
                await service.shutdown()
                repo.close()

        asyncio.run(run())


def test_ip_literal_is_not_claimed_as_a_dns_query_or_egress_observation():
    async def run():
        repo, _, ws, program, profile, service = setup(
            resolver=SystemResolver(),
            privacy_changes={"verification_urls": ["http://127.0.0.1/echo"]},
        )
        try:
            await service.startup()
            job = await service.start(
                ws.id,
                profile.id,
                request(program.id, "dns", verification_url="http://127.0.0.1/echo"),
            )
            result = await wait(service, ws.id, job.id)
            evidence = service.store.evidence(
                ws.id, result.evidence_refs[0].split(":")[1]
            )
            assert (
                result.status == "not_tested"
                and result.reason == "dns_not_tested_for_ip_literal"
            )
            assert (
                not evidence.application_resolution_tested
                and not evidence.path_observed
            )
            assert evidence.ipv4_answer_count == evidence.ipv6_answer_count == 0
        finally:
            await service.shutdown()
            repo.close()

    asyncio.run(run())


@pytest.mark.parametrize("ipv6", [False, True])
def test_real_loopback_egress_preserves_pinning_and_distinguishes_native_ipv6(ipv6):
    if ipv6:
        try:
            with socket.socket(socket.AF_INET6) as probe:
                probe.bind(("::1", 0))
        except OSError:
            pytest.skip(
                "This host has no IPv6 loopback socket; no IPv6 protection claim"
            )
    with ExitStack() as stack:
        port, received = stack.enter_context(echo_lab(ipv6))
        url = f"http://[::1]:{port}/echo" if ipv6 else f"http://lab.test:{port}/echo"
        configuration = policy()
        configuration.target_scope.allowed_ports.append(port)

        async def run():
            repo, _, ws, program, profile, service = setup(
                configuration=configuration,
                resolver=SystemResolver() if ipv6 else None,
                profile_changes={
                    "approved_egress_identity": ["127.0.0.1"],
                    "ipv6_expectation": "forbidden",
                },
                privacy_changes={"verification_urls": [url], "allow_ipv6_probe": ipv6},
            )
            service.transport = None
            try:
                await service.startup()
                job = await service.start(
                    ws.id,
                    profile.id,
                    request(
                        program.id,
                        verification_url=url,
                        family="ipv6" if ipv6 else "ipv4",
                    ),
                )
                result = await wait(service, ws.id, job.id)
                evidence = service.store.evidence(
                    ws.id, result.evidence_refs[0].split(":")[1]
                )
                assert (
                    result.execution_status == "completed" and result.requests_made == 1
                )
                assert evidence.connection_family == ("ipv6" if ipv6 else "ipv4")
                assert result.status == (
                    "leak_validated" if ipv6 else "secure_observed"
                )
                assert len(received) == 1 and received[0][0] == "/echo"
                assert received[0][1] == (
                    f"[::1]:{port}" if ipv6 else f"lab.test:{port}"
                )
                assert not evidence.route_verified and not evidence.interface_verified
                assert "PRIVATE_SESSION" not in json.dumps(
                    evidence.model_dump(mode="json")
                )
            finally:
                await service.shutdown()
                repo.close()

        asyncio.run(run())
