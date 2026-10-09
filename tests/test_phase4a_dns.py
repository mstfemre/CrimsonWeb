import asyncio
from unittest.mock import AsyncMock, patch

import dns.message
import dns.name
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest

from crimsonweb.api.scope import ScopeError
from crimsonweb.api.workspaces.dns import SystemResolver, answer_chain


def answer(kind="A", aliases=(), address="127.0.0.1"):
    name = "lab.test"
    query = dns.message.make_query(name, kind)
    response = dns.message.make_response(query)
    for target in aliases:
        response.answer.append(
            dns.rrset.from_text(name + ".", 60, "IN", "CNAME", target + ".")
        )
        name = target
    if address is not None:
        response.answer.append(dns.rrset.from_text(name + ".", 60, "IN", kind, address))
    return dns.resolver.Answer(
        dns.name.from_text("lab.test"),
        dns.rdatatype.from_text(kind),
        dns.rdataclass.IN,
        dns.message.from_wire(response.to_wire()),
    )


def test_system_resolver_full_chain_and_both_address_families():
    resolver = AsyncMock()
    aliases = ("cdn.lab.test", "origin.lab.test")
    resolver.resolve.side_effect = [
        answer(aliases=aliases),
        answer("AAAA", aliases, "::1"),
    ]
    with patch("dns.asyncresolver.Resolver", return_value=resolver):
        result = asyncio.run(SystemResolver().resolve("lab.test"))
    assert result.addresses == ("127.0.0.1", "::1")
    assert result.cnames == aliases and resolver.cache is None
    assert [call.args for call in resolver.resolve.call_args_list] == [
        ("lab.test.", "A"),
        ("lab.test.", "AAAA"),
    ]
    assert all(
        call.kwargs["search"] is False for call in resolver.resolve.call_args_list
    )


def test_nodata_ipv6_answer_is_supported():
    resolver = AsyncMock()
    resolver.resolve.side_effect = [answer(), answer("AAAA", address=None)]
    with patch("dns.asyncresolver.Resolver", return_value=resolver):
        assert asyncio.run(SystemResolver().resolve("lab.test")).addresses == (
            "127.0.0.1",
        )


def test_inconsistent_family_alias_chains_rejected():
    resolver = AsyncMock()
    resolver.resolve.side_effect = [
        answer(aliases=("cdn.lab.test",)),
        answer("AAAA", address=None),
    ]
    with (
        patch("dns.asyncresolver.Resolver", return_value=resolver),
        pytest.raises(ScopeError, match="inconsistent_dns_answers"),
    ):
        asyncio.run(SystemResolver().resolve("lab.test"))


@pytest.mark.parametrize(
    "error", [dns.resolver.NXDOMAIN(), dns.resolver.NoNameservers(), TimeoutError()]
)
def test_dns_failure_is_safe_and_closed(error):
    resolver = AsyncMock()
    resolver.resolve.side_effect = error
    with (
        patch("dns.asyncresolver.Resolver", return_value=resolver),
        pytest.raises(ScopeError),
    ):
        asyncio.run(SystemResolver().resolve("lab.test"))


def test_literals_do_not_issue_dns_requests():
    with patch(
        "dns.asyncresolver.Resolver", side_effect=AssertionError("DNS must not run")
    ):
        assert asyncio.run(SystemResolver().resolve("127.0.0.1")).addresses == (
            "127.0.0.1",
        )
        assert asyncio.run(SystemResolver().resolve("::1")).addresses == ("::1",)


def test_dns_dname_unsupported_fail_closed():
    item = answer()
    item.response.answer.append(
        dns.rrset.from_text("lab.test", 60, "IN", "DNAME", "outside.test")
    )
    with pytest.raises(ScopeError, match="unsupported_dns_alias"):
        answer_chain(item, "lab.test")


def test_dns_incomplete_chain_rejected():
    item = answer(aliases=("cdn.lab.test",))
    item.response.answer.pop(0)
    with pytest.raises(ScopeError, match="incomplete_dns_chain"):
        answer_chain(item, "lab.test")


def test_alias_chain_limit():
    item = answer(aliases=tuple(f"s{i}.lab.test" for i in range(9)))
    with pytest.raises(ScopeError, match="invalid_dns_chain"):
        answer_chain(item, "lab.test")


def test_missing_dns_configuration_denies_safely():
    with (
        patch(
            "dns.asyncresolver.Resolver",
            side_effect=dns.resolver.NoResolverConfiguration(),
        ),
        pytest.raises(ScopeError, match="dns_unavailable"),
    ):
        asyncio.run(SystemResolver().resolve("lab.test"))
