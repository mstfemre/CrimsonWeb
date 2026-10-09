"""Fresh A/AAAA answers and their complete CNAME chains from OS-configured DNS."""

import asyncio
import ipaddress
from dataclasses import dataclass
from typing import Protocol

import dns.asyncresolver
import dns.exception
import dns.rdatatype
import dns.resolver

from ..scope import ScopeError
from .models import domain_name


@dataclass(frozen=True)
class Resolution:
    addresses: tuple[str, ...]
    cnames: tuple[str, ...] = ()


class Resolver(Protocol):
    async def resolve(self, host: str) -> Resolution: ...


def answer_chain(answer, host: str) -> tuple[str, ...]:
    current = host
    chain = []
    aliases = {}
    for rrset in answer.response.answer:
        if rrset.rdtype == dns.rdatatype.DNAME:
            raise ScopeError("unsupported_dns_alias")
        if rrset.rdtype == dns.rdatatype.CNAME:
            if len(rrset) != 1:
                raise ScopeError("invalid_dns_chain")
            aliases[rrset.name.to_text().rstrip(".").lower()] = domain_name(
                rrset[0].target.to_text().rstrip(".")
            )
    while current in aliases:
        current = aliases[current]
        if current == host or current in chain or len(chain) >= 8:
            raise ScopeError("invalid_dns_chain")
        chain.append(current)
    if current != answer.canonical_name.to_text().rstrip(".").lower():
        raise ScopeError("incomplete_dns_chain")
    if answer.rrset and current != answer.rrset.name.to_text().rstrip(".").lower():
        raise ScopeError("invalid_dns_chain")
    return tuple(chain)


class SystemResolver:
    async def resolve(self, host: str) -> Resolution:
        try:
            return Resolution((str(ipaddress.ip_address(host)),))
        except ValueError:
            domain_name(host)
        try:
            resolver = dns.asyncresolver.Resolver()
        except dns.exception.DNSException as exc:
            raise ScopeError("dns_unavailable") from exc
        resolver.cache = None
        addresses = set()
        chains = []
        try:
            async with asyncio.timeout(5):
                for kind in ("A", "AAAA"):
                    try:
                        answer = await resolver.resolve(
                            host + ".",
                            kind,
                            search=False,
                            raise_on_no_answer=False,
                            lifetime=4,
                        )
                    except dns.resolver.NXDOMAIN as exc:
                        raise ScopeError("dns_unknown") from exc
                    chain = answer_chain(answer, host)
                    chains.append(chain)
                    if answer.rrset:
                        addresses.update(
                            str(ipaddress.ip_address(item.address)) for item in answer
                        )
        except (TimeoutError, dns.exception.DNSException, OSError) as exc:
            raise ScopeError("dns_unavailable") from exc
        if not addresses or chains[0] != chains[1]:
            raise ScopeError("inconsistent_dns_answers")
        return Resolution(tuple(sorted(addresses)), chains[0])
