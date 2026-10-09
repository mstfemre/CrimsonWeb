"""Observe the existing resolver, without selecting a new routing/DNS path."""

import ipaddress

import dns.asyncresolver
import dns.exception

from ..workspaces.dns import SystemResolver


class ObservedResolver:
    def __init__(self, get_delegate):
        self.get_delegate = get_delegate
        self.last = {}

    def configuration(self, delegate):
        if isinstance(delegate, SystemResolver):
            try:
                values = dns.asyncresolver.Resolver().nameservers
                return "os_configured_application", [
                    str(ipaddress.ip_address(v)) for v in values if isinstance(v, str)
                ][:16]
            except (ValueError, OSError, dns.exception.DNSException):
                return "unknown", []
        method = getattr(delegate, "privacy_diagnostics", None)
        if method:
            data = method()
            if isinstance(data, dict):
                try:
                    return "provider_reported", [
                        str(ipaddress.ip_address(v))
                        for v in data.get("configured_resolvers", [])
                    ][:16]
                except (ValueError, TypeError):
                    pass
        return "unknown", []

    async def resolve(self, host):
        delegate = self.get_delegate()
        source, configured = self.configuration(delegate)
        try:
            ipaddress.ip_address(host)
            literal_target = True
        except ValueError:
            literal_target = False
        self.last = {
            "literal_target": literal_target,
            "configuration_source": source,
            "configured": configured,
            "path_observed": False,
            "observed": [],
            "addresses": (),
            "cnames": (),
        }
        result = await delegate.resolve(host)
        self.last.update(addresses=result.addresses, cnames=result.cnames)
        method = getattr(delegate, "privacy_diagnostics", None)
        if method and not literal_target:
            data = method()
            if (
                isinstance(data, dict)
                and data.get("source") == "controlled_packet_capture"
                and data.get("path_observed") is True
            ):
                try:
                    observed = [
                        str(ipaddress.ip_address(v))
                        for v in data.get("observed_resolvers", [])
                    ][:16]
                    if observed:
                        self.last.update(path_observed=True, observed=observed)
                except (ValueError, TypeError):
                    pass
        return result
