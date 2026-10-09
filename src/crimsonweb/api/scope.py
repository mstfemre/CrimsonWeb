"""Validate every hop and connect to the validated address, avoiding DNS rebinding."""

import asyncio
import ipaddress
import os
import socket
from dataclasses import dataclass

import httpx


class ScopeError(ValueError):
    pass


@dataclass(frozen=True)
class Scope:
    hosts: tuple[str, ...] = ("localhost", "127.0.0.1", "::1")
    networks: tuple[str, ...] = ("127.0.0.0/8", "::1/128")

    def __post_init__(self) -> None:
        for network in self.networks:
            ipaddress.ip_network(network)

    @classmethod
    def from_env(cls) -> "Scope":
        defaults = cls()
        return cls(
            tuple(
                s.strip().lower()
                for s in os.getenv(
                    "CRIMSON_ALLOWED_HOSTS", ",".join(defaults.hosts)
                ).split(",")
                if s.strip()
            ),
            tuple(
                s.strip()
                for s in os.getenv(
                    "CRIMSON_ALLOWED_NETWORKS", ",".join(defaults.networks)
                ).split(",")
                if s.strip()
            ),
        )

    def snapshot(self) -> dict[str, list[str]]:
        return {"hosts": list(self.hosts), "networks": list(self.networks)}

    def validate_url(self, value: str) -> httpx.URL:
        url = self.parse_url(value)
        if url.host.lower() not in self.hosts:
            raise ScopeError("Host is outside the authorized scope")
        return url

    @staticmethod
    def parse_url(value: str) -> httpx.URL:
        if len(value) > 2048 or any(ord(c) < 32 for c in value) or "\\" in value:
            raise ScopeError("Invalid URL")
        try:
            url = httpx.URL(value)
            port = url.port
        except (httpx.InvalidURL, ValueError) as exc:
            raise ScopeError("Invalid URL") from exc
        if url.scheme not in {"http", "https"} or not url.host:
            raise ScopeError("An absolute HTTP(S) URL is required")
        if url.userinfo or url.fragment or url.query:
            raise ScopeError(
                "Credentials, fragments and query strings are not accepted"
            )
        if port is not None and not 1 <= port <= 65535:
            raise ScopeError("Invalid port")
        return url

    async def resolve(self, url: httpx.URL) -> list[str]:
        try:
            literal = ipaddress.ip_address(url.host)
            addresses = [str(literal)]
        except ValueError:
            records = await asyncio.wait_for(
                asyncio.get_running_loop().getaddrinfo(
                    url.host,
                    url.port or (443 if url.scheme == "https" else 80),
                    type=socket.SOCK_STREAM,
                ),
                timeout=5,
            )
            addresses = sorted(
                {str(ipaddress.ip_address(record[4][0])) for record in records}
            )
        if not addresses:
            raise ScopeError("DNS returned no addresses")
        networks = [ipaddress.ip_network(network) for network in self.networks]
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if (
                ip.is_unspecified
                or ip.is_multicast
                or not any(ip in n for n in networks)
            ):
                raise ScopeError("DNS address is outside the authorized networks")
        return addresses
