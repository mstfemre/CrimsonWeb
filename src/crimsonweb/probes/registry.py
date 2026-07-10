"""Small registry abstraction for service fingerprint probe payloads."""

from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Iterable, Iterator


@dataclass(frozen=True, slots=True)
class ActiveProbe:
    name: str
    payload: bytes


class ProbeRegistry:
    def __init__(self, probes: Iterable[ActiveProbe] = ()) -> None:
        self._probes: list[ActiveProbe] = []
        self._names: set[str] = set()
        for probe in probes:
            self.register(probe.name, probe.payload)

    def register(self, name: str, payload: bytes) -> "ProbeRegistry":
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Probe name cannot be empty")
        if clean_name in self._names:
            raise ValueError(f"Duplicate probe name: {clean_name}")
        if not isinstance(payload, bytes) or not payload:
            raise ValueError(f"Probe payload for {clean_name} must be non-empty bytes")
        self._probes.append(ActiveProbe(clean_name, payload))
        self._names.add(clean_name)
        return self

    def items(self) -> tuple[ActiveProbe, ...]:
        return tuple(self._probes)

    def __iter__(self) -> Iterator[ActiveProbe]:
        return iter(self.items())

    def __len__(self) -> int:
        return len(self._probes)
