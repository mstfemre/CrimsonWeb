"""Fixed, code-defined test catalog. The LLM planner may only select these ids.

The catalog includes BOLA, inert HTML reflection, SQL error differential and
configuration observations. No writes, script execution, extraction or delays.
"""

from dataclasses import dataclass

READ_ONLY_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    category: str
    method: str
    title: str
    description: str
    requires_object_identifier: bool
    requires_query_parameter: bool = False

    def __post_init__(self) -> None:
        # Defence in depth: the catalog can never hold a state-changing test.
        if self.method not in READ_ONLY_METHODS:
            raise ValueError("Catalog entries must be read-only")


_CATALOG: dict[str, CatalogEntry] = {
    entry.id: entry
    for entry in (
        CatalogEntry(
            id="bola_cross_owner_read",
            category="auth",
            method="GET",
            title="Read-only cross-owner object access",
            description=(
                "Compare a read of an owner-scoped object by its owner against the "
                "same read attempted by a second authorized test identity, to check "
                "whether object-level authorization is enforced."
            ),
            requires_object_identifier=True,
        ),
        CatalogEntry(
            id="xss_reflection_probe", category="xss", method="GET",
            title="Inert HTML reflection comparison",
            description="Compare a baseline and inert HTML marker; never execute script or confirm XSS.",
            requires_object_identifier=False, requires_query_parameter=True,
        ),
        CatalogEntry(
            id="sql_error_probe", category="sqli", method="GET",
            title="Bounded SQL error differential",
            description="Compare baseline, inert invalid value and quote; no extraction, delays or writes.",
            requires_object_identifier=False, requires_query_parameter=True,
        ),
        CatalogEntry(
            id="web_security_observation", category="web_observation", method="GET",
            title="HTTP configuration and negotiated TLS observations",
            description="Reuse existing header, cookie, CORS and TLS analysis; configuration signals only.",
            requires_object_identifier=False,
        ),
    )
}


def catalog_ids() -> list[str]:
    return sorted(_CATALOG)


def catalog_entry(entry_id: str) -> CatalogEntry | None:
    return _CATALOG.get(entry_id)
