"""CPE extraction and NVD CVE lookup helpers."""

from __future__ import annotations

import asyncio
import os
import re
from collections import OrderedDict

try:
    import httpx
except ImportError as exc:
    httpx = None  # type: ignore[assignment]
    HTTPX_IMPORT_ERROR = exc
else:
    HTTPX_IMPORT_ERROR = None

try:
    from asyncio_throttle import Throttler
except ImportError as exc:
    Throttler = None  # type: ignore[assignment]
    THROTTLE_IMPORT_ERROR = exc
else:
    THROTTLE_IMPORT_ERROR = None


MAX_CVE_DESCRIPTION_LENGTH = 500
MAX_CVE_RESULTS_PER_QUERY = 3
MAX_CVE_CACHE_ENTRIES = 500
NVD_FREE_RATE_LIMIT = 90
NVD_API_KEY_RATE_LIMIT = 2000
NVD_RATE_PERIOD_SECONDS = 300

CPE_PRODUCT_MAP: dict[str, tuple[str, str]] = {
    "apache": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "apache tomcat": ("apache", "tomcat"),
    "nginx": ("nginx", "nginx"),
    "openssh": ("openbsd", "openssh"),
    "open ssh": ("openbsd", "openssh"),
    "microsoft-iis": ("microsoft", "iis"),
    "microsoft iis": ("microsoft", "iis"),
    "iis": ("microsoft", "iis"),
    "mysql": ("oracle", "mysql"),
    "mariadb": ("mariadb", "mariadb"),
    "postgresql": ("postgresql", "postgresql"),
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "pure-ftpd": ("pureftpd", "pure-ftpd"),
}

PRODUCT_SERVICES = {
    "http_server": {"http", "https"},
    "tomcat": {"http", "https"},
    "nginx": {"http", "https"},
    "iis": {"http", "https"},
    "openssh": {"ssh"},
    "mysql": {"mysql"},
    "mariadb": {"mysql", "mariadb"},
    "postgresql": {"postgresql"},
    "proftpd": {"ftp", "ftps"},
    "vsftpd": {"ftp", "ftps"},
    "pure-ftpd": {"ftp", "ftps"},
}


class CveLookup:
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, enabled: bool, concurrency: int = 3) -> None:
        self.enabled = enabled
        self.semaphore = asyncio.Semaphore(concurrency)
        self.cache: OrderedDict[str, list[dict[str, str]]] = OrderedDict()
        self._api_key = os.getenv("NVD_API_KEY")
        self._client = None
        if Throttler is not None:
            rate = NVD_API_KEY_RATE_LIMIT if self._api_key else NVD_FREE_RATE_LIMIT
            self.throttler = Throttler(rate_limit=rate, period=NVD_RATE_PERIOD_SECONDS)
        else:
            self.throttler = None

    def _api_headers(self) -> dict[str, str]:
        if not self._api_key:
            return {}
        return {"apiKey": self._api_key}

    def _http_client(self):
        if self._client is None and httpx is not None:
            self._client = httpx.AsyncClient(timeout=8)
        return self._client

    def _cache_store(self, key: str, value: list[dict[str, str]]) -> None:
        if key in self.cache:
            self.cache.move_to_end(key)
        self.cache[key] = value
        while len(self.cache) > MAX_CVE_CACHE_ENTRIES:
            self.cache.popitem(last=False)

    async def aclose(self) -> None:
        if self._client is None:
            return
        await self._client.aclose()
        self._client = None

    @staticmethod
    def _query_from_version(service: str, version: str) -> str | None:
        if version.lower() in {"unknown", "filtered", "no response", "open, no banner", "open, probe failed"}:
            return None
        if version.startswith("<Binary Data:"):
            return None
        parsed = CveLookup._extract_cpe_parts(version)
        if parsed is None:
            return None
        vendor, product, product_version = parsed
        allowed_services = PRODUCT_SERVICES.get(product)
        if allowed_services is not None and service.lower() not in allowed_services:
            return None
        return f"cpe:2.3:a:{vendor}:{product}:{product_version}:*:*:*:*:*:*:*"

    @staticmethod
    def _extract_cpe_parts(version: str) -> tuple[str, str, str] | None:
        cleaned = re.sub(r"[\r\n].*", "", version).strip()
        cleaned = re.sub(r"\([^)]*\)", "", cleaned)
        cleaned = re.sub(r"[,;]+", " ", cleaned)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        # Strip the SSH transport-banner prefix ("SSH-2.0-...") so the software
        # token (e.g. dropbear_2020.81, OpenSSH_8.9p1) is what the patterns see.
        cleaned = re.sub(r"^SSH-\d[\w.]*-", "", cleaned)
        if not cleaned or cleaned.startswith("<Binary Data:"):
            return None
        candidates = [
            # product<sep>version, where sep is "/", "_", "-", or whitespace.
            r"(?P<product>[A-Za-z][A-Za-z0-9+_. -]+)/(?P<version>\d+(?:[._-]\d+)*(?:[A-Za-z0-9._-]*)?)",
            r"(?P<product>[A-Za-z][A-Za-z0-9+]*)[-_](?P<version>\d+(?:[._-]\d+)*(?:[A-Za-z0-9._-]*)?)",
            r"(?P<product>[A-Za-z][A-Za-z0-9+_. -]+)\s+(?P<version>\d+(?:[._-]\d+)*(?:[A-Za-z0-9._-]*)?)",
        ]
        product_name = ""
        product_version = ""
        for pattern in candidates:
            match = re.search(pattern, cleaned, re.IGNORECASE)
            if match:
                product_name = re.sub(r"\s+", " ", match.group("product")).strip()
                product_version = match.group("version").strip()
                break
        if not product_name or not product_version:
            return None
        normalized = product_name.lower().replace("_", " ").replace("/", " ").strip()
        mapped = CPE_PRODUCT_MAP.get(normalized)
        if mapped is not None:
            vendor, product = mapped
        else:
            slug = normalized.replace(" ", "_")
            vendor = slug
            product = slug
        return vendor, product, product_version

    async def query(self, service: str, version: str, session=None) -> list[dict[str, str]]:
        if not self.enabled or httpx is None:
            return []
        virtual_match = self._query_from_version(service, version)
        if not virtual_match:
            return []
        if virtual_match in self.cache:
            self.cache.move_to_end(virtual_match)
            return self.cache[virtual_match]
        params = {"virtualMatchString": virtual_match, "resultsPerPage": MAX_CVE_RESULTS_PER_QUERY}
        client = self._http_client()
        if client is None:
            return []
        async with self.semaphore:
            try:
                if self.throttler is not None:
                    async with self.throttler:
                        response = await client.get(self.NVD_API, params=params, headers=self._api_headers())
                else:
                    response = await client.get(self.NVD_API, params=params, headers=self._api_headers())
                if response.status_code != 200:
                    self._cache_store(virtual_match, [])
                    return []
                payload = response.json()
            except (httpx.HTTPError, asyncio.TimeoutError, ValueError):
                self._cache_store(virtual_match, [])
                return []
        findings = []
        for item in payload.get("vulnerabilities", []):
            cve = item.get("cve", {})
            descriptions = cve.get("descriptions") or []
            description = descriptions[0].get("value", "N/A") if descriptions else "N/A"
            metrics = cve.get("metrics", {})
            severity = "unknown"
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    severity = metrics[key][0].get("cvssData", {}).get("baseSeverity", "unknown")
                    break
            findings.append({
                "id": cve.get("id", "unknown"),
                "severity": severity,
                "description": description[:MAX_CVE_DESCRIPTION_LENGTH],
            })
        self._cache_store(virtual_match, findings)
        return findings
