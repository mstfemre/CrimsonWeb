import asyncio
import unittest

from crimsonweb.cve import CveLookup, MAX_CVE_CACHE_ENTRIES


class CveLookupTests(unittest.TestCase):
    def test_query_from_http_banner_builds_cpe(self):
        cpe = CveLookup._query_from_version("http", "Apache/2.4.57 (Ubuntu)")

        self.assertEqual(cpe, "cpe:2.3:a:apache:http_server:2.4.57:*:*:*:*:*:*:*")

    def test_query_from_ssh_banner_builds_cpe(self):
        cpe = CveLookup._query_from_version("ssh", "OpenSSH_8.9p1 Ubuntu-3")

        self.assertEqual(cpe, "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*")

    def test_extraction_is_service_independent(self):
        # Whitelist removed: a parseable product yields a CPE regardless of the
        # service label it was seen on.
        self.assertEqual(
            CveLookup._query_from_version("ssh", "nginx/1.25.4"),
            "cpe:2.3:a:nginx:nginx:1.25.4:*:*:*:*:*:*:*",
        )

    def test_unparseable_banner_is_rejected(self):
        self.assertIsNone(CveLookup._query_from_version("ssh", "no-version-here"))

    def test_unknown_and_binary_versions_are_rejected(self):
        self.assertIsNone(CveLookup._query_from_version("http", "unknown"))
        self.assertIsNone(CveLookup._query_from_version("http", "<Binary Data: 010203>"))

    def test_disabled_lookup_returns_empty_without_network(self):
        lookup = CveLookup(enabled=False)

        result = asyncio.run(lookup.query("http", "Apache/2.4.57"))

        self.assertEqual(result, [])

    def test_cache_store_enforces_max_entries(self):
        lookup = CveLookup(enabled=False)

        for idx in range(MAX_CVE_CACHE_ENTRIES + 2):
            lookup._cache_store(f"cpe:{idx}", [])

        self.assertEqual(len(lookup.cache), MAX_CVE_CACHE_ENTRIES)
        self.assertNotIn("cpe:0", lookup.cache)
        self.assertNotIn("cpe:1", lookup.cache)


if __name__ == "__main__":
    unittest.main()
