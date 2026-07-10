import types
import unittest

from crimsonweb.egress import (
    DecoyInjector,
    EgressKind,
    EgressMode,
    EgressNode,
    EgressPool,
    build_egress_from_args,
    build_pool_tor_only,
    parse_status_codes,
    redact_proxy_url,
)


class EgressTests(unittest.TestCase):
    def test_redact_proxy_url_masks_credentials(self):
        redacted = redact_proxy_url("http://user:secret@127.0.0.1:8080")

        self.assertEqual(redacted, "http://<credentials>@127.0.0.1:8080")
        self.assertNotIn("user:secret", redacted)

    def test_tor_proxy_requires_remote_dns_scheme(self):
        with self.assertRaises(SystemExit):
            build_pool_tor_only("socks5://127.0.0.1:9050")

        pool = build_pool_tor_only("socks5h://127.0.0.1:9050")
        self.assertEqual(pool.mode, EgressMode.TOR_ONLY)

    def test_parse_status_codes(self):
        self.assertEqual(parse_status_codes(None), {403, 429, 503})
        self.assertEqual(parse_status_codes("401, 429"), {401, 429})

        with self.assertRaises(SystemExit):
            parse_status_codes("abc")
        with self.assertRaises(SystemExit):
            parse_status_codes("99")

    def test_multi_egress_prefers_tor_for_sensitive_urls(self):
        pool = EgressPool(
            [
                EgressNode(
                    id="proxy-a",
                    kind=EgressKind.PROXY,
                    url="http://127.0.0.1:8080",
                    role="general",
                ),
                EgressNode(
                    id="tor-a",
                    kind=EgressKind.TOR,
                    url="socks5h://127.0.0.1:9050",
                    role="sensitive",
                ),
            ],
            mode=EgressMode.MULTI_EGRESS,
        )

        selected = pool.select("https://example.test/login")

        self.assertIsNotNone(selected)
        self.assertEqual(selected.kind, EgressKind.TOR)

    def test_decoy_rate_is_clamped(self):
        self.assertEqual(DecoyInjector(rate=2.0, paths=["/"]).rate, 1.0)
        self.assertEqual(DecoyInjector(rate=-1.0, paths=["/"]).rate, 0.0)

    def test_legacy_args_direct_mode_when_no_proxy_flags(self):
        args = types.SimpleNamespace(
            web_tor=False,
            egress_config=None,
            web_proxy=None,
            web_proxy_file=None,
            tor_new_identity=False,
            tor_control_password=None,
            tor_control_cookie=None,
        )

        pool = build_egress_from_args(args)

        self.assertEqual(pool.mode, EgressMode.DIRECT)


if __name__ == "__main__":
    unittest.main()
