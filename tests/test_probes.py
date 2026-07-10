import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from crimsonweb.models import ServiceResult  # noqa: E402
from crimsonweb.probes.builtin import (  # noqa: E402
    ACTIVE_PROBE_REGISTRY,
    detect_waf,
    port_hint_result,
    result_from_active_probe_response,
    service_result_from_greeting,
)
from crimsonweb.probes.registry import ProbeRegistry  # noqa: E402


class ProbeRegistryTests(unittest.TestCase):
    def test_registry_rejects_duplicate_and_empty_payload(self):
        registry = ProbeRegistry().register("probe-a", b"abc")

        with self.assertRaises(ValueError):
            registry.register("probe-a", b"def")
        with self.assertRaises(ValueError):
            registry.register("probe-b", b"")

    def test_builtin_registry_contains_expected_probe_names(self):
        names = {probe.name for probe in ACTIVE_PROBE_REGISTRY}

        self.assertIn("tls_client_hello", names)
        self.assertIn("rdp_routing_token", names)
        self.assertIn("smbv2_negotiate", names)


class BuiltinProbeClassifierTests(unittest.TestCase):
    def test_detect_waf_from_headers(self):
        self.assertEqual(detect_waf({"server": "cloudflare", "cf-ray": "abc"}), "cloudflare")
        self.assertIsNone(detect_waf({"server": "nginx"}))

    def test_greeting_classifiers(self):
        self.assertEqual(
            service_result_from_greeting(22, b"SSH-2.0-OpenSSH_8.9\r\n").service,
            "ssh",
        )
        self.assertEqual(
            service_result_from_greeting(21, b"220 vsftpd 3.0.5 ready\r\n").service,
            "ftp",
        )
        self.assertEqual(
            service_result_from_greeting(25, b"220 postfix ESMTP ready\r\n").service,
            "smtp",
        )
        self.assertEqual(
            service_result_from_greeting(110, b"+OK Dovecot ready\r\n").service,
            "pop3",
        )
        self.assertEqual(
            service_result_from_greeting(3306, b"\x00\x00mysql_native_password\x005.7.31-log" ).service,
            "mysql",
        )
        self.assertIsNone(service_result_from_greeting(12345, b"unknown banner"))

    def test_active_probe_response_classifiers(self):
        self.assertEqual(result_from_active_probe_response(443, "tls", b"\x16\x03\x03").service, "tls")
        self.assertEqual(result_from_active_probe_response(3389, "rdp", b"\x03\x00\x00\x13abc").service, "rdp")
        self.assertEqual(result_from_active_probe_response(445, "smb", b"xxxx\xFE\x53\x4D\x42").service, "smb")

        proprietary = result_from_active_probe_response(1234, "custom", b"hello service")
        self.assertEqual(proprietary.service, "proprietary")
        self.assertIn("custom:", proprietary.version)
        self.assertIsNone(result_from_active_probe_response(1234, "custom", b""))

    def test_port_hint_preserves_original_banner_note(self):
        prior = ServiceResult(port=31337, service="unknown", version="raw banner value")

        hinted = port_hint_result(31337, prior)

        self.assertIsNotNone(hinted)
        self.assertEqual(hinted.service, "elite")
        self.assertIn("Original banner: raw banner value", hinted.notes)
        self.assertIn("Service name assigned by port heuristic", hinted.notes)


if __name__ == "__main__":
    unittest.main()
