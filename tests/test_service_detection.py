import socket
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from crimsonweb.models import Target, WebResponse  # noqa: E402
from crimsonweb.service_detection import ServiceDetector  # noqa: E402


class DummyCveLookup:
    async def query(self, *_args, **_kwargs):
        return []


def detector_for(target: Target, web_controller=None) -> ServiceDetector:
    return ServiceDetector(
        target=target,
        concurrency=1,
        timeout=1.0,
        check_sensitive_paths=False,
        cve_lookup=DummyCveLookup(),
        web_controller=web_controller,
    )


class ServiceDetectionTests(unittest.TestCase):
    def test_http_url_uses_default_ports_and_ipv6_brackets(self):
        detector = detector_for(Target(original="example.test", address="127.0.0.1"))

        self.assertEqual(detector._http_url(80, tls=False), "http://example.test/")
        self.assertEqual(detector._http_url(8080, tls=False, path="/health"), "http://example.test:8080/health")

        ipv6_detector = detector_for(
            Target(original="2001:db8::10", address="2001:db8::10", family=socket.AF_INET6)
        )
        self.assertEqual(ipv6_detector._http_url(443, tls=True), "https://[2001:db8::10]/")

    def test_parse_headers_extracts_status_headers_and_title(self):
        raw = (
            "HTTP/1.1 200 OK\r\n"
            "Server: nginx\r\n"
            "X-Test: yes\r\n"
            "\r\n"
            "<html><title> Hello   World </title></html>"
        )

        status, headers, title = ServiceDetector._parse_headers(raw)

        self.assertEqual(status, 200)
        self.assertEqual(headers["server"], "nginx")
        self.assertEqual(headers["x-test"], "yes")
        self.assertEqual(title, "Hello World")

    def test_extract_title_from_bytes(self):
        self.assertEqual(ServiceDetector._extract_title(b"<title>Admin Login</title>"), "Admin Login")
        self.assertIsNone(ServiceDetector._extract_title(b"no title"))

    def test_result_from_web_response_sets_waf_title_and_egress_note(self):
        controller = SimpleNamespace(block_events=[])
        detector = detector_for(Target(original="example.test", address="127.0.0.1"), controller)
        response = WebResponse(
            url="https://example.test/",
            status=200,
            headers={"server": "cloudflare", "cf-ray": "abc"},
            body=b"<title>Home</title>",
            egress_id="direct",
        )

        result = detector._result_from_web_response(443, tls=True, response=response)

        self.assertEqual(result.service, "https")
        self.assertEqual(result.http_status, 200)
        self.assertEqual(result.title, "Home")
        self.assertEqual(result.waf, "cloudflare")
        self.assertIn("egress=direct", result.notes)


if __name__ == "__main__":
    unittest.main()
