import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from crimsonweb.web_checks import (  # noqa: E402
    CORS_TEST_ORIGIN,
    analyze_cookie_flags,
    analyze_security_headers,
    cors_findings_from_headers,
)


class WebChecksTests(unittest.TestCase):
    def test_security_headers_skip_hsts_on_plain_http(self) -> None:
        findings = analyze_security_headers({}, tls=False)
        names = {finding["name"] for finding in findings}

        self.assertNotIn("strict-transport-security", names)
        self.assertIn("content-security-policy", names)

    def test_security_headers_flags_short_hsts_max_age(self) -> None:
        findings = analyze_security_headers(
            {"strict-transport-security": "max-age=100", "x-content-type-options": "nosniff"},
            tls=True,
        )

        self.assertTrue(
            any(finding["name"] == "strict-transport-security" and finding["issue"] == "short_max_age"
                for finding in findings)
        )

    def test_cookie_flags_detect_missing_secure_httponly_samesite(self) -> None:
        findings = analyze_cookie_flags({"set-cookie": "sid=abc; Path=/"}, tls=True)

        self.assertEqual(findings[0]["name"], "sid")
        self.assertIn("missing HttpOnly", findings[0]["issues"])
        self.assertIn("missing Secure", findings[0]["issues"])
        self.assertIn("missing SameSite", findings[0]["issues"])

    def test_cors_reflection_with_credentials_is_high(self) -> None:
        findings = cors_findings_from_headers({
            "access-control-allow-origin": CORS_TEST_ORIGIN,
            "access-control-allow-credentials": "true",
        })

        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertTrue(findings[0]["allow_credentials"])

    def test_cors_wildcard_without_credentials_is_medium(self) -> None:
        findings = cors_findings_from_headers({"access-control-allow-origin": "*"})

        self.assertEqual(findings[0]["severity"], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
