import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from crimsonweb.audit import redact_cli_args  # noqa: E402


class AuditRedactionTests(unittest.TestCase):
    def test_redacts_space_separated_secret_options(self) -> None:
        cli = redact_cli_args(["crimson", "--tor-control-password", "secret", "-t", "localhost"])

        self.assertIn("--tor-control-password <redacted>", cli)
        self.assertNotIn("secret", cli)

    def test_redacts_equals_form_secret_options(self) -> None:
        cli = redact_cli_args(["crimson", "--nvd-api-key=abc123", "-t", "localhost"])

        self.assertIn("--nvd-api-key=<redacted>", cli)
        self.assertNotIn("abc123", cli)

    def test_redacts_proxy_credentials(self) -> None:
        cli = redact_cli_args(
            ["crimson", "--web-proxy", "http://user:pass@127.0.0.1:8080", "--web-only"]
        )

        self.assertIn("--web-proxy <redacted>", cli)
        self.assertNotIn("user:pass", cli)


if __name__ == "__main__":
    unittest.main()
