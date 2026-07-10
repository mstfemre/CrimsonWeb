import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from crimsonweb.core_engine import build_parser, validate_args  # noqa: E402


class CliAuthorizationContextTests(unittest.TestCase):
    def test_roe_is_not_required_for_lab_target(self) -> None:
        args = build_parser().parse_args(["-t", "127.0.0.1", "-p", "80"])

        validate_args(args)

        self.assertEqual(args.target, "127.0.0.1")
        self.assertIsNone(args.roe_confirmed)

    def test_engagement_id_is_accepted_for_url_target(self) -> None:
        args = build_parser().parse_args(
            ["--engagement-id", "school-project", "-u", "http://localhost:8000"]
        )

        validate_args(args)

        self.assertEqual(args.target, "localhost")
        self.assertEqual(args.ports, "8000")
        self.assertTrue(args.web_only)
        self.assertEqual(args.roe_confirmed, "school-project")

    def test_legacy_roe_alias_still_works(self) -> None:
        args = build_parser().parse_args(["--roe", "legacy-ref", "-t", "localhost", "-p", "80"])

        validate_args(args)

        self.assertEqual(args.roe_confirmed, "legacy-ref")


if __name__ == "__main__":
    unittest.main()
