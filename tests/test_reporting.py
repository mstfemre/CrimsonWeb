import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from crimsonweb.models import ServiceResult, Target, WebFinding  # noqa: E402
from crimsonweb.reporting import web_finding_count, write_executive_report  # noqa: E402


class ReportingTests(unittest.TestCase):
    def test_web_finding_count_sums_web_findings(self) -> None:
        result = ServiceResult(
            port=80,
            service="http",
            version="nginx",
            sensitive_paths=[WebFinding(path="/.env", status=200, size=12)],
            cors_findings=[{"severity": "HIGH"}],
        )

        self.assertEqual(web_finding_count(result), 2)

    def test_write_executive_report_creates_markdown(self) -> None:
        target = Target(original="localhost", address="127.0.0.1")
        results = {
            80: ServiceResult(
                port=80,
                service="http",
                version="nginx",
                sensitive_paths=[WebFinding(path="/.env", status=200, size=12)],
            )
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.executive.md"
            raw = Path(tmpdir) / "report.json"
            write_executive_report(
                target=target,
                results=results,
                engagement_id="school-project",
                scan_mode="web-only",
                web_policy={"egress": {"mode": "direct", "nodes": []}, "blocked_targets": []},
                raw_report_path=raw,
                output_path=output,
                tool_name="CrimsonWeb",
                tool_version="test",
            )
            content = output.read_text(encoding="utf-8")

        self.assertIn("school-project", content)
        self.assertIn("CrimsonWeb vtest", content)
        self.assertIn("/.env", content)


if __name__ == "__main__":
    unittest.main()
