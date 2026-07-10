import contextlib
import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from crimsonweb.cli_commands import (  # noqa: E402
    CONFIG_ENV_VAR,
    default_config_path,
    normalize_command_argv,
    run_config,
    run_doctor,
)
from crimsonweb.core_engine import build_parser, validate_args  # noqa: E402


def parse_scan_args(argv):
    command, parser_argv = normalize_command_argv(argv)
    args = build_parser().parse_args(parser_argv)
    args.command = command
    if command == "web":
        args.web_only = True
    validate_args(args)
    return command, args


class CliCommandTests(unittest.TestCase):
    def test_legacy_invocation_maps_to_scan(self):
        command, args = parse_scan_args(["-t", "127.0.0.1", "-p", "80"])

        self.assertEqual(command, "scan")
        self.assertEqual(args.target, "127.0.0.1")

    def test_scan_subcommand_preserves_scan_options(self):
        command, args = parse_scan_args(["scan", "-t", "localhost", "--top-ports", "--top-ports-count", "10"])

        self.assertEqual(command, "scan")
        self.assertEqual(args.target, "localhost")
        self.assertTrue(args.top_ports)
        self.assertEqual(args.top_ports_count, 10)

    def test_web_subcommand_accepts_positional_url_and_forces_web_only(self):
        command, args = parse_scan_args(["web", "http://localhost:8000"])

        self.assertEqual(command, "web")
        self.assertEqual(args.target, "localhost")
        self.assertEqual(args.ports, "8000")
        self.assertTrue(args.web_only)

    def test_utility_commands_are_detected(self):
        self.assertEqual(normalize_command_argv(["doctor"]), ("doctor", []))
        self.assertEqual(normalize_command_argv(["config", "path"]), ("config", ["path"]))
        self.assertEqual(normalize_command_argv(["init", "--force"]), ("init", ["--force"]))

    def test_config_init_uses_env_override(self):
        old_value = os.environ.get(CONFIG_ENV_VAR)
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "crimson.yaml"
            os.environ[CONFIG_ENV_VAR] = str(config_path)
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    code = run_config(["init"])
                self.assertEqual(code, 0)
                self.assertEqual(default_config_path(), config_path)
                self.assertTrue(config_path.exists())
                self.assertIn("scan:", config_path.read_text(encoding="utf-8"))
            finally:
                if old_value is None:
                    os.environ.pop(CONFIG_ENV_VAR, None)
                else:
                    os.environ[CONFIG_ENV_VAR] = old_value

    def test_doctor_json_returns_status_code(self):
        with contextlib.redirect_stdout(io.StringIO()) as stdout:
            code = run_doctor(["--json"], version="test")

        self.assertIn(code, {0, 1})
        self.assertIn('"version": "test"', stdout.getvalue())

    def test_cli_module_invocation_shows_help(self):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")

        result = subprocess.run(
            [sys.executable, "-m", "crimsonweb.cli", "--help"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )

        self.assertEqual(result.returncode, 0)
        self.assertIn("usage: crimsonweb", result.stdout)


if __name__ == "__main__":
    unittest.main()
