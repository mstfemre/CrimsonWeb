import argparse
import socket
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from crimsonweb.ports import get_top_ports, parse_ports, target_from_args  # noqa: E402


def args_for(**overrides):
    values = {
        "top_ports": False,
        "top_ports_count": 1000,
        "ports": None,
        "start": 1,
        "end": 3,
        "target": "localhost",
        "web_only": False,
        "web_tor": False,
        "egress_config": None,
        "web_proxy": None,
        "web_proxy_file": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


class PortsTests(unittest.TestCase):
    def test_parse_explicit_ports_and_ranges(self) -> None:
        ports = parse_ports(args_for(ports="443,80,8000-8002,80"))

        self.assertEqual(ports, [80, 443, 8000, 8001, 8002])

    def test_parse_default_range(self) -> None:
        ports = parse_ports(args_for(start=3, end=5))

        self.assertEqual(ports, [3, 4, 5])

    def test_top_ports_uses_requested_count(self) -> None:
        self.assertEqual(len(get_top_ports(10)), 10)

    def test_proxy_web_only_defers_local_resolution(self) -> None:
        target = target_from_args(
            args_for(target="example.invalid", web_only=True, web_proxy="socks5h://127.0.0.1:9050")
        )

        self.assertEqual(target.original, "example.invalid")
        self.assertEqual(target.address, "example.invalid")
        self.assertEqual(target.family, socket.AF_UNSPEC)


if __name__ == "__main__":
    unittest.main()
