"""CLI entry point for CrimsonWeb."""

import sys

from .core_engine import main as legacy_main


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) >= 2 and args[0] == "web" and args[1] in {
        "plan", "approve", "execute", "report", "cancel", "next", "--help", "-h",
    }:
        try:
            from .web_cli import main as web_main
        except ImportError:
            print('Web verification requires: pip install -e ".[api]"', file=sys.stderr)
            return 2
        return web_main(args[1:])
    return legacy_main(args)


__all__ = ["main"]


if __name__ == "__main__":
    raise SystemExit(main())
