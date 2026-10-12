"""Convenience bridge entry point; use the prepared CrimsonWeb virtualenv."""

from crimsonweb.local_lab.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
