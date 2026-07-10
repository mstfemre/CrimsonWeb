"""CLI entry point for CrimsonWeb."""

from .core_engine import main


__all__ = ["main"]


if __name__ == "__main__":
    raise SystemExit(main())
