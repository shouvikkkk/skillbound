"""Entry point: `python -m skillbound check <skill-dir>`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
