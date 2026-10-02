"""`python -m demo_server` entrypoint — thin shim over :mod:`demo_server.cli`."""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
