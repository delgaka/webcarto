"""Pacote principal do WebCarto."""

from __future__ import annotations

import sys


def main() -> None:
    """Ponto de entrada do executável `webcarto`."""
    if len(sys.argv) > 1 and sys.argv[1] in {"report", "report-builder"}:
        from .report_builder import run

        exit_code = run(sys.argv[2:])
        if exit_code:
            raise SystemExit(exit_code)
        return

    from .cli import main as cli_main

    cli_main()


__all__ = ["main"]
