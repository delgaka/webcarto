"""Pacote principal do WebCarto."""

from __future__ import annotations

import sys


def main() -> None:
    """Ponto de entrada do executável `webcarto`."""
    if len(sys.argv) > 1:
        subcommand = sys.argv[1]
        if subcommand in {"report", "report-builder"}:
            from .report_builder import run

            exit_code = run(sys.argv[2:])
            if exit_code:
                raise SystemExit(exit_code)
            return
        if subcommand in {"analyze-js", "analyze_js"}:
            from .js_analyzer import run as analyze

            exit_code = analyze(sys.argv[2:])
            if exit_code:
                raise SystemExit(exit_code)
            return
        if subcommand in {"privacy-check", "privacy"}:
            from .privacy_check import run as privacy_run

            exit_code = privacy_run(sys.argv[2:])
            if exit_code:
                raise SystemExit(exit_code)
            return

    from .cli import main as cli_main

    cli_main()


__all__ = ["main"]
