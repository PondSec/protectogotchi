#!/usr/bin/env python3
"""One-command launcher for the local Protectogotchi web app.

Run from a fresh clone with:

    python3 start.py

No virtual environment or package installation is required for the default web
UI because this project currently only uses the Python standard library at
runtime.
"""

from __future__ import annotations

import sys
from pathlib import Path

DEFAULT_ARGS = ["web", "--host", "127.0.0.1", "--port", "8765", "--scan-interval", "3"]


def repo_root() -> Path:
    return Path(__file__).resolve().parent


def ensure_source_tree_importable() -> None:
    src = repo_root() / "src"
    src_text = str(src)
    if src_text not in sys.path:
        sys.path.insert(0, src_text)


def build_argv(argv: list[str] | None = None) -> list[str]:
    provided = list(sys.argv[1:] if argv is None else argv)
    if provided:
        return provided
    return DEFAULT_ARGS.copy()


def main(argv: list[str] | None = None) -> int:
    ensure_source_tree_importable()
    from protectogotchi.cli import main as cli_main

    effective_args = build_argv(argv)
    if effective_args == DEFAULT_ARGS:
        print("🐾 Protectogotchi startet ohne venv und ohne Installation ...")
        print("🌸 Öffne gleich im Browser: http://127.0.0.1:8765")
        print("   Tipp: Mit Ctrl+C beendest du Protectogotchi wieder.\n")
    return cli_main(effective_args)


if __name__ == "__main__":
    raise SystemExit(main())
