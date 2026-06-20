#!/usr/bin/env python3
"""One-command launcher for the local Protectogotchi web console.

Run from a fresh clone with:

    python3 start.py

The launcher adds the local ``src`` tree to ``sys.path`` so the web console can
start from source without installing the package first.
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
    if src.exists() and src_text not in sys.path:
        sys.path.insert(0, src_text)


def build_argv(argv: list[str] | None = None) -> list[str]:
    provided = list(sys.argv[1:] if argv is None else argv)
    if not provided:
        return DEFAULT_ARGS.copy()
    if provided[0] == "web":
        return ["web", *provided[1:]]
    if provided[0].startswith("-"):
        return ["web", *provided]
    return provided


def main(argv: list[str] | None = None) -> int:
    ensure_source_tree_importable()
    from protectogotchi.cli import main as cli_main

    return cli_main(build_argv(argv))


if __name__ == "__main__":
    raise SystemExit(main())
