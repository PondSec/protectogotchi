#!/usr/bin/env python3
"""One-command launcher for the local Protectogotchi web console.

Run from a fresh clone with:

    python3 start.py

The launcher adds the local ``src`` tree to ``sys.path`` so the web console can
start from source without installing the package first. When called directly
from an activated virtual environment, it re-execs the underlying system Python
so the project does not depend on venv activation.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


DEFAULT_ARGS = ["web", "--host", "127.0.0.1", "--port", "8765", "--scan-interval", "3"]


def repo_root() -> Path:
    return Path(__file__).resolve().parent


def running_in_virtualenv() -> bool:
    return sys.prefix != getattr(sys, "base_prefix", sys.prefix)


def base_python_executable() -> str | None:
    candidate = getattr(sys, "_base_executable", None)
    if candidate and Path(candidate).exists():
        return str(candidate)

    base_prefix = getattr(sys, "base_prefix", None)
    if not base_prefix:
        return None

    bin_dir = Path(base_prefix) / "bin"
    candidates = [
        f"python{sys.version_info.major}.{sys.version_info.minor}",
        f"python{sys.version_info.major}",
        "python3",
        "python",
    ]
    for name in candidates:
        executable = bin_dir / name
        if executable.exists():
            return str(executable)
    return None


def reexec_without_virtualenv() -> None:
    if os.environ.get("PROTECTOGOTCHI_ALLOW_VENV") == "1":
        return
    if os.environ.get("PROTECTOGOTCHI_REEXECED") == "1":
        return
    if not running_in_virtualenv():
        return

    executable = base_python_executable()
    if not executable:
        return

    current = Path(sys.executable).resolve()
    target = Path(executable).resolve()
    if current == target:
        return

    env = os.environ.copy()
    env["PROTECTOGOTCHI_REEXECED"] = "1"
    env.pop("VIRTUAL_ENV", None)
    os.execve(
        str(target),
        [str(target), str(Path(__file__).resolve()), *sys.argv[1:]],
        env,
    )


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
    reexec_without_virtualenv()
    raise SystemExit(main())
