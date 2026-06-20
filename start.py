from __future__ import annotations

import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    repo_root = Path(__file__).resolve().parent
    src_dir = repo_root / "src"
    if src_dir.exists():
        sys.path.insert(0, str(src_dir))

    from protectogotchi.cli import main as cli_main

    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "web":
        args = args[1:]
    return cli_main(["web", *args])


if __name__ == "__main__":
    raise SystemExit(main())
