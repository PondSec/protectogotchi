from __future__ import annotations

import argparse

from protectogotchi import __version__
from protectogotchi.face import FACES, render_face


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="protectogotchi",
        description="Local-first defensive AI companion for Wi-Fi and home networks.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command")
    face_parser = subparsers.add_parser("face", help="Render a Protectogotchi face.")
    face_parser.add_argument("state", choices=sorted(FACES), help="Face state to render.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "face":
        print(render_face(args.state))
        return 0

    parser.print_help()
    return 0
