from __future__ import annotations

import platform

from protectogotchi.collectors.base import Collector
from protectogotchi.collectors.linux import LinuxCollector
from protectogotchi.collectors.macos import MacOSCollector


def get_collector(name: str | None = None) -> Collector:
    selected = (name or platform.system()).lower()
    if selected in {"darwin", "macos", "mac"}:
        return MacOSCollector()
    if selected in {"linux", "pi", "raspberrypi"}:
        return LinuxCollector()
    raise ValueError(f"Unsupported collector: {name or platform.system()}")


__all__ = ["Collector", "get_collector"]
