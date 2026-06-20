from __future__ import annotations

from abc import ABC, abstractmethod

from protectogotchi.models import NetworkSnapshot


class Collector(ABC):
    @abstractmethod
    def collect(self) -> NetworkSnapshot:
        raise NotImplementedError
