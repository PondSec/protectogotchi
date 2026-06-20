from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Face:
    name: str
    mood: str
    art: str


FACES: dict[str, Face] = {
    "idle": Face("idle", "watching quietly", "( -_-)"),
    "learning": Face("learning", "learning the network", "( o_o)"),
    "analyzing": Face("analyzing", "checking signals", "( @_@)"),
    "alert": Face("alert", "suspicious activity", "( O_O)!"),
    "fighting": Face("fighting", "defending", "( >_<)"),
    "happy": Face("happy", "all clear", "( ^_^)"),
}


def get_face(state: str) -> Face:
    return FACES.get(state, FACES["idle"])


def render_face(state: str) -> str:
    face = get_face(state)
    return f"{face.art}  {face.name}: {face.mood}"
