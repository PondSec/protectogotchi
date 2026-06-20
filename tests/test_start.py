import importlib.util
from pathlib import Path


def load_start_module():
    path = Path(__file__).resolve().parents[1] / "start.py"
    spec = importlib.util.spec_from_file_location("protectogotchi_start", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_start_defaults_to_local_web_app():
    start = load_start_module()

    assert start.build_argv([]) == [
        "web",
        "--host",
        "127.0.0.1",
        "--port",
        "8765",
        "--scan-interval",
        "3",
    ]


def test_start_preserves_explicit_cli_args():
    start = load_start_module()

    assert start.build_argv(["scan", "--json"]) == ["scan", "--json"]
