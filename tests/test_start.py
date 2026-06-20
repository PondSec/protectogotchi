import start


def test_start_defaults_to_local_web_app():
    assert start.build_argv([]) == [
        "web",
        "--host",
        "127.0.0.1",
        "--port",
        "8765",
        "--scan-interval",
        "3",
    ]


def test_start_treats_leading_options_as_web_args():
    assert start.build_argv(["--host", "127.0.0.1", "--port", "9999"]) == [
        "web",
        "--host",
        "127.0.0.1",
        "--port",
        "9999",
    ]


def test_start_accepts_optional_web_prefix():
    assert start.build_argv(["web", "--scan-interval", "1"]) == [
        "web",
        "--scan-interval",
        "1",
    ]


def test_start_preserves_explicit_cli_commands():
    assert start.build_argv(["scan", "--json"]) == ["scan", "--json"]


def test_start_main_dispatches_to_cli(monkeypatch):
    captured = {}

    def fake_cli_main(argv):
        captured["argv"] = argv
        return 0

    monkeypatch.setattr("protectogotchi.cli.main", fake_cli_main)

    assert start.main(["--port", "9999"]) == 0
    assert captured["argv"] == ["web", "--port", "9999"]
