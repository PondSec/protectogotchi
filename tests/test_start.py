import start


def test_start_dispatches_to_web_command(monkeypatch):
    captured = {}

    def fake_cli_main(argv):
        captured["argv"] = argv
        return 0

    monkeypatch.setattr("protectogotchi.cli.main", fake_cli_main)

    assert start.main(["--host", "127.0.0.1", "--port", "9999"]) == 0
    assert captured["argv"] == ["web", "--host", "127.0.0.1", "--port", "9999"]


def test_start_accepts_optional_web_prefix(monkeypatch):
    captured = {}

    def fake_cli_main(argv):
        captured["argv"] = argv
        return 0

    monkeypatch.setattr("protectogotchi.cli.main", fake_cli_main)

    assert start.main(["web", "--scan-interval", "1"]) == 0
    assert captured["argv"] == ["web", "--scan-interval", "1"]
