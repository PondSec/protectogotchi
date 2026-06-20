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


def test_running_in_virtualenv_detects_prefix_split(monkeypatch):
    monkeypatch.setattr(start.sys, "prefix", "/tmp/protectogotchi-venv")
    monkeypatch.setattr(start.sys, "base_prefix", "/opt/homebrew/python")

    assert start.running_in_virtualenv() is True


def test_reexec_without_virtualenv_uses_base_python(monkeypatch, tmp_path):
    target = tmp_path / "python3.12"
    target.write_text("")
    current = tmp_path / "venv-python"
    current.write_text("")
    captured = {}

    def fake_execve(path, argv, env):
        captured["path"] = path
        captured["argv"] = argv
        captured["env"] = env

    monkeypatch.delenv("PROTECTOGOTCHI_ALLOW_VENV", raising=False)
    monkeypatch.delenv("PROTECTOGOTCHI_REEXECED", raising=False)
    monkeypatch.setenv("VIRTUAL_ENV", str(tmp_path / ".venv"))
    monkeypatch.setattr(start, "running_in_virtualenv", lambda: True)
    monkeypatch.setattr(start, "base_python_executable", lambda: str(target))
    monkeypatch.setattr(start.sys, "executable", str(current))
    monkeypatch.setattr(start.sys, "argv", ["start.py", "ai"])
    monkeypatch.setattr(start.os, "execve", fake_execve)

    start.reexec_without_virtualenv()

    assert captured["path"] == str(target)
    assert captured["argv"][0] == str(target)
    assert captured["argv"][-1] == "ai"
    assert captured["env"]["PROTECTOGOTCHI_REEXECED"] == "1"
    assert "VIRTUAL_ENV" not in captured["env"]


def test_reexec_without_virtualenv_allows_opt_in_venv(monkeypatch):
    called = False

    def fake_execve(*_args):
        nonlocal called
        called = True

    monkeypatch.setenv("PROTECTOGOTCHI_ALLOW_VENV", "1")
    monkeypatch.setattr(start, "running_in_virtualenv", lambda: True)
    monkeypatch.setattr(start, "base_python_executable", lambda: "/usr/bin/python3")
    monkeypatch.setattr(start.os, "execve", fake_execve)

    start.reexec_without_virtualenv()

    assert called is False
