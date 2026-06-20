from protectogotchi.cli import main


def test_face_command_prints_state(capsys):
    assert main(["face", "happy"]) == 0
    output = capsys.readouterr().out
    assert "happy" in output
    assert "all clear" in output


def test_tools_command_lists_available_arsenal(capsys):
    assert main(["tools", "--available-only"]) == 0
    output = capsys.readouterr().out
    assert "scan" in output
    assert "doctor" in output
    assert "planned" not in output


def test_baseline_show_uses_state_dir(tmp_path, capsys):
    assert main(["--state-dir", str(tmp_path), "baseline", "show"]) == 0
    output = capsys.readouterr().out
    assert "observations=0" in output
    assert "known_devices=0" in output
