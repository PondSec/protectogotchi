from protectogotchi.cli import main


def test_face_command_prints_state(capsys):
    assert main(["face", "happy"]) == 0
    output = capsys.readouterr().out
    assert "happy" in output
    assert "all clear" in output
