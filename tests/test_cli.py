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


def test_rules_command_lists_detection_rules(capsys):
    assert main(["rules"]) == 0
    output = capsys.readouterr().out
    assert "gateway_mac_changed" in output
    assert "new_device_seen" in output


def test_map_command_accepts_json(monkeypatch, capsys):
    from protectogotchi.models import NetworkSnapshot, utc_now

    class FakeCollector:
        def collect(self):
            return NetworkSnapshot(taken_at=utc_now(), hostname="test-host", platform="test")

    monkeypatch.setattr("protectogotchi.cli.get_collector", lambda _name: FakeCollector())
    assert main(["map", "--json"]) == 0
    output = capsys.readouterr().out
    assert '"summary"' in output
    assert '"coverage"' in output


def test_knowledge_command_shows_playbook(capsys):
    assert main(["knowledge", "arp-spoofing"]) == 0
    output = capsys.readouterr().out
    assert "gateway MAC drift" in output
    assert "response_playbook" in output


def test_enforcement_command_explains_inline_mode(capsys):
    assert main(["enforcement", "inline-gateway"]) == 0
    output = capsys.readouterr().out
    assert "can_prevent=yes" in output
    assert "default gateway" in output


def test_simulate_command_runs_arp_spoof_scenario(capsys):
    assert main(["simulate", "arp-spoof"]) == 0
    output = capsys.readouterr().out
    assert "scenario=arp-spoof" in output
    assert "gateway_mac_changed" in output


def test_trust_and_untrust_device_commands(tmp_path, capsys):
    mac = "00-11-22-33-44-55"
    assert main(["--state-dir", str(tmp_path), "trust-device", "--mac", mac, "--label", "laptop"]) == 0
    output = capsys.readouterr().out
    assert "trusted 00:11:22:33:44:55" in output

    assert main(["--state-dir", str(tmp_path), "baseline", "show"]) == 0
    output = capsys.readouterr().out
    assert "trusted_devices=1" in output

    assert main(["--state-dir", str(tmp_path), "untrust-device", "--mac", mac]) == 0
    output = capsys.readouterr().out
    assert "untrusted 00:11:22:33:44:55" in output
