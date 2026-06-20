from __future__ import annotations

from dataclasses import dataclass

from protectogotchi.config import ProtectogotchiConfig
from protectogotchi.models import Finding, NetworkSnapshot, SEVERITY_SCORE
from protectogotchi.state import ProtectogotchiState


RISKY_REMOTE_PORTS = {
    21: "ftp",
    23: "telnet",
    445: "smb",
    1433: "mssql",
    2323: "telnet-alt",
    3389: "rdp",
    5900: "vnc",
}


@dataclass
class Analysis:
    findings: list[Finding]
    risk_score: int
    face_state: str


class AnomalyDetector:
    def __init__(self, config: ProtectogotchiConfig) -> None:
        self.config = config

    def analyze(
        self,
        snapshot: NetworkSnapshot,
        state: ProtectogotchiState,
    ) -> Analysis:
        findings: list[Finding] = []
        learning = state.is_learning(self.config.min_baseline_observations)

        findings.extend(self._detect_identity_changes(snapshot, state))
        findings.extend(self._detect_new_devices(snapshot, state, learning))
        findings.extend(self._detect_feature_anomalies(snapshot, state))
        findings.extend(self._detect_new_listeners(snapshot, state, learning))
        findings.extend(self._detect_risky_remote_services(snapshot))

        risk_score = self._score(findings)
        return Analysis(
            findings=findings,
            risk_score=risk_score,
            face_state=self._face_state(risk_score, findings, learning),
        )

    def _detect_identity_changes(
        self,
        snapshot: NetworkSnapshot,
        state: ProtectogotchiState,
    ) -> list[Finding]:
        findings: list[Finding] = []

        if snapshot.default_gateway and snapshot.default_gateway_mac:
            known_gateway_mac = state.gateway_macs.get(snapshot.default_gateway)
            current_gateway_mac = snapshot.default_gateway_mac.lower()
            if known_gateway_mac and known_gateway_mac != current_gateway_mac:
                findings.append(
                    Finding(
                        code="gateway_mac_changed",
                        title="Default gateway MAC changed",
                        severity="critical",
                        description=(
                            "The router/gateway IP is now associated with a different "
                            "MAC address than the learned baseline."
                        ),
                        evidence={
                            "gateway": snapshot.default_gateway,
                            "known_mac": known_gateway_mac,
                            "current_mac": current_gateway_mac,
                        },
                        recommended_action="alert_admin",
                    )
                )

        for device in snapshot.devices:
            old_mac = state.ip_mac.get(device.ip)
            current_mac = device.normalized_mac()
            if not old_mac or old_mac == current_mac:
                continue

            severity = "high"
            code = "ip_mac_changed"
            title = "Device identity changed for IP"
            action = "investigate"
            if device.ip == snapshot.default_gateway:
                severity = "critical"
                code = "gateway_ip_mac_changed"
                title = "Gateway identity changed"
                action = "alert_admin"

            findings.append(
                Finding(
                    code=code,
                    title=title,
                    severity=severity,  # type: ignore[arg-type]
                    description=(
                        "An IP address is associated with a different MAC address "
                        "than Protectogotchi previously learned."
                    ),
                    evidence={
                        "ip": device.ip,
                        "known_mac": old_mac,
                        "current_mac": current_mac,
                    },
                    recommended_action=action,
                )
            )

        return findings

    def _detect_new_devices(
        self,
        snapshot: NetworkSnapshot,
        state: ProtectogotchiState,
        learning: bool,
    ) -> list[Finding]:
        findings: list[Finding] = []
        known_macs = state.known_macs()
        for device in snapshot.devices:
            mac = device.normalized_mac()
            if mac in known_macs:
                continue
            findings.append(
                Finding(
                    code="new_device_seen",
                    title="New device on local network",
                    severity="info" if learning else "low",
                    description=(
                        "Protectogotchi observed a MAC address that is not in the "
                        "local baseline yet."
                    ),
                    evidence={
                        "ip": device.ip,
                        "mac": mac,
                        "interface": device.interface,
                        "learning": learning,
                    },
                    recommended_action="learn" if learning else "watch",
                )
            )
        return findings

    def _detect_feature_anomalies(
        self,
        snapshot: NetworkSnapshot,
        state: ProtectogotchiState,
    ) -> list[Finding]:
        findings: list[Finding] = []
        for name, value in snapshot.features().items():
            stats = state.feature_stats.get(name)
            if not stats or stats.count < self.config.min_baseline_observations:
                continue

            zscore = stats.zscore(value)
            if zscore < self.config.zscore_threshold:
                continue

            severity = "high" if zscore >= self.config.high_zscore_threshold else "medium"
            findings.append(
                Finding(
                    code=f"feature_spike_{name}",
                    title=f"Unusual {name.replace('_', ' ')}",
                    severity=severity,  # type: ignore[arg-type]
                    description=(
                        "A live network feature is significantly above the learned "
                        "baseline for this network."
                    ),
                    evidence={
                        "feature": name,
                        "value": value,
                        "mean": round(stats.mean, 2),
                        "stddev": round(stats.stddev, 2),
                        "zscore": round(zscore, 2),
                    },
                    recommended_action="investigate",
                )
            )
        return findings

    def _detect_new_listeners(
        self,
        snapshot: NetworkSnapshot,
        state: ProtectogotchiState,
        learning: bool,
    ) -> list[Finding]:
        if learning:
            return []

        known_ports = set(state.seen_listening_ports)
        findings: list[Finding] = []
        for port in sorted(snapshot.listening_ports() - known_ports):
            findings.append(
                Finding(
                    code="new_listening_port",
                    title="New local listening port",
                    severity="medium",
                    description=(
                        "A local service is listening on a port that was not part "
                        "of the learned baseline."
                    ),
                    evidence={"port": port},
                    recommended_action="investigate",
                )
            )
        return findings

    def _detect_risky_remote_services(
        self,
        snapshot: NetworkSnapshot,
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str | None, int]] = set()
        for connection in snapshot.connections:
            if connection.remote_port not in RISKY_REMOTE_PORTS:
                continue
            key = (connection.remote_address, connection.remote_port)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    code="risky_remote_service",
                    title="Connection to risky remote service",
                    severity="medium",
                    description=(
                        "A connection targets a service commonly involved in lateral "
                        "movement or remote administration. This can be legitimate, "
                        "but deserves attention."
                    ),
                    evidence={
                        "remote_address": connection.remote_address,
                        "remote_port": connection.remote_port,
                        "service": RISKY_REMOTE_PORTS[connection.remote_port],
                    },
                    recommended_action="investigate",
                )
            )
        return findings

    def _score(self, findings: list[Finding]) -> int:
        if not findings:
            return 0
        score = max(SEVERITY_SCORE[finding.severity] for finding in findings)
        score += min(20, sum(1 for finding in findings if finding.severity != "info") * 3)
        return min(100, score)

    def _face_state(
        self,
        risk_score: int,
        findings: list[Finding],
        learning: bool,
    ) -> str:
        if risk_score >= 70:
            return "fighting"
        if risk_score >= 35:
            return "alert"
        if findings:
            return "analyzing"
        if learning:
            return "learning"
        return "happy"
