from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class ProcessObservation:
    pid: int
    name: str | None
    executable_path: str | None = None


@dataclass(frozen=True)
class ConnectionObservation:
    pid: int | None
    process_name: str | None
    protocol: str
    status: str
    local_address: str | None
    local_port: int | None
    remote_address: str | None
    remote_port: int | None


@dataclass(frozen=True)
class SystemObservation:
    operating_system: str
    release: str
    architecture: str


@dataclass(frozen=True)
class DefenderDetection:
    threat_id: str | None
    detection_time: str | None
    action_success: bool | None


@dataclass(frozen=True)
class DefenderObservation:
    available: bool
    antivirus_enabled: bool | None
    real_time_protection_enabled: bool | None
    signature_last_updated: str | None
    detections: list[DefenderDetection]
    quick_scan_status: str
    error: str | None = None


@dataclass(frozen=True)
class Finding:
    finding_id: str
    severity: str
    title: str
    detail: str
    evidence: list[str]
    recommended_actions: list[str]
    confidence: str


@dataclass(frozen=True)
class AIInterpretation:
    status: str
    model: str | None
    risk_level: str | None
    summary: str | None
    observations: list[str]
    immediate_actions: list[str]
    alternatives: list[str]
    prevention: list[str]
    caveats: list[str]
    error: str | None = None


@dataclass(frozen=True)
class ScanReport:
    schema_version: str
    scan_id: str
    generated_at: str
    scope: str
    system: SystemObservation
    processes: list[ProcessObservation]
    connections: list[ConnectionObservation]
    warnings: list[str]
    limitations: list[str]
    defender: DefenderObservation | None = None
    findings: list[Finding] | None = None
    ai_interpretation: AIInterpretation | None = None

    @classmethod
    def create(
        cls,
        *,
        system: SystemObservation,
        processes: list[ProcessObservation],
        connections: list[ConnectionObservation],
        warnings: list[str],
        defender: DefenderObservation | None = None,
        findings: list[Finding] | None = None,
    ) -> "ScanReport":
        return cls(
            schema_version="1.1",
            scan_id=str(uuid4()),
            generated_at=datetime.now(timezone.utc).isoformat(),
            scope="local_processes_and_network_connections_snapshot",
            system=system,
            processes=processes,
            connections=connections,
            warnings=warnings,
            limitations=[
                "Snapshot puntual; no es monitoreo continuo.",
                "Las observaciones no prueban por sí solas actividad maliciosa ni compromiso.",
                "Este reporte no evalúa CVE ni demuestra por sí solo que el equipo esté comprometido.",
                "No se inspeccionan contenidos de archivos ni persistencia, y las conexiones no se verifican con reputación externa.",
            ],
            defender=defender,
            findings=findings or [],
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)