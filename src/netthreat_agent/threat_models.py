from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


@dataclass(frozen=True)
class ThreatDetection:
    file_path: str
    threat_name: str | None
    action_status: str = "not_requested"
    action_detail: str | None = None


@dataclass(frozen=True)
class ThreatScanReport:
    schema_version: str
    scan_id: str
    generated_at: str
    operating_system: str
    engine: str
    engine_version: str | None
    signatures_updated: str | None
    detection_basis: str
    scan_status: str
    scope: str
    started_at: str | None
    finished_at: str | None
    detections: list[ThreatDetection]
    warnings: list[str]
    error: str | None = None

    @classmethod
    def create(
        cls,
        *,
        operating_system: str,
        engine: str,
        engine_version: str | None,
        signatures_updated: str | None = None,
        detection_basis: str = "scan_output",
        scan_status: str,
        scope: str,
        started_at: str | None,
        finished_at: str | None,
        detections: list[ThreatDetection] | None = None,
        warnings: list[str] | None = None,
        error: str | None = None,
    ) -> "ThreatScanReport":
        return cls(
            schema_version="1.0",
            scan_id=str(uuid4()),
            generated_at=datetime.now(timezone.utc).isoformat(),
            operating_system=operating_system,
            engine=engine,
            engine_version=engine_version,
            signatures_updated=signatures_updated,
            detection_basis=detection_basis,
            scan_status=scan_status,
            scope=scope,
            started_at=started_at,
            finished_at=finished_at,
            detections=detections or [],
            warnings=warnings or [],
            error=error,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
