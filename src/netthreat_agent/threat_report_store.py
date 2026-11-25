import json
from datetime import datetime
from pathlib import Path

from .report_store import default_report_directory
from .threat_models import ThreatScanReport


def save_threat_report(
    report: ThreatScanReport,
    directory: Path | None = None,
    generated_at: datetime | None = None,
) -> Path:
    target_directory = directory or default_report_directory()
    target_directory.mkdir(parents=True, exist_ok=True)

    timestamp = (generated_at or datetime.now()).strftime("%m_%d_%Y_%H_%M")
    candidate = target_directory / f"amenazas_{timestamp}.json"
    sequence = 2
    payload = json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"

    while True:
        try:
            with candidate.open("x", encoding="utf-8") as report_file:
                report_file.write(payload)
            return candidate
        except FileExistsError:
            candidate = target_directory / f"amenazas_{timestamp}_{sequence:02}.json"
            sequence += 1


def update_threat_report(report: ThreatScanReport, report_path: Path) -> None:
    payload = json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"
    report_path.write_text(payload, encoding="utf-8")
