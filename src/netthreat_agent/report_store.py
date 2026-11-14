import json
from datetime import datetime
from pathlib import Path

from .models import ScanReport


def default_report_directory() -> Path:
    return Path.home() / "NetThreatVision" / "reports"


def save_report(
    report: ScanReport,
    directory: Path | None = None,
    generated_at: datetime | None = None,
) -> Path:
    target_directory = directory or default_report_directory()
    target_directory.mkdir(parents=True, exist_ok=True)

    timestamp = (generated_at or datetime.now()).strftime("%m_%d_%Y_%H_%M")
    filename = f"reporte_{timestamp}.json"
    payload = json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"
    candidate = target_directory / filename
    sequence = 2

    while True:
        try:
            with candidate.open("x", encoding="utf-8") as report_file:
                report_file.write(payload)
            return candidate
        except FileExistsError:
            candidate = target_directory / f"reporte_{timestamp}_{sequence:02}.json"
            sequence += 1