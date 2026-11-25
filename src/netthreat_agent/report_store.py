import json
import os
import platform
from datetime import datetime
from pathlib import Path

from .models import ScanReport


def default_report_directory() -> Path:
    if platform.system() == "Windows":
        base_directory = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
        application_directory = "NetThreatVision"
    else:
        configured_data_home = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
        base_directory = configured_data_home if configured_data_home.is_absolute() else Path.home() / ".local" / "share"
        application_directory = "netthreat-vision"
    return base_directory / application_directory / "reports"


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