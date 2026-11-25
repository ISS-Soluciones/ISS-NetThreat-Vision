import os
import re
import shutil
import subprocess
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .report_store import default_report_directory
from .threat_models import ThreatDetection, ThreatScanReport


_DETECTION_LINE = re.compile(r"^(.*): (.+) FOUND$")
_PSEUDO_FILESYSTEMS = r"^/(proc|sys|dev|run)(/|$)"


def scan_with_clamav(operating_system: str, *, quick_scan: bool = False) -> ThreatScanReport:
    started_at = _utc_now()
    scope = "windows_user_profile_quick_scan" if quick_scan else "entire_system"
    targets = _windows_quick_scan_targets() if quick_scan else [os.path.abspath(os.sep)]
    clamscan = shutil.which("clamscan")
    if not clamscan:
        return ThreatScanReport.create(
            operating_system=operating_system,
            engine="ClamAV",
            engine_version=None,
            scan_status="unavailable",
            scope=scope,
            started_at=started_at,
            finished_at=_utc_now(),
            warnings=["ClamAV no está instalado o no se encuentra en PATH."],
        )

    try:
        version_result = subprocess.run(
            [clamscan, "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return ThreatScanReport.create(
            operating_system=operating_system,
            engine="ClamAV",
            engine_version=None,
            scan_status="failed",
            scope=scope,
            started_at=started_at,
            finished_at=_utc_now(),
            error=f"No se pudo consultar ClamAV: {error}",
        )

    engine_version = version_result.stdout.strip() or None
    if version_result.returncode != 0:
        return ThreatScanReport.create(
            operating_system=operating_system,
            engine="ClamAV",
            engine_version=engine_version,
            scan_status="unavailable",
            scope=scope,
            started_at=started_at,
            finished_at=_utc_now(),
            error=version_result.stderr.strip() or "ClamAV no pudo inicializarse.",
        )

    if not targets:
        return ThreatScanReport.create(
            operating_system=operating_system,
            engine="ClamAV",
            engine_version=engine_version,
            scan_status="failed",
            scope=scope,
            started_at=started_at,
            finished_at=_utc_now(),
            error="No se encontraron ubicaciones accesibles para el análisis rápido.",
        )

    quarantine_root = default_report_directory() / "quarantine"
    arguments = [
        clamscan,
        "--recursive",
        "--infected",
        "--no-summary",
        f"--exclude-dir=^{re.escape(str(quarantine_root))}(/|$)",
    ]
    if not quick_scan:
        arguments.append("--cross-fs")
    if operating_system == "Linux" and not quick_scan:
        arguments.append(f"--exclude-dir={_PSEUDO_FILESYSTEMS}")
    arguments.extend(targets)

    warnings = []
    if quick_scan:
        warnings.append(
            "Modo rápido: solo se revisaron las carpetas frecuentes del perfil de usuario; "
            "otras ubicaciones no fueron analizadas."
        )
        warnings.append(f"Ubicaciones incluidas: {'; '.join(targets)}")

    try:
        result = subprocess.run(
            arguments,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except OSError as error:
        return ThreatScanReport.create(
            operating_system=operating_system,
            engine="ClamAV",
            engine_version=engine_version,
            scan_status="failed",
            scope=scope,
            started_at=started_at,
            finished_at=_utc_now(),
            warnings=warnings,
            error=f"No se pudo iniciar ClamAV: {error}",
        )

    output = "\n".join((result.stdout, result.stderr))
    detections = _parse_detections(output)
    scan_warnings = _parse_warnings(output)
    warnings.extend(scan_warnings)
    warnings = sorted(set(warnings))
    if result.returncode == 2:
        scan_status = "incomplete"
        error = "ClamAV encontró errores durante el análisis; revisa las advertencias."
    elif result.returncode == 1 and detections and not scan_warnings:
        scan_status = "completed_with_detections"
        error = None
    elif result.returncode == 0 and not scan_warnings:
        scan_status = "completed"
        error = None
    elif result.returncode in (0, 1):
        scan_status = "incomplete"
        error = "ClamAV reportó archivos que no pudo revisar; el resultado no confirma un análisis completo."
    else:
        scan_status = "failed"
        error = f"ClamAV terminó con código inesperado: {result.returncode}."

    return ThreatScanReport.create(
        operating_system=operating_system,
        engine="ClamAV",
        engine_version=engine_version,
        scan_status=scan_status,
        scope=scope,
        started_at=started_at,
        finished_at=_utc_now(),
        detections=detections,
        warnings=warnings,
        error=error,
    )


def _windows_quick_scan_targets() -> list[str]:
    profile = Path(os.environ.get("USERPROFILE", str(Path.home())))
    local_app_data = Path(os.environ.get("LOCALAPPDATA", str(profile / "AppData" / "Local")))
    roaming_app_data = Path(os.environ.get("APPDATA", str(profile / "AppData" / "Roaming")))
    candidates = [
        profile / "Downloads",
        profile / "Desktop",
        profile / "Documents",
        local_app_data / "Temp",
        roaming_app_data / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
    ]
    targets = []
    for candidate in candidates:
        if candidate.is_dir():
            resolved = str(candidate.resolve())
            if resolved not in targets:
                targets.append(resolved)
    return targets


def quarantine_with_clamav(report: ThreatScanReport) -> ThreatScanReport:
    clamscan = shutil.which("clamscan")
    if not clamscan:
        raise RuntimeError("ClamAV ya no está disponible; no se puso ningún archivo en cuarentena.")

    detections = list(report.detections)
    for index, detection in enumerate(detections):
        source = Path(detection.file_path)
        if not source.is_file():
            detections[index] = ThreatDetection(
                detection.file_path,
                detection.threat_name,
                "failed",
                "El archivo ya no existe o no es accesible.",
            )
            continue

        try:
            quarantine_root = default_report_directory() / "quarantine"
            scan_quarantine = quarantine_root / report.scan_id
            target_directory = scan_quarantine / str(index + 1)
            target_directory.mkdir(parents=True, exist_ok=True)
            if os.name != "nt":
                quarantine_root.chmod(0o700)
                scan_quarantine.chmod(0o700)
                target_directory.chmod(0o700)
            result = subprocess.run(
                [
                    clamscan,
                    "--infected",
                    "--no-summary",
                    f"--move={target_directory}",
                    str(source),
                ],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            detections[index] = ThreatDetection(
                detection.file_path,
                detection.threat_name,
                "failed",
                str(error),
            )
            continue

        output = "\n".join((result.stdout, result.stderr))
        moved_files = list(target_directory.iterdir())
        if result.returncode == 1 and "FOUND" in output and not source.exists() and moved_files:
            detections[index] = ThreatDetection(
                detection.file_path,
                detection.threat_name,
                "quarantined",
                str(moved_files[0]),
            )
        elif result.returncode == 0:
            detections[index] = ThreatDetection(
                detection.file_path,
                detection.threat_name,
                "not_detected_on_rescan",
                "No se volvió a detectar; no se movió el archivo.",
            )
        else:
            detections[index] = ThreatDetection(
                detection.file_path,
                detection.threat_name,
                "failed",
                result.stderr.strip() or "ClamAV no pudo mover el archivo.",
            )

    return replace(report, detections=detections)


def _parse_detections(output: str) -> list[ThreatDetection]:
    detections: list[ThreatDetection] = []
    for line in output.splitlines():
        match = _DETECTION_LINE.match(line.strip())
        if match:
            detections.append(ThreatDetection(file_path=match.group(1), threat_name=match.group(2)))
    return detections


def _parse_warnings(output: str) -> list[str]:
    return sorted(
        {
            line.strip()
            for line in output.splitlines()
            if "WARNING:" in line or "ERROR:" in line
        }
    )


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
