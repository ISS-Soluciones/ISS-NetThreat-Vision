import os
import re
import shutil
import stat
import subprocess
import tempfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .report_store import default_report_directory
from .threat_models import ThreatDetection, ThreatScanReport


_DETECTION_LINE = re.compile(r"^(.*): (.+) FOUND$")
_PSEUDO_FILESYSTEMS = r"^/(proc|sys|dev|run)(/|$)"
_WINDOWS_PATH = re.compile(r"(?:[A-Za-z]:\\|\\\\)")
_SHARING_VIOLATION = re.compile(r"Can't open file\s+(.+):\s*32$", re.IGNORECASE)


def scan_with_clamav(operating_system: str, *, quick_scan: bool = False) -> ThreatScanReport:
    started_at = _utc_now()
    scope = "windows_user_profile_quick_scan" if quick_scan else "entire_system"
    if quick_scan:
        targets, target_warnings = _windows_quick_scan_targets()
    else:
        targets, target_warnings = [os.path.abspath(os.sep)], []
    clamscan = resolve_clamscan()
    if not clamscan:
        return ThreatScanReport.create(
            operating_system=operating_system,
            engine="ClamAV",
            engine_version=None,
            scan_status="unavailable",
            scope=scope,
            started_at=started_at,
            finished_at=_utc_now(),
            warnings=[
                "No se encontró clamscan. Comprueba NETTHREAT_CLAMAV_HOME, el PATH o la carpeta "
                "de instalación estándar de ClamAV."
            ],
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
            warnings=target_warnings,
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
    base_arguments = arguments.copy()
    arguments.extend(targets)

    warnings = list(target_warnings)
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
    missing_database_error = _missing_database_error(output)
    if missing_database_error:
        warnings.extend(
            [
                "ClamAV está instalado, pero no pudo cargar una base de firmas. "
                "Instala o actualiza las firmas con FreshClam y vuelve a intentar.",
                f"Detalle del motor: {missing_database_error}",
            ]
        )
        return ThreatScanReport.create(
            operating_system=operating_system,
            engine="ClamAV",
            engine_version=engine_version,
            scan_status="unavailable",
            scope=scope,
            started_at=started_at,
            finished_at=_utc_now(),
            warnings=warnings,
            error=(
                "ClamAV no dispone de una base de firmas accesible; no se pudo iniciar "
                "el análisis."
            ),
        )

    detections = _parse_detections(output)
    scan_warnings = _parse_warnings(output)
    unattributed_warnings = [
        warning for warning in scan_warnings if not _WINDOWS_PATH.search(warning)
    ]
    if quick_scan and unattributed_warnings:
        target_diagnostics = _diagnose_quick_scan_errors(
            clamscan, base_arguments, targets
        )
        scan_warnings.extend(target_diagnostics)
    scan_warnings = _summarize_scan_warnings(scan_warnings)
    warnings.extend(scan_warnings)
    warnings = sorted(set(warnings))
    if result.returncode == 2:
        scan_status = "incomplete"
        error = "ClamAV encontró errores; consulta las advertencias para ver su ubicación y causa."
    elif target_warnings:
        scan_status = "incomplete"
        error = "No se pudieron revisar todas las ubicaciones previstas; consulta las advertencias."
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


def _windows_quick_scan_targets() -> tuple[list[str], list[str]]:
    folder_values = (
        ("Descargas", "{374DE290-123F-4565-9164-39C4925E467B}"),
        ("Escritorio", "Desktop"),
        ("Documentos", "Personal"),
        ("Inicio", "Startup"),
    )
    candidates: list[tuple[str, Path]] = []
    warnings = []
    for label, value_name in folder_values:
        try:
            folder = _windows_user_shell_folder(value_name)
        except OSError as error:
            warnings.append(
                f"No se pudo leer la ruta configurada para {label} en Windows: {error}"
            )
            continue
        if folder is None:
            warnings.append(f"Windows no proporcionó una ruta configurada para {label}.")
            continue
        candidates.append((label, folder))

    try:
        candidates.append(("Temporales", Path(tempfile.gettempdir())))
    except OSError as error:
        warnings.append(f"No se pudo obtener la ruta de archivos temporales: {error}")

    targets = []
    for label, candidate in candidates:
        try:
            if not stat.S_ISDIR(candidate.stat().st_mode):
                warnings.append(
                    f"La ubicación de {label} no existe o no es una carpeta: {candidate}"
                )
                continue
            with os.scandir(candidate) as entries:
                next(entries, None)
            resolved = str(candidate.resolve())
        except PermissionError as error:
            warnings.append(
                f"No hay permisos para acceder a la carpeta de {label} ({candidate}): {error}"
            )
            continue
        except FileNotFoundError as error:
            warnings.append(f"La ubicación de {label} no existe ({candidate}): {error}")
            continue
        except NotADirectoryError as error:
            warnings.append(
                f"La ruta configurada para {label} contiene un componente que no es "
                f"una carpeta ({candidate}): {error}"
            )
            continue
        except OSError as error:
            warnings.append(
                f"No se pudo acceder a la carpeta de {label} ({candidate}): "
                f"{type(error).__name__}: {error}"
            )
            continue
        if resolved not in targets:
            targets.append(resolved)
    return targets, warnings


def _windows_user_shell_folder(value_name: str) -> Path | None:
    if os.name != "nt":
        return None

    import winreg

    shell_folders_key = r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, shell_folders_key) as key:
        value, _ = winreg.QueryValueEx(key, value_name)

    return Path(os.path.expandvars(value))


def _diagnose_quick_scan_errors(
    clamscan: str,
    base_arguments: list[str],
    targets: list[str],
) -> list[str]:
    diagnostics = []
    reproduced_error = False
    for target in targets:
        try:
            result = subprocess.run(
                [*base_arguments, target],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except OSError as error:
            diagnostics.append(
                f"No se pudo ejecutar el diagnóstico de {target}: "
                f"{type(error).__name__}: {error}"
            )
            continue

        output = "\n".join((result.stdout, result.stderr))
        target_warnings = _parse_warnings(output)
        if target_warnings:
            reproduced_error = True
            diagnostics.extend(
                _describe_target_warning(target, warning)
                for warning in target_warnings
            )
        elif result.returncode == 2:
            reproduced_error = True
            diagnostics.append(
                f"ClamAV devolvió el código de error 2 al revisar {target}, "
                "pero no indicó la causa."
            )

    if not reproduced_error:
        diagnostics.append(
            "El error original no se reprodujo al revisar las ubicaciones por separado; "
            "no se pudo atribuir a una carpeta."
        )
    return diagnostics


def _describe_target_warning(target: str, warning: str) -> str:
    lowered = warning.casefold()
    if any(
        phrase in lowered
        for phrase in ("permission denied", "access denied", "access is denied")
    ):
        return (
            f"Posible falta de permisos durante el análisis de {target}. "
            f"ClamAV informó: {warning}"
        )
    if "can't get file status" in lowered:
        return (
            f"ClamAV no pudo consultar el estado de una ruta dentro de {target}; "
            f"no identificó el archivo concreto. Mensaje: {warning}"
        )
    return f"ClamAV informó un error al analizar {target}: {warning}"


def resolve_clamscan() -> str | None:
    configured_home = os.environ.get("NETTHREAT_CLAMAV_HOME", "").strip()
    if configured_home:
        executable = Path(configured_home) / "clamscan.exe"
        if executable.is_file():
            return str(executable)

    for executable_name in ("clamscan.exe", "clamscan"):
        executable = shutil.which(executable_name)
        if executable:
            return executable

    if os.name == "nt":
        install_roots = []
        for variable in ("ProgramFiles", "ProgramFiles(x86)"):
            install_root = os.environ.get(variable)
            if install_root:
                install_roots.append(Path(install_root))
        for install_root in install_roots:
            executable = install_root / "ClamAV" / "clamscan.exe"
            if executable.is_file():
                return str(executable)

    return None


def quarantine_with_clamav(report: ThreatScanReport) -> ThreatScanReport:
    clamscan = resolve_clamscan()
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
            if re.search(r"\b(?:warning|error):", line, re.IGNORECASE)
        }
    )


def _summarize_scan_warnings(warnings: list[str]) -> list[str]:
    sharing_violation_paths = []
    remaining_warnings = []
    for warning in warnings:
        match = _SHARING_VIOLATION.search(warning)
        if match and _WINDOWS_PATH.search(match.group(1)):
            sharing_violation_paths.append(match.group(1).strip())
        else:
            remaining_warnings.append(warning)

    unique_paths = sorted(set(sharing_violation_paths))
    if unique_paths:
        examples = "; ".join(unique_paths[:5])
        remaining_count = len(unique_paths) - 5
        remaining_note = f"; y {remaining_count} más" if remaining_count > 0 else ""
        remaining_warnings.append(
            f"ClamAV no pudo abrir {len(unique_paths)} archivo(s) porque estaban en uso "
            f"o bloqueados por otro proceso (error Win32 32). Ejemplos: {examples}"
            f"{remaining_note}"
        )
    return sorted(set(remaining_warnings))


def _missing_database_error(output: str) -> str | None:
    markers = (
        "cl_load: no such file or directory",
        "no supported database files found",
    )
    for line in output.splitlines():
        if any(marker in line.casefold() for marker in markers):
            return line.strip()
    return None


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
