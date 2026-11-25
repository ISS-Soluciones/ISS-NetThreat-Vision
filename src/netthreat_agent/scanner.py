from dataclasses import replace
import platform

from .collector import collect_snapshot
from .findings import build_findings
from .groq_client import interpret_report_with_groq
from .models import ScanReport


def run_security_scan(
    *,
    include_executable_paths: bool = False,
    start_quick_scan: bool = False,
    use_groq: bool = False,
) -> ScanReport:
    report = collect_snapshot(include_executable_paths=include_executable_paths)
    warnings = list(report.warnings)
    defender = None
    findings = []

    if platform.system() == "Windows":
        from .windows_security import collect_windows_security

        defender = collect_windows_security(start_quick_scan=start_quick_scan)
        findings = build_findings(defender)
        if not defender.available:
            warnings.append("No se pudo comprobar el estado de Microsoft Defender.")
        if defender.quick_scan_status == "initiated":
            warnings.append("El análisis rápido de Defender se inició; su finalización no se confirmó.")

    report = replace(
        report,
        defender=defender,
        findings=findings,
        warnings=sorted(set(warnings)),
    )
    if use_groq:
        report = replace(report, ai_interpretation=interpret_report_with_groq(report))
    return report