import platform

from .clamav_scanner import scan_with_clamav
from .threat_models import ThreatScanReport
from .windows_threat_scanner import scan_with_defender


SUPPORTED_OPERATING_SYSTEMS = ("Windows", "Linux", "macOS")


def normalize_operating_system(value: str) -> str:
    aliases = {
        "Windows": "Windows",
        "Linux": "Linux",
        "Darwin": "macOS",
        "macOS": "macOS",
    }
    try:
        return aliases[value]
    except KeyError as error:
        raise ValueError(f"Sistema operativo no compatible: {value}") from error


def detect_operating_system() -> str:
    return normalize_operating_system(platform.system())


def run_threat_scan(
    selected_operating_system: str,
    *,
    windows_engine: str = "defender",
) -> ThreatScanReport:
    selected = normalize_operating_system(selected_operating_system)
    detected = detect_operating_system()
    if selected != detected:
        raise ValueError(
            f"Seleccionaste {selected}, pero este agente se está ejecutando en {detected}. "
            "Solo se puede analizar el sistema operativo local."
        )
    if selected == "Windows":
        if windows_engine == "defender":
            return scan_with_defender()
        if windows_engine == "clamav":
            return scan_with_clamav(selected, quick_scan=True)
        raise ValueError(f"Motor de análisis de amenazas no compatible en Windows: {windows_engine}")
    if windows_engine != "defender":
        raise ValueError("La selección de motor solo está disponible para Windows.")
    return scan_with_clamav(selected)
