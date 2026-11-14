import json
import shutil
import subprocess
import sys

from .models import DefenderDetection, DefenderObservation


_POWERSHELL_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$quickScanStatus = 'not_requested'
$quickScanError = $null
try {
    $status = Get-MpComputerStatus
    $detections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue |
        Select-Object -First 50 `
            @{Name='threat_id';Expression={ [string]$_.ThreatID }}, `
            @{Name='detection_time';Expression={ if ($_.InitialDetectionTime) { $_.InitialDetectionTime.ToString('o') } else { $null } }}, `
            @{Name='action_success';Expression={ if ($null -eq $_.ActionSuccess) { $null } else { [bool]$_.ActionSuccess } }})
    if ($StartQuickScan) {
        try {
            Start-MpScan -ScanType QuickScan -ErrorAction Stop
            $quickScanStatus = 'initiated'
        } catch {
            $quickScanStatus = 'failed'
            $quickScanError = $_.Exception.Message
        }
    }
    [ordered]@{
        available = $true
        antivirus_enabled = [bool]$status.AntivirusEnabled
        real_time_protection_enabled = [bool]$status.RealTimeProtectionEnabled
        signature_last_updated = if ($status.AntivirusSignatureLastUpdated) { $status.AntivirusSignatureLastUpdated.ToString('o') } else { $null }
        detections = $detections
        quick_scan_status = $quickScanStatus
        error = $quickScanError
    } | ConvertTo-Json -Depth 4 -Compress
} catch {
    [ordered]@{
        available = $false
        antivirus_enabled = $null
        real_time_protection_enabled = $null
        signature_last_updated = $null
        detections = @()
        quick_scan_status = $quickScanStatus
        error = $_.Exception.Message
    } | ConvertTo-Json -Depth 4 -Compress
}
"""


def collect_windows_security(*, start_quick_scan: bool = False) -> DefenderObservation:
    if sys.platform != "win32":
        return DefenderObservation(
            available=False,
            antivirus_enabled=None,
            real_time_protection_enabled=None,
            signature_last_updated=None,
            detections=[],
            quick_scan_status="unsupported",
            error="La consulta de Microsoft Defender está disponible solo en Windows.",
        )

    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        return DefenderObservation(
            available=False,
            antivirus_enabled=None,
            real_time_protection_enabled=None,
            signature_last_updated=None,
            detections=[],
            quick_scan_status="unavailable",
            error="No se encontró Windows PowerShell.",
        )

    script = _POWERSHELL_SCRIPT.replace("$StartQuickScan", "$true" if start_quick_scan else "$false")
    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "PowerShell no pudo consultar Microsoft Defender.")
        payload = json.loads(result.stdout)
        detections = [
            DefenderDetection(
                threat_id=item.get("threat_id") or None,
                detection_time=item.get("detection_time") or None,
                action_success=item.get("action_success"),
            )
            for item in payload.get("detections", [])
        ]
        return DefenderObservation(
            available=bool(payload.get("available")),
            antivirus_enabled=payload.get("antivirus_enabled"),
            real_time_protection_enabled=payload.get("real_time_protection_enabled"),
            signature_last_updated=payload.get("signature_last_updated"),
            detections=detections,
            quick_scan_status=payload.get("quick_scan_status", "unknown"),
            error=payload.get("error"),
        )
    except (OSError, RuntimeError, subprocess.TimeoutExpired, json.JSONDecodeError) as error:
        return DefenderObservation(
            available=False,
            antivirus_enabled=None,
            real_time_protection_enabled=None,
            signature_last_updated=None,
            detections=[],
            quick_scan_status="unknown",
            error=str(error),
        )