import json
import shutil
import subprocess
from datetime import datetime, timezone

from .threat_models import ThreatDetection, ThreatScanReport


_FULL_SCAN_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$requestTime = Get-Date
$before = Get-MpComputerStatus
$engineVersion = [string]$before.AMProductVersion
$signatureUpdated = $before.AntivirusSignatureLastUpdated
$startedAt = $null
$finishedAt = $null
$scanStatus = 'incomplete'
$errorMessage = $null
$signatureUpdatedText = if ($signatureUpdated) { $signatureUpdated.ToString('o') } else { $null }
$detections = @()
try {
    if (-not $before.AntivirusEnabled) {
        throw 'Microsoft Defender Antivirus no está habilitado.'
    }
    if ($before.FullScanStartTime -and $before.FullScanEndTime -and
        $before.FullScanStartTime -gt $before.FullScanEndTime) {
        throw 'Ya hay un análisis completo de Defender en curso.'
    }
    Start-MpScan -ScanType FullScan -ErrorAction Stop
    $deadline = (Get-Date).AddHours(72)
    do {
        Start-Sleep -Seconds 5
        $status = Get-MpComputerStatus
        $candidateStart = $status.FullScanStartTime
        if ($candidateStart -and $candidateStart -ge $requestTime.AddSeconds(-5)) {
            $startedAt = $candidateStart
            if ($status.FullScanEndTime -and $status.FullScanEndTime -ge $candidateStart) {
                $finishedAt = $status.FullScanEndTime
                $scanStatus = 'completed'
                break
            }
        }
    } while ((Get-Date) -lt $deadline)
    if ($startedAt) {
        $knownThreats = @(Get-MpThreat -ErrorAction SilentlyContinue)
        $detections = @(Get-MpThreatDetection -ErrorAction SilentlyContinue |
            Select-Object -First 100 |
            Select-Object @{Name='file_path';Expression={
                $resource = @($_.Resources) | Select-Object -First 1
                if ($resource) { ([string]$resource -replace '^file:_?', '') } else { '' }
            }}, @{Name='threat_name';Expression={
                $threatId = $_.ThreatID
                $known = $knownThreats | Where-Object { $_.ThreatID -eq $threatId } | Select-Object -First 1
                if ($known -and $known.ThreatName) { [string]$known.ThreatName } else { "Threat ID $($_.ThreatID)" }
            }},
            @{Name='action_status';Expression={
                if ($_.ActionSuccess -eq $true) { 'remediated_by_defender' }
                elseif ($_.ActionSuccess -eq $false) { 'remediation_not_confirmed' }
                else { 'unknown' }
            }})
    }
} catch {
    $scanStatus = 'failed'
    $errorMessage = $_.Exception.Message
}
[ordered]@{
    scan_status = $scanStatus
    engine_version = $engineVersion
    signatures_updated = $signatureUpdatedText
    started_at = if ($startedAt) { $startedAt.ToUniversalTime().ToString('o') } else { $null }
    finished_at = if ($finishedAt) { $finishedAt.ToUniversalTime().ToString('o') } else { $null }
    detections = $detections
    detection_basis = 'defender_history'
    error = $errorMessage
} | ConvertTo-Json -Depth 5 -Compress
"""


def scan_with_defender() -> ThreatScanReport:
    now = datetime.now(timezone.utc).isoformat()
    powershell = shutil.which("powershell.exe") or shutil.which("powershell")
    if not powershell:
        return ThreatScanReport.create(
            operating_system="Windows",
            engine="Microsoft Defender Antivirus",
            engine_version=None,
            scan_status="unavailable",
            scope="full_scan",
            started_at=now,
            finished_at=now,
            warnings=["No se encontró Windows PowerShell."],
        )

    try:
        result = subprocess.run(
            [powershell, "-NoProfile", "-NonInteractive", "-Command", _FULL_SCAN_SCRIPT],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=72 * 60 * 60 + 120,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(result.stderr.strip() or "PowerShell no pudo iniciar el análisis completo.")
        payload = json.loads(result.stdout)
    except subprocess.TimeoutExpired as error:
        return ThreatScanReport.create(
            operating_system="Windows",
            engine="Microsoft Defender Antivirus",
            engine_version=None,
            scan_status="incomplete",
            scope="full_scan",
            started_at=now,
            finished_at=None,
            warnings=[
                "La espera del análisis excedió 72 horas. Verifica su estado en Seguridad de Windows."
            ],
            error=str(error),
        )
    except (OSError, RuntimeError, json.JSONDecodeError) as error:
        return ThreatScanReport.create(
            operating_system="Windows",
            engine="Microsoft Defender Antivirus",
            engine_version=None,
            scan_status="failed",
            scope="full_scan",
            started_at=now,
            finished_at=datetime.now(timezone.utc).isoformat(),
            error=str(error),
        )

    detections = [
        ThreatDetection(
            file_path=item.get("file_path") or "(ruta no disponible)",
            threat_name=item.get("threat_name") or None,
            action_status=item.get("action_status") or "unknown",
        )
        for item in payload.get("detections", [])
    ]
    warnings = []
    if payload.get("detection_basis") == "defender_history":
        warnings.append(
            "Defender entrega historial de detecciones, que puede preceder a este análisis y no confirma amenazas activas."
        )
        if len(detections) == 100:
            warnings.append("Se muestran hasta los primeros 100 registros disponibles del historial de Defender.")
    if payload.get("scan_status") == "incomplete":
        warnings.append(
            "No se pudo confirmar la finalización dentro de 72 horas. El estado debe verificarse en Seguridad de Windows."
        )

    return ThreatScanReport.create(
        operating_system="Windows",
        engine="Microsoft Defender Antivirus",
        engine_version=payload.get("engine_version"),
        signatures_updated=payload.get("signatures_updated"),
        detection_basis=payload.get("detection_basis", "defender_history"),
        scan_status=payload.get("scan_status", "failed"),
        scope="full_scan",
        started_at=payload.get("started_at") or now,
        finished_at=payload.get("finished_at"),
        detections=detections,
        warnings=warnings,
        error=payload.get("error"),
    )
