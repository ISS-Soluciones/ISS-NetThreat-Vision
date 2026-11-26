import json
import subprocess
from datetime import datetime
from pathlib import Path

from netthreat_agent import clamav_scanner, threat_scanner, windows_threat_scanner
from netthreat_agent.threat_dashboard import write_threat_dashboard
from netthreat_agent.threat_models import ThreatDetection, ThreatScanReport
from netthreat_agent.threat_report_store import save_threat_report, update_threat_report


def _report(**overrides):
    values = {
        "operating_system": "Linux",
        "engine": "ClamAV",
        "engine_version": "ClamAV test",
        "detection_basis": "scan_output",
        "scan_status": "completed",
        "scope": "entire_system",
        "started_at": "2026-11-25T10:00:00+00:00",
        "finished_at": "2026-11-25T10:01:00+00:00",
    }
    values.update(overrides)
    return ThreatScanReport.create(**values)


def test_threat_scanner_routes_from_selected_local_platform(monkeypatch):
    monkeypatch.setattr(threat_scanner.platform, "system", lambda: "Linux")
    expected = _report()
    monkeypatch.setattr(threat_scanner, "scan_with_clamav", lambda operating_system: expected)

    assert threat_scanner.run_threat_scan("Linux") is expected


def test_threat_scanner_routes_windows_to_defender(monkeypatch):
    monkeypatch.setattr(threat_scanner.platform, "system", lambda: "Windows")
    expected = _report(operating_system="Windows", engine="Microsoft Defender Antivirus")
    monkeypatch.setattr(threat_scanner, "scan_with_defender", lambda: expected)

    assert threat_scanner.run_threat_scan("Windows") is expected
    assert threat_scanner.normalize_operating_system("Darwin") == "macOS"


def test_threat_scanner_can_route_windows_to_quick_clamav(monkeypatch):
    monkeypatch.setattr(threat_scanner.platform, "system", lambda: "Windows")
    expected = _report(operating_system="Windows", scope="windows_user_profile_quick_scan")
    calls = []

    def fake_scan(operating_system, *, quick_scan):
        calls.append((operating_system, quick_scan))
        return expected

    monkeypatch.setattr(threat_scanner, "scan_with_clamav", fake_scan)

    assert threat_scanner.run_threat_scan("Windows", windows_engine="clamav") is expected
    assert calls == [("Windows", True)]


def test_threat_scanner_rejects_platform_that_does_not_match_host(monkeypatch):
    monkeypatch.setattr(threat_scanner.platform, "system", lambda: "Windows")

    try:
        threat_scanner.run_threat_scan("Linux")
    except ValueError as error:
        assert "Solo se puede analizar el sistema operativo local" in str(error)
    else:
        raise AssertionError("A mismatched platform must not start a scanner")


def test_clamav_scan_parses_detections_without_removing_files(tmp_path, monkeypatch):
    monkeypatch.setattr(clamav_scanner.shutil, "which", lambda _name: "clamscan")
    monkeypatch.setattr(clamav_scanner, "default_report_directory", lambda: tmp_path / "reports")
    monkeypatch.setattr(clamav_scanner.os.path, "abspath", lambda _path: "/")
    calls = []

    def fake_run(arguments, **_kwargs):
        calls.append(arguments)
        if arguments[-1] == "--version":
            return subprocess.CompletedProcess(arguments, 0, "ClamAV 1.4.3/12345", "")
        return subprocess.CompletedProcess(arguments, 1, "/home/user/sample: Test.Signature FOUND\n", "")

    monkeypatch.setattr(clamav_scanner.subprocess, "run", fake_run)

    report = clamav_scanner.scan_with_clamav("Linux")

    assert report.scan_status == "completed_with_detections"
    assert report.detections == [ThreatDetection("/home/user/sample", "Test.Signature")]
    assert "--recursive" in calls[1]
    assert "--cross-fs" in calls[1]
    assert "--remove" not in calls[1]
    assert calls[1][-1] == "/"


def test_clamav_scan_marks_permission_warnings_as_incomplete(tmp_path, monkeypatch):
    monkeypatch.setattr(clamav_scanner.shutil, "which", lambda _name: "clamscan")
    monkeypatch.setattr(clamav_scanner, "default_report_directory", lambda: tmp_path / "reports")
    monkeypatch.setattr(clamav_scanner.os.path, "abspath", lambda _path: "/")

    def fake_run(arguments, **_kwargs):
        if arguments[-1] == "--version":
            return subprocess.CompletedProcess(arguments, 0, "ClamAV test", "")
        return subprocess.CompletedProcess(arguments, 0, "", "WARNING: Permission denied")

    monkeypatch.setattr(clamav_scanner.subprocess, "run", fake_run)

    report = clamav_scanner.scan_with_clamav("Linux")

    assert report.scan_status == "incomplete"
    assert report.warnings == ["WARNING: Permission denied"]
    assert report.error


def test_missing_clamav_is_reported_as_unavailable(monkeypatch):
    monkeypatch.setattr(clamav_scanner, "resolve_clamscan", lambda: None)

    report = clamav_scanner.scan_with_clamav("Linux")

    assert report.scan_status == "unavailable"
    assert report.warnings


def test_clamav_resolver_uses_configured_install_directory(tmp_path, monkeypatch):
    executable = tmp_path / "clamscan.exe"
    executable.write_text("", encoding="utf-8")
    monkeypatch.setenv("NETTHREAT_CLAMAV_HOME", str(tmp_path))
    monkeypatch.setattr(clamav_scanner.shutil, "which", lambda _name: None)

    assert clamav_scanner.resolve_clamscan() == str(executable)


def test_clamav_resolver_finds_default_windows_msi_directory(tmp_path, monkeypatch):
    if clamav_scanner.os.name != "nt":
        return
    install_directory = tmp_path / "ClamAV"
    install_directory.mkdir()
    executable = install_directory / "clamscan.exe"
    executable.write_text("", encoding="utf-8")
    monkeypatch.delenv("NETTHREAT_CLAMAV_HOME", raising=False)
    monkeypatch.setenv("ProgramFiles", str(tmp_path))
    monkeypatch.delenv("ProgramFiles(x86)", raising=False)
    monkeypatch.setattr(clamav_scanner.shutil, "which", lambda _name: None)

    assert clamav_scanner.resolve_clamscan() == str(executable)


def test_windows_quick_clamav_scans_only_existing_common_profile_folders(tmp_path, monkeypatch):
    desktop = tmp_path / "OneDrive" / "Escritorio"
    documents = tmp_path / "OneDrive" / "Documentos"
    downloads = tmp_path / "Downloads"
    startup = tmp_path / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    temp = tmp_path / "AppData" / "Local" / "Temp"
    expected_directories = [
        downloads,
        desktop,
        documents,
        startup,
        temp,
    ]
    for directory in expected_directories:
        directory.mkdir(parents=True)

    shell_folders = {
        "{374DE290-123F-4565-9164-39C4925E467B}": downloads,
        "Desktop": desktop,
        "Personal": documents,
        "Startup": startup,
    }
    monkeypatch.setattr(
        clamav_scanner,
        "_windows_user_shell_folder",
        lambda value_name: shell_folders.get(value_name),
    )
    monkeypatch.setattr(clamav_scanner.tempfile, "gettempdir", lambda: str(temp))
    monkeypatch.setattr(clamav_scanner.shutil, "which", lambda _name: "clamscan")
    monkeypatch.setattr(clamav_scanner, "default_report_directory", lambda: tmp_path / "reports")
    calls = []

    def fake_run(arguments, **_kwargs):
        calls.append(arguments)
        if arguments[-1] == "--version":
            return subprocess.CompletedProcess(arguments, 0, "ClamAV test", "")
        return subprocess.CompletedProcess(arguments, 0, "", "")

    monkeypatch.setattr(clamav_scanner.subprocess, "run", fake_run)

    report = clamav_scanner.scan_with_clamav("Windows", quick_scan=True)

    assert report.scan_status == "completed"
    assert report.scope == "windows_user_profile_quick_scan"
    assert all(str(directory) in calls[1] for directory in expected_directories)
    assert "--cross-fs" not in calls[1]
    assert any("Ubicaciones incluidas:" in warning for warning in report.warnings)


def test_windows_quick_clamav_attributes_generic_errors_to_scan_targets(tmp_path, monkeypatch):
    targets = [
        tmp_path / "Downloads",
        tmp_path / "Escritorio",
        tmp_path / "Documentos",
        tmp_path / "Startup",
        tmp_path / "Temp",
    ]
    for target in targets:
        target.mkdir()
    shell_folders = {
        "{374DE290-123F-4565-9164-39C4925E467B}": targets[0],
        "Desktop": targets[1],
        "Personal": targets[2],
        "Startup": targets[3],
    }
    monkeypatch.setattr(
        clamav_scanner,
        "_windows_user_shell_folder",
        lambda value_name: shell_folders.get(value_name),
    )
    monkeypatch.setattr(clamav_scanner.tempfile, "gettempdir", lambda: str(targets[4]))
    monkeypatch.setattr(clamav_scanner, "resolve_clamscan", lambda: "clamscan")
    monkeypatch.setattr(clamav_scanner, "default_report_directory", lambda: tmp_path / "reports")
    calls = []

    def fake_run(arguments, **_kwargs):
        calls.append(arguments)
        if arguments[-1] == "--version":
            return subprocess.CompletedProcess(arguments, 0, "ClamAV test", "")
        if len(arguments) > 6:
            return subprocess.CompletedProcess(
                arguments, 2, "", "ERROR: Can't get file status"
            )
        if arguments[-1] == str(targets[0]):
            return subprocess.CompletedProcess(
                arguments, 2, "", "ERROR: Can't get file status"
            )
        if arguments[-1] == str(targets[1]):
            return subprocess.CompletedProcess(arguments, 2, "", "ERROR: Access denied")
        return subprocess.CompletedProcess(arguments, 0, "", "")

    monkeypatch.setattr(clamav_scanner.subprocess, "run", fake_run)

    report = clamav_scanner.scan_with_clamav("Windows", quick_scan=True)

    assert report.scan_status == "incomplete"
    assert any(
        str(targets[0]) in warning and "no pudo consultar el estado" in warning
        for warning in report.warnings
    )
    assert any(
        str(targets[1]) in warning and "Posible falta de permisos" in warning
        for warning in report.warnings
    )
    assert len(calls) == 1 + 1 + len(targets)


def test_windows_quick_clamav_summarizes_locked_files_without_rescanning(
    tmp_path, monkeypatch
):
    target = tmp_path / "Temp"
    target.mkdir()
    monkeypatch.setattr(
        clamav_scanner,
        "_windows_quick_scan_targets",
        lambda: ([str(target)], []),
    )
    monkeypatch.setattr(clamav_scanner, "resolve_clamscan", lambda: "clamscan")
    monkeypatch.setattr(clamav_scanner, "default_report_directory", lambda: tmp_path / "reports")
    calls = []

    def fake_run(arguments, **_kwargs):
        calls.append(arguments)
        if arguments[-1] == "--version":
            return subprocess.CompletedProcess(arguments, 0, "ClamAV test", "")
        file_paths = [target / f"locked-{index}.tmp" for index in range(7)]
        warnings = "\n".join(
            f"LibClamAV Warning: Can't open file {file_path}: 32"
            for file_path in file_paths
        )
        return subprocess.CompletedProcess(arguments, 2, "", warnings)

    monkeypatch.setattr(clamav_scanner.subprocess, "run", fake_run)

    report = clamav_scanner.scan_with_clamav("Windows", quick_scan=True)

    assert report.scan_status == "incomplete"
    assert len(calls) == 2
    assert any(
        "7 archivo(s)" in warning
        and "en uso" in warning
        and "error Win32 32" in warning
        for warning in report.warnings
    )


def test_clamav_missing_signature_database_is_reported_without_folder_retries(
    tmp_path, monkeypatch
):
    targets = [
        tmp_path / "Downloads",
        tmp_path / "Desktop",
        tmp_path / "Documents",
        tmp_path / "Startup",
        tmp_path / "Temp",
    ]
    for target in targets:
        target.mkdir()
    shell_folders = {
        "{374DE290-123F-4565-9164-39C4925E467B}": targets[0],
        "Desktop": targets[1],
        "Personal": targets[2],
        "Startup": targets[3],
    }
    monkeypatch.setattr(
        clamav_scanner,
        "_windows_user_shell_folder",
        lambda value_name: shell_folders.get(value_name),
    )
    monkeypatch.setattr(clamav_scanner.tempfile, "gettempdir", lambda: str(targets[4]))
    monkeypatch.setattr(clamav_scanner, "resolve_clamscan", lambda: "clamscan")
    monkeypatch.setattr(clamav_scanner, "default_report_directory", lambda: tmp_path / "reports")
    calls = []

    def fake_run(arguments, **_kwargs):
        calls.append(arguments)
        if arguments[-1] == "--version":
            return subprocess.CompletedProcess(arguments, 0, "ClamAV 1.5.5", "")
        return subprocess.CompletedProcess(
            arguments,
            2,
            "",
            "LibClamAV Error: cl_load: No such file or directory: "
            "C:\\Program Files\\ClamAV\\database\nERROR: Can't get file status",
        )

    monkeypatch.setattr(clamav_scanner.subprocess, "run", fake_run)

    report = clamav_scanner.scan_with_clamav("Windows", quick_scan=True)

    assert report.scan_status == "unavailable"
    assert "base de firmas accesible" in report.error
    assert any("C:\\Program Files\\ClamAV\\database" in warning for warning in report.warnings)
    assert not any("no pudo consultar el estado" in warning for warning in report.warnings)
    assert len(calls) == 2


def test_windows_quick_clamav_marks_missing_scan_locations_incomplete(tmp_path, monkeypatch):
    target_names = ("Downloads", "Desktop", "Documents", "Startup", "Temp")
    targets = [tmp_path / name for name in target_names]
    for target in targets:
        target.mkdir()
    targets[2].rmdir()
    shell_folders = {
        "{374DE290-123F-4565-9164-39C4925E467B}": targets[0],
        "Desktop": targets[1],
        "Personal": targets[2],
        "Startup": targets[3],
    }
    monkeypatch.setattr(
        clamav_scanner,
        "_windows_user_shell_folder",
        lambda value_name: shell_folders.get(value_name),
    )
    monkeypatch.setattr(clamav_scanner.tempfile, "gettempdir", lambda: str(targets[4]))
    monkeypatch.setattr(clamav_scanner, "resolve_clamscan", lambda: "clamscan")
    monkeypatch.setattr(clamav_scanner, "default_report_directory", lambda: tmp_path / "reports")

    def fake_run(arguments, **_kwargs):
        if arguments[-1] == "--version":
            return subprocess.CompletedProcess(arguments, 0, "ClamAV test", "")
        return subprocess.CompletedProcess(arguments, 0, "", "")

    monkeypatch.setattr(clamav_scanner.subprocess, "run", fake_run)

    report = clamav_scanner.scan_with_clamav("Windows", quick_scan=True)

    assert report.scan_status == "incomplete"
    assert "todas las ubicaciones previstas" in report.error
    assert any(
        "Documentos" in warning and "no existe" in warning
        for warning in report.warnings
    )


def test_windows_quick_clamav_does_not_run_without_existing_targets(tmp_path, monkeypatch):
    monkeypatch.setattr(clamav_scanner, "_windows_user_shell_folder", lambda _value_name: None)
    monkeypatch.setattr(clamav_scanner.tempfile, "gettempdir", lambda: str(tmp_path / "missing-temp"))
    monkeypatch.setattr(clamav_scanner.shutil, "which", lambda _name: "clamscan")
    calls = []

    def fake_run(arguments, **_kwargs):
        calls.append(arguments)
        return subprocess.CompletedProcess(arguments, 0, "ClamAV test", "")

    monkeypatch.setattr(clamav_scanner.subprocess, "run", fake_run)

    report = clamav_scanner.scan_with_clamav("Windows", quick_scan=True)

    assert report.scan_status == "failed"
    assert "No se encontraron ubicaciones" in report.error
    assert any("Temporales" in warning for warning in report.warnings)
    assert len(calls) == 1


def test_defender_full_scan_uses_powershell_and_reports_scan_state(monkeypatch):
    monkeypatch.setattr(windows_threat_scanner.shutil, "which", lambda _name: "powershell.exe")
    payload = {
        "scan_status": "completed",
        "engine_version": "4.18",
        "detection_basis": "defender_history",
        "signatures_updated": "2026-11-25T10:00:00.0000000Z",
        "started_at": "2026-11-25T10:01:00.0000000Z",
        "finished_at": "2026-11-25T10:02:00.0000000Z",
        "detections": [
            {
                "file_path": "C:\\sample.exe",
                "threat_name": "123",
                "action_status": "remediated_by_defender",
            }
        ],
        "error": None,
    }
    called = {}

    def fake_run(arguments, **_kwargs):
        called["arguments"] = arguments
        return subprocess.CompletedProcess(arguments, 0, json.dumps(payload), "")

    monkeypatch.setattr(windows_threat_scanner.subprocess, "run", fake_run)

    report = windows_threat_scanner.scan_with_defender()

    assert report.scan_status == "completed"
    assert report.signatures_updated == payload["signatures_updated"]
    assert report.detections[0].file_path == "C:\\sample.exe"
    assert "Start-MpScan -ScanType FullScan" in called["arguments"][-1]


def test_clamav_quarantine_rescans_before_moving_a_file(tmp_path, monkeypatch):
    source = tmp_path / "infected.bin"
    source.write_text("test data", encoding="utf-8")
    monkeypatch.setattr(clamav_scanner.shutil, "which", lambda _name: "clamscan")
    monkeypatch.setattr(clamav_scanner, "default_report_directory", lambda: tmp_path / "reports")
    calls = []

    def fake_run(arguments, **_kwargs):
        calls.append(arguments)
        destination = Path(arguments[3].split("=", 1)[1]) / source.name
        source.rename(destination)
        return subprocess.CompletedProcess(
            arguments,
            1,
            f"{source}: Test.Signature FOUND -> moved",
            "",
        )

    monkeypatch.setattr(clamav_scanner.subprocess, "run", fake_run)
    report = _report(detections=[ThreatDetection(str(source), "Test.Signature")])

    updated = clamav_scanner.quarantine_with_clamav(report)

    assert updated.detections[0].action_status == "quarantined"
    assert "--remove" not in calls[0]
    assert str(source) in calls[0]
    assert calls[0][0] == "clamscan"


def test_threat_report_store_preserves_reports_and_dashboard_escapes_payload(tmp_path):
    report = _report(
        detections=[ThreatDetection("</script><script>alert(1)</script>", "Test.Signature")]
    )
    generated_at = datetime(2026, 11, 25, 10, 0)

    first_path = save_threat_report(report, tmp_path, generated_at)
    second_path = save_threat_report(report, tmp_path, generated_at)
    html_path = write_threat_dashboard(report, first_path)
    updated = ThreatScanReport.create(
        operating_system="Linux",
        engine="ClamAV",
        engine_version="ClamAV test",
        scan_status="completed_with_detections",
        scope="entire_system",
        started_at=report.started_at,
        finished_at=report.finished_at,
        detections=[ThreatDetection("file", "Test.Signature", "quarantined")],
    )
    update_threat_report(updated, first_path)

    assert first_path.name == "amenazas_11_25_2026_10_00.json"
    assert second_path.name == "amenazas_11_25_2026_10_00_02.json"
    assert json.loads(first_path.read_text(encoding="utf-8"))["detections"][0]["action_status"] == "quarantined"
    assert "\\u003c/script\\u003e" in html_path.read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html_path.read_text(encoding="utf-8")
