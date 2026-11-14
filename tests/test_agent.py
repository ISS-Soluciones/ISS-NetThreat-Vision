import json
import io
from datetime import datetime
import urllib.error
from unittest.mock import patch

from netthreat_agent.cli import main
from netthreat_agent.dashboard import write_dashboard
from netthreat_agent.findings import build_findings
from netthreat_agent.groq_client import (
    MAX_GROQ_INPUT_CHARS,
    GROQ_RESPONSES_URL,
    _build_groq_input,
    interpret_report_with_groq,
    test_groq_connection as run_groq_connection_test,
)
from netthreat_agent.models import (
    DefenderDetection,
    DefenderObservation,
    ProcessObservation,
    ScanReport,
    SystemObservation,
)
from netthreat_agent.report_store import save_report


def test_scan_requires_explicit_consent(tmp_path):
    output = tmp_path / "report.json"

    try:
        main(["scan", "--output", str(output)])
    except SystemExit as error:
        assert error.code == 2
    else:
        raise AssertionError("scan should require explicit consent")

    assert not output.exists()


def test_scan_writes_versioned_local_report(tmp_path):
    output = tmp_path / "report.json"

    assert main(["scan", "--consent", "--output", str(output)]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))

    assert report["schema_version"] == "1.1"
    assert report["scope"] == "local_processes_and_network_connections_snapshot"
    assert report["system"]["operating_system"]
    assert "limitations" in report
    assert "processes" in report
    assert "connections" in report
    assert "defender" in report
    assert output.with_suffix(".html").exists()


def test_report_uses_requested_name_and_preserves_existing_reports(tmp_path):
    report = ScanReport.create(
        system=SystemObservation("Windows", "11", "AMD64"),
        processes=[],
        connections=[],
        warnings=[],
    )
    generated_at = datetime(2026, 11, 13, 18, 6)

    first_path = save_report(report, tmp_path, generated_at)
    second_path = save_report(report, tmp_path, generated_at)

    assert first_path.name == "reporte_11_13_2026_18_06.json"
    assert second_path.name == "reporte_11_13_2026_18_06_02.json"
    assert json.loads(first_path.read_text(encoding="utf-8"))["schema_version"] == "1.1"


def test_defender_detection_history_is_not_reported_as_active_infection():
    defender = DefenderObservation(
        available=True,
        antivirus_enabled=True,
        real_time_protection_enabled=True,
        signature_last_updated=None,
        detections=[DefenderDetection("1234", "2026-11-12T10:00:00Z", True)],
        quick_scan_status="not_requested",
    )

    findings = build_findings(defender)

    assert findings[0].finding_id == "defender_detection_history"
    assert "no confirma una amenaza activa" in findings[0].detail


def test_disabled_defender_protection_creates_posture_finding():
    defender = DefenderObservation(
        available=True,
        antivirus_enabled=True,
        real_time_protection_enabled=False,
        signature_last_updated=None,
        detections=[],
        quick_scan_status="not_requested",
    )

    findings = build_findings(defender)

    assert findings[0].finding_id == "defender_protection_disabled"
    assert findings[0].severity == "high"


def test_dashboard_is_self_contained_and_escapes_script_payload(tmp_path):
    report = ScanReport.create(
        system=SystemObservation("Windows", "11", "AMD64"),
        processes=[ProcessObservation(123, "</script><script>alert(1)</script>")],
        connections=[],
        warnings=[],
    )

    dashboard_path = write_dashboard(report, tmp_path / "reporte.json")
    dashboard = dashboard_path.read_text(encoding="utf-8")

    assert dashboard_path.name == "reporte.html"
    assert "NetThreat Vision" in dashboard
    assert "\\u003c/script\\u003e" in dashboard
    assert "<script>alert(1)</script>" not in dashboard


def test_groq_interpretation_uses_environment_key_without_persisting_it(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-secret-not-for-report")
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    report = ScanReport.create(
        system=SystemObservation("Windows", "11", "AMD64"),
        processes=[],
        connections=[],
        warnings=[],
    )
    response_body = json.dumps(
        {
            "object": "response",
            "status": "completed",
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "output_text",
                            "text": json.dumps(
                            {
                                "risk_level": "Indeterminado",
                                "summary": "Sin evidencia suficiente.",
                                "observations": [],
                                "immediate_actions": [],
                                "alternatives": [],
                                "prevention": [],
                                "caveats": ["Captura puntual."],
                            }
                            ),
                        }
                    ],
                    }
            ]
        }
    ).encode("utf-8")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return response_body

    with patch("netthreat_agent.groq_client.urllib.request.urlopen", return_value=FakeResponse()) as urlopen:
        interpretation = interpret_report_with_groq(report)

    request = urlopen.call_args.args[0]
    assert request.full_url == GROQ_RESPONSES_URL
    assert request.get_header("Authorization") == "Bearer test-secret-not-for-report"
    request_body = json.loads(request.data)
    assert request_body["model"] == "openai/gpt-oss-120b"
    assert set(request_body) == {"model", "input"}
    assert "Responde solo con JSON" in request_body["input"]
    assert '"schema_version":"1.1"' in request_body["input"]
    assert interpretation.status == "ready"
    assert interpretation.summary == "Sin evidencia suficiente."
    assert "test-secret-not-for-report" not in json.dumps(interpretation.__dict__)


def test_groq_http_error_exposes_provider_reason_without_api_key(monkeypatch):
    api_key = "test-secret-not-for-report"
    monkeypatch.setenv("GROQ_API_KEY", api_key)
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    report = ScanReport.create(
        system=SystemObservation("Windows", "11", "AMD64"),
        processes=[],
        connections=[],
        warnings=[],
    )
    response_body = json.dumps(
        {"error": {"message": "model is not available for this account", "type": "access_denied", "code": "model_access_denied"}}
    ).encode("utf-8")
    http_error = urllib.error.HTTPError(
        GROQ_RESPONSES_URL,
        403,
        "Forbidden",
        hdrs=None,
        fp=io.BytesIO(response_body),
    )

    with patch("netthreat_agent.groq_client.urllib.request.urlopen", side_effect=http_error):
        interpretation = interpret_report_with_groq(report)

    assert interpretation.status == "error"
    assert "model_access_denied" in interpretation.error
    assert "openai/gpt-oss-120b" in interpretation.error
    assert "model is not available for this account" in interpretation.error
    assert api_key not in interpretation.error


def test_groq_connection_check_uses_only_minimal_input(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test-secret-not-for-report")
    monkeypatch.setenv("GROQ_MODEL", "openai/gpt-oss-120b")
    response_body = json.dumps(
        {"status": "completed", "output": [{"content": [{"type": "output_text", "text": "OK"}]}]}
    ).encode("utf-8")

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self):
            return response_body

    with patch("netthreat_agent.groq_client.urllib.request.urlopen", return_value=FakeResponse()) as urlopen:
        success, message = run_groq_connection_test()

    request = urlopen.call_args.args[0]
    request_body = json.loads(request.data)
    assert request.full_url == GROQ_RESPONSES_URL
    assert request.get_method() == "POST"
    assert request.get_header("Authorization") == "Bearer test-secret-not-for-report"
    assert request.get_header("Content-type") == "application/json"
    assert request.get_header("Accept") == "application/json"
    assert request.get_header("User-agent") == "NetThreatVision/0.1"
    assert request_body == {"model": "openai/gpt-oss-120b", "input": "Responde únicamente: OK"}
    assert success
    assert "Conexión correcta" in message


def test_groq_input_stays_under_budget_for_large_reports():
    report = ScanReport.create(
        system=SystemObservation("Windows", "11", "AMD64"),
        processes=[ProcessObservation(pid, f"process-{pid}-" + "x" * 400) for pid in range(600)],
        connections=[],
        warnings=["w" * 300 for _ in range(100)],
    )

    input_text = _build_groq_input(report)

    assert len(input_text) <= MAX_GROQ_INPUT_CHARS
    assert '"processes":600' in input_text
    report_json = input_text.split("REPORTE:\n", 1)[1]
    assert len(json.loads(report_json)["processes"]) < 600