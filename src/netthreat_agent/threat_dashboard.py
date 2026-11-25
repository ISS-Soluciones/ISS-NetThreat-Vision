import json
from pathlib import Path

from .threat_models import ThreatScanReport


def write_threat_dashboard(report: ThreatScanReport, report_path: Path) -> Path:
    dashboard_path = report_path.with_suffix(".html")
    report_json = (
        json.dumps(report.to_dict(), ensure_ascii=False, separators=(",", ":"))
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    dashboard_path.write_text(_html_document(report_json), encoding="utf-8")
    return dashboard_path


def _html_document(report_json: str) -> str:
    return r'''<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetThreat Vision | Análisis de amenazas</title>
  <style>
    :root { color-scheme:light; --ink:#17324d; --muted:#60788c; --blue:#1677c8; --line:#dbe7ef; --surface:#fff; --canvas:#f5f9fc; --red:#b42318; --amber:#946200; --green:#137547; }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--canvas); color:var(--ink); font-family:Segoe UI,sans-serif; font-size:15px; line-height:1.55; }
    header { background:var(--surface); border-bottom:1px solid var(--line); padding:22px max(24px,calc((100% - 960px)/2)); }
    main { max-width:960px; margin:28px auto; padding:0 22px 40px; }
    h1 { margin:0; font-size:22px; }
    h2 { margin:0 0 12px; font-size:17px; }
    section,.summary { background:var(--surface); border:1px solid var(--line); border-radius:6px; padding:20px; margin-top:14px; }
    .summary { border-left:4px solid var(--blue); }
    .meta,.empty { color:var(--muted); }
    .error { color:var(--red); }
    .detection { border:1px solid var(--line); border-left:4px solid var(--red); border-radius:4px; padding:14px; margin-top:10px; overflow-wrap:anywhere; }
    .detection h3 { margin:0 0 8px; font-size:15px; }
    ul { padding-left:20px; }
    li+li { margin-top:5px; }
    footer { color:var(--muted); font-size:12px; padding:18px 2px; }
  </style>
</head>
<body>
  <header><h1>NetThreat Vision — Análisis de amenazas</h1><div class="meta" id="meta"></div></header>
  <main>
    <div class="summary"><h2 id="status"></h2><p id="summary"></p></div>
    <section><h2>Motor y alcance</h2><div id="engine"></div></section>
    <section><h2>Detecciones</h2><div id="detections"></div></section>
    <section><h2>Advertencias</h2><div id="warnings"></div></section>
    <footer>Una detección requiere verificación. Un análisis puntual no equivale a protección continua ni garantiza ausencia total de amenazas.</footer>
  </main>
  <script id="report-data" type="application/json">__REPORT_JSON__</script>
  <script>
    "use strict";
    const report = JSON.parse(document.getElementById("report-data").textContent);
    const node = (tag, text, className) => { const item = document.createElement(tag); if (text !== undefined) item.textContent = text; if (className) item.className = className; return item; };
    document.getElementById("meta").textContent = `${report.operating_system} · ${new Date(report.generated_at).toLocaleString("es")}`;
    const labels = {completed:"Análisis completado",completed_with_detections:"Análisis completado con detecciones",incomplete:"Análisis incompleto",unavailable:"Motor no disponible",failed:"Análisis fallido"};
    document.getElementById("status").textContent = labels[report.scan_status] || "Estado indeterminado";
    const summary = report.error || (report.scan_status === "unavailable" ? "No se pudo realizar el análisis porque el motor no está disponible." : report.scan_status === "incomplete" ? "El análisis quedó incompleto; no se puede concluir que el sistema esté limpio." : report.detections.length ? `Se encontraron ${report.detections.length} detección(es) reportada(s).` : "El motor no reportó detecciones dentro del alcance revisado.");
    document.getElementById("summary").textContent = summary;
    document.getElementById("engine").append(node("p", `Motor: ${report.engine}${report.engine_version ? ` (${report.engine_version})` : ""}`), node("p", `Alcance: ${report.scope}`), node("p", `Base de detecciones: ${report.detection_basis === "defender_history" ? "historial de Defender" : "salida del análisis"}`), node("p", `Firmas actualizadas: ${report.signatures_updated || "no disponible"}`), node("p", `Inicio: ${report.started_at || "no disponible"} · Fin: ${report.finished_at || "no confirmado"}`, "meta"));
    const detections = document.getElementById("detections");
    if (!report.detections.length) detections.append(node("p", "No hay detecciones reportadas.", "empty"));
    report.detections.forEach(item => { const card = node("article", undefined, "detection"); card.append(node("h3", item.threat_name || "Detección"), node("p", item.file_path), node("p", `Acción: ${item.action_status}${item.action_detail ? ` · ${item.action_detail}` : ""}`, "meta")); detections.append(card); });
    const warnings = document.getElementById("warnings");
    if (!report.warnings.length) warnings.append(node("p", "Sin advertencias.", "empty"));
    else { const list = node("ul"); report.warnings.forEach(item => list.append(node("li", item))); warnings.append(list); }
  </script>
</body>
</html>'''.replace("__REPORT_JSON__", report_json)
