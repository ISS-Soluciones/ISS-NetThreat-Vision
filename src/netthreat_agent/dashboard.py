import json
from pathlib import Path

from .models import ScanReport


def _safe_json(report: ScanReport) -> str:
    return (
        json.dumps(report.to_dict(), ensure_ascii=False, separators=(",", ":"))
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def write_dashboard(report: ScanReport, report_path: Path) -> Path:
    dashboard_path = report_path.with_suffix(".html")
    dashboard_path.write_text(_html_document(_safe_json(report)), encoding="utf-8")
    return dashboard_path


def _html_document(report_json: str) -> str:
    return r'''<!doctype html>
<html lang="es">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NetThreat Vision | Reporte</title>
  <style>
    :root { color-scheme: light; --ink:#17324d; --muted:#60788c; --blue:#1677c8; --blue-pale:#eaf5fc; --line:#dbe7ef; --surface:#fff; --canvas:#f5f9fc; --red:#b42318; --amber:#946200; --green:#137547; }
    * { box-sizing:border-box; }
    body { margin:0; background:var(--canvas); color:var(--ink); font-family:Segoe UI, sans-serif; font-size:15px; line-height:1.55; }
    header { background:var(--surface); border-bottom:1px solid var(--line); padding:22px max(24px, calc((100% - 1120px)/2)); display:flex; justify-content:space-between; align-items:center; gap:20px; }
    h1 { margin:0; font-size:22px; line-height:1.2; }
    h2 { margin:0 0 16px; font-size:17px; }
    h3 { margin:0; font-size:15px; }
    p { margin:6px 0; }
    main { max-width:1120px; margin:28px auto; padding:0 22px 40px; }
    .meta { color:var(--muted); font-size:13px; }
    .pill { border:1px solid var(--line); border-radius:20px; padding:6px 12px; color:var(--blue); background:var(--blue-pale); font-weight:600; white-space:nowrap; }
    .grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:12px; margin:18px 0; }
    .metric, section { background:var(--surface); border:1px solid var(--line); border-radius:6px; }
    .metric { padding:16px; min-height:94px; }
    .metric-label { color:var(--muted); font-size:12px; }
    .metric-value { margin-top:5px; font-size:18px; font-weight:700; overflow-wrap:anywhere; }
    section { padding:20px; margin-top:14px; }
    .summary { border-left:4px solid var(--blue); background:var(--blue-pale); padding:18px 20px; }
    .summary p { margin-bottom:0; }
    .stack { display:grid; gap:10px; }
    .finding { border:1px solid var(--line); border-left:4px solid var(--blue); padding:14px; border-radius:4px; }
    .finding.high, .finding.critical { border-left-color:var(--red); }
    .finding.medium, .finding.warning { border-left-color:var(--amber); }
    .finding h3 { display:flex; justify-content:space-between; gap:12px; flex-wrap:wrap; }
    .tag { color:var(--muted); font-size:12px; font-weight:600; text-transform:uppercase; }
    .list { margin:8px 0 0; padding-left:20px; }
    .list li + li { margin-top:5px; }
    .columns { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
    .table-wrap { overflow:auto; max-height:380px; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th, td { padding:9px 10px; text-align:left; border-bottom:1px solid var(--line); vertical-align:top; overflow-wrap:anywhere; }
    th { position:sticky; top:0; background:#f5f9fc; color:var(--muted); font-size:12px; }
    .empty { color:var(--muted); }
    .error { color:var(--red); }
    footer { color:var(--muted); font-size:12px; padding:18px 2px; }
    @media (max-width:760px) { header { align-items:flex-start; flex-direction:column; } .grid { grid-template-columns:repeat(2,minmax(0,1fr)); } .columns { grid-template-columns:1fr; } main { margin-top:16px; padding:0 14px 28px; } section { padding:16px; } }
    @media (max-width:420px) { .grid { grid-template-columns:1fr 1fr; gap:8px; } .metric { padding:12px; } .metric-value { font-size:16px; } }
  </style>
</head>
<body>
  <header><div><h1>NetThreat Vision</h1><div class="meta" id="scan-meta"></div></div><div class="pill">Reporte local</div></header>
  <main>
    <div class="summary"><h2 id="risk-title">Resultado del análisis</h2><p id="summary"></p></div>
    <div class="grid" id="metrics"></div>
    <section><h2>Hallazgos locales</h2><div class="stack" id="findings"></div></section>
    <section><h2>Interpretación de IA</h2><div id="ai-analysis"></div></section>
    <section id="defender-section"><h2>Microsoft Defender</h2><div id="defender"></div></section>
    <div class="columns">
      <section><h2>Procesos observados</h2><div class="table-wrap" id="processes"></div></section>
      <section><h2>Conexiones observadas</h2><div class="table-wrap" id="connections"></div></section>
    </div>
    <section><h2>Advertencias y cobertura</h2><div id="coverage"></div></section>
    <footer>Las observaciones son una captura puntual y no prueban por sí solas un compromiso. Verifica los hallazgos antes de tomar medidas.</footer>
  </main>
  <script id="report-data" type="application/json">__REPORT_JSON__</script>
  <script>
    "use strict";
    const report = JSON.parse(document.getElementById("report-data").textContent);
    const node = (tag, text, className) => { const item = document.createElement(tag); if (text !== undefined) item.textContent = text; if (className) item.className = className; return item; };
    const list = (items) => { if (!items || !items.length) return node("p", "Sin datos disponibles.", "empty"); const ul = node("ul", undefined, "list"); items.forEach(text => ul.append(node("li", text))); return ul; };
    const ai = report.ai_interpretation;
    const defender = report.defender;
    document.getElementById("scan-meta").textContent = `${report.system.operating_system} ${report.system.release} · ${new Date(report.generated_at).toLocaleString("es")}`;
    const findingsList = report.findings || [];
    const risk = ai && ai.status === "ready" ? ai.risk_level : findingsList.some(item => item.severity === "high" || item.severity === "critical") ? "Revisión prioritaria" : findingsList.some(item => item.severity === "medium" || item.severity === "warning") ? "Requiere revisión" : findingsList.some(item => item.severity === "unknown") ? "Cobertura incompleta" : "Sin alerta confirmada";
    document.getElementById("risk-title").textContent = `Estado: ${risk || "Indeterminado"}`;
    document.getElementById("summary").textContent = ai && ai.status === "ready" ? ai.summary : "Se recopilaron indicadores locales. Sin interpretación de IA; consulta los hallazgos y su evidencia.";
    const metrics = document.getElementById("metrics");
    const metricData = [["Procesos", report.processes.length], ["Conexiones", report.connections.length]];
    if (defender) metricData.push(["Registros Defender", defender.detections.length]);
    metricData.push(["Hallazgos", (report.findings || []).length]);
    metricData.forEach(([label, value]) => { const card = node("div", undefined, "metric"); card.append(node("div", label, "metric-label"), node("div", String(value), "metric-value")); metrics.append(card); });
    const findings = document.getElementById("findings");
    if (!(report.findings || []).length) findings.append(node("p", "No se generaron hallazgos con las comprobaciones disponibles.", "empty"));
    (report.findings || []).forEach(item => { const card = node("article", undefined, `finding ${item.severity}`); const title = node("h3"); title.append(node("span", item.title), node("span", item.severity, "tag")); card.append(title, node("p", item.detail), node("p", `Confianza: ${item.confidence}`, "meta")); if (item.evidence.length) card.append(node("h3", "Evidencia"), list(item.evidence)); if (item.recommended_actions.length) card.append(node("h3", "Acciones sugeridas"), list(item.recommended_actions)); findings.append(card); });
    const aiSection = document.getElementById("ai-analysis");
    if (ai && ai.status === "ready") { aiSection.append(node("p", `Modelo: ${ai.model} · Riesgo estimado: ${ai.risk_level}`, "meta"), node("h3", "Observaciones"), list(ai.observations), node("h3", "Acciones inmediatas"), list(ai.immediate_actions), node("h3", "Alternativas"), list(ai.alternatives), node("h3", "Prevención"), list(ai.prevention), node("h3", "Limitaciones"), list(ai.caveats)); }
    else { aiSection.append(node("p", ai && ai.error ? ai.error : "La interpretación de IA no se solicitó."), node("p", "Los hallazgos locales están disponibles aunque Groq no responda.", "meta")); }
    const defenderSection = document.getElementById("defender-section");
    if (!defender) defenderSection.remove();
    else {
      const defenderContent = document.getElementById("defender");
      if (!defender.available) defenderContent.append(node("p", defender.error || "No se obtuvo información de Defender.", "empty"));
      else { defenderContent.append(node("p", `Antivirus: ${defender.antivirus_enabled ? "activo" : "inactivo o desconocido"} · Protección en tiempo real: ${defender.real_time_protection_enabled ? "activa" : "inactiva o desconocida"}`), node("p", `Última actualización de firmas: ${defender.signature_last_updated || "no disponible"}`), node("p", `Análisis rápido: ${defender.quick_scan_status}`)); if (defender.error) defenderContent.append(node("p", defender.error, "error")); }
    }
    function renderTable(targetId, headers, rows) { const target = document.getElementById(targetId); if (!rows.length) { target.append(node("p", "No hay observaciones.", "empty")); return; } const table = node("table"); const head = node("thead"); const headerRow = node("tr"); headers.forEach(value => headerRow.append(node("th", value))); head.append(headerRow); const body = node("tbody"); rows.slice(0, 100).forEach(values => { const row = node("tr"); values.forEach(value => row.append(node("td", value || "—"))); body.append(row); }); table.append(head, body); target.append(table); if (rows.length > 100) target.append(node("p", `Se muestran 100 de ${rows.length}; el JSON contiene todos los registros.`, "meta")); }
    renderTable("processes", ["PID", "Proceso", "Ruta"], report.processes.map(item => [String(item.pid), item.name, item.executable_path]));
    renderTable("connections", ["Proceso", "Protocolo", "Estado", "Local", "Remoto"], report.connections.map(item => [item.process_name || String(item.pid || "—"), item.protocol, item.status, `${item.local_address || "—"}:${item.local_port || "—"}`, item.remote_address ? `${item.remote_address}:${item.remote_port || "—"}` : "—"]));
    const coverage = document.getElementById("coverage");
    coverage.append(node("h3", "Advertencias"), list(report.warnings), node("h3", "Limitaciones"), list(report.limitations));
  </script>
</body>
</html>'''.replace("__REPORT_JSON__", report_json)