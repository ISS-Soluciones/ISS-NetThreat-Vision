import argparse
import json
from pathlib import Path

from .dashboard import write_dashboard
from .scanner import run_security_scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="netthreat-agent")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("gui", help="Abre la interfaz gráfica local")
    commands.add_parser("groq-test", help="Prueba Groq con un texto fijo, sin enviar telemetría local")
    scan = commands.add_parser("scan", help="Genera una captura local de solo lectura")
    scan.add_argument("--consent", action="store_true", help="Confirma autorización para inspeccionar este equipo")
    scan.add_argument("--output", type=Path, default=Path("report.json"), help="Ruta del reporte JSON")
    scan.add_argument(
        "--defender-quick-scan",
        action="store_true",
        help="Solicita un análisis rápido nativo de Microsoft Defender",
    )
    scan.add_argument(
        "--interpret-with-groq",
        action="store_true",
        help="Envía una selección del reporte a Groq para obtener una interpretación",
    )
    scan.add_argument(
        "--open-dashboard",
        action="store_true",
        help="Abre el dashboard HTML al finalizar",
    )
    scan.add_argument(
        "--include-executable-paths",
        action="store_true",
        help="Incluye rutas que pueden revelar nombres de usuario o carpetas personales",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "gui":
        from .gui import main as gui_main

        return gui_main()
    if args.command == "groq-test":
        from .groq_client import test_groq_connection

        success, message = test_groq_connection()
        print(message)
        return 0 if success else 1

    if not args.consent:
        parser.error("se requiere --consent para inspeccionar el equipo local")

    report = run_security_scan(
        include_executable_paths=args.include_executable_paths,
        start_quick_scan=args.defender_quick_scan,
        use_groq=args.interpret_with_groq,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    dashboard_path = write_dashboard(report, args.output)
    print(f"Reporte local creado: {args.output}")
    print(f"Dashboard local creado: {dashboard_path}")
    print(f"Procesos: {len(report.processes)} | conexiones: {len(report.connections)} | advertencias: {len(report.warnings)}")
    if args.open_dashboard:
        import webbrowser

        webbrowser.open(dashboard_path.resolve().as_uri())
    return 0