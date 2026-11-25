import os
import platform
from pathlib import Path
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import font, messagebox, ttk
import webbrowser

from .clamav_scanner import quarantine_with_clamav
from .dashboard import write_dashboard
from .groq_client import has_groq_api_key
from .report_store import default_report_directory, save_report
from .scanner import run_security_scan
from .threat_dashboard import write_threat_dashboard
from .threat_models import ThreatScanReport
from .threat_report_store import save_threat_report, update_threat_report
from .threat_scanner import SUPPORTED_OPERATING_SYSTEMS, detect_operating_system, run_threat_scan


class NetThreatApp:
    background = "#FFFFFF"
    blue = "#1677C8"
    blue_hover = "#0F66AE"
    pale_blue = "#EAF5FC"
    text = "#17324D"
    muted = "#60788C"

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("NetThreat Vision")
        ws = root.winfo_screenwidth()
        hs = root.winfo_screenheight()
        self.root.geometry(f"860x780+{int(ws/2 - 860/2)}+{int(hs/2 - 780/2)}")
        self.root.minsize(720, 700)
        self.root.configure(bg=self.background)

        self.consent = tk.BooleanVar(value=False)
        self.threat_consent = tk.BooleanVar(value=False)
        self.quick_scan = tk.BooleanVar(value=False)
        self.groq_consent = tk.BooleanVar(value=False)
        self.include_paths = tk.BooleanVar(value=False)
        try:
            self.detected_os = detect_operating_system()
        except ValueError:
            self.detected_os = ""
        self.selected_os = tk.StringVar(value=self.detected_os)
        self.selected_windows_engine = tk.StringVar(value="defender")
        self.is_windows = platform.system() == "Windows"
        self.results: queue.Queue[tuple[str, object]] = queue.Queue()
        self._progress_started_at: float | None = None
        self._progress_after_id: str | None = None
        self._build_ui()

    def _build_ui(self) -> None:
        title_font = font.Font(family="Segoe UI", size=25, weight="bold")
        body_font = font.Font(family="Segoe UI", size=11)
        small_font = font.Font(family="Segoe UI", size=9)
        link_font = font.Font(family="Segoe UI", size=9, underline=True)

        header = tk.Frame(self.root, bg=self.background, padx=42, pady=28)
        header.pack(fill="x")
        tk.Label(
            header,
            text="NetThreat Vision",
            bg=self.background,
            fg=self.text,
            font=title_font,
        ).pack(anchor="w")
        tk.Frame(self.root, bg=self.blue, height=1.5).pack(fill="x")
        tk.Frame(self.root, bg=self.pale_blue, height=2).pack(fill="x")

        main = tk.Frame(self.root, bg=self.background, padx=42)
        main.pack(fill="both", expand=True)
        content = tk.Frame(main, bg=self.background)
        content.pack(fill="both", expand=True, pady=(16, 20))

        self.consent_check = tk.Checkbutton(
            content,
            text="Autorizo el escaneo preventivo de procesos y conexiones de este equipo",
            variable=self.consent,
            command=self._update_button_state,
            bg=self.background,
            fg=self.text,
            activebackground=self.background,
            selectcolor=self.background,
            font=body_font,
            cursor="hand2",
        )
        self.consent_check.pack(anchor="w", pady=(0, 12))

        tk.Checkbutton(
            content,
            text="Incluir rutas de ejecutables (pueden revelar carpetas personales)",
            variable=self.include_paths,
            bg=self.background,
            fg=self.text,
            activebackground=self.background,
            selectcolor=self.background,
            font=body_font,
            cursor="hand2",
        ).pack(anchor="w", pady=(0, 10))

        if self.is_windows:
            tk.Checkbutton(
                content,
                text="Solicitar un análisis rápido de Microsoft Defender",
                variable=self.quick_scan,
                bg=self.background,
                fg=self.text,
                activebackground=self.background,
                selectcolor=self.background,
                font=body_font,
                cursor="hand2",
            ).pack(anchor="w", pady=(0, 3))
            tk.Label(
                content,
                text="Defender puede poner elementos en cuarentena según su configuración.",
                bg=self.background,
                fg=self.muted,
                font=small_font,
                wraplength=560,
                justify="left",
            ).pack(anchor="w", padx=(24, 0), pady=(0, 10))

        self.groq_check = tk.Checkbutton(
            content,
            text="Enviar telemetría seleccionada a Groq para interpretarla",
            variable=self.groq_consent,
            bg=self.background,
            fg=self.text,
            activebackground=self.background,
            selectcolor=self.background,
            font=body_font,
            cursor="hand2",
            state="normal" if has_groq_api_key() else "disabled",
        )
        self.groq_check.pack(anchor="w", pady=(0, 3))
        if not has_groq_api_key():
            tk.Label(
                content,
                text="Configura GROQ_API_KEY para habilitar el envío. El reporte local funciona sin Groq.",
                bg=self.background,
                fg=self.muted,
                font=small_font,
                wraplength=560,
                justify="left",
            ).pack(anchor="w", padx=(24, 0), pady=(0, 12))
        else:
            tk.Label(
                content,
                text="Al marcarlo se enviarán procesos, conexiones e indicadores a un servicio externo, incluidas rutas si las habilitas.",
                bg=self.background,
                fg=self.muted,
                font=small_font,
                wraplength=560,
                justify="left",
            ).pack(anchor="w", padx=(24, 0), pady=(0, 12))

        tk.Frame(content, bg="#DCE8F0", height=1).pack(fill="x", pady=(6, 12))
        tk.Label(
            content,
            text="Análisis puntual de amenazas",
            bg=self.background,
            fg=self.text,
            font=font.Font(family="Segoe UI", size=12, weight="bold"),
        ).pack(anchor="w")
        tk.Label(
            content,
            text="En Windows elige Defender completo o ClamAV rápido; Linux y macOS usan ClamAV.",
            bg=self.background,
            fg=self.muted,
            font=small_font,
            wraplength=700,
            justify="left",
        ).pack(anchor="w", pady=(3, 8))

        os_row = tk.Frame(content, bg=self.background)
        os_row.pack(anchor="w", pady=(0, 8))
        tk.Label(
            os_row,
            text="Sistema operativo:",
            bg=self.background,
            fg=self.text,
            font=body_font,
        ).pack(side="left", padx=(0, 8))
        self.os_selector = ttk.Combobox(
            os_row,
            textvariable=self.selected_os,
            values=SUPPORTED_OPERATING_SYSTEMS,
            state="readonly",
            width=14,
        )
        self.os_selector.pack(side="left")
        self.os_selector.bind("<<ComboboxSelected>>", lambda _event: self._update_button_state())
        detected_label = self.detected_os or platform.system() or "Desconocido"
        tk.Label(
            os_row,
            text=f"Detectado en este equipo: {detected_label}",
            bg=self.background,
            fg=self.muted,
            font=small_font,
        ).pack(side="left", padx=(10, 0))

        self.windows_engine_frame = tk.Frame(content, bg=self.background)
        tk.Label(
            self.windows_engine_frame,
            text="Motor para Windows:",
            bg=self.background,
            fg=self.text,
            font=body_font,
        ).pack(side="left", padx=(0, 8))
        self.defender_radio = ttk.Radiobutton(
            self.windows_engine_frame,
            text="Defender (análisis completo)",
            variable=self.selected_windows_engine,
            value="defender",
        )
        self.defender_radio.pack(side="left", padx=(0, 10))
        self.clamav_radio = ttk.Radiobutton(
            self.windows_engine_frame,
            text="ClamAV (rápido, alcance limitado)",
            variable=self.selected_windows_engine,
            value="clamav",
        )
        self.clamav_radio.pack(side="left")
        if self.detected_os == "Windows":
            self.windows_engine_frame.pack(fill="x", after=os_row, pady=(0, 8))

        self.threat_consent_check = tk.Checkbutton(
            content,
            text="Autorizo revisar archivos del sistema. El análisis completo puede tardar varias horas y requerir permisos adicionales.",
            variable=self.threat_consent,
            command=self._update_button_state,
            bg=self.background,
            fg=self.text,
            activebackground=self.background,
            selectcolor=self.background,
            font=body_font,
            cursor="hand2",
            wraplength=700,
            justify="left",
        )
        self.threat_consent_check.pack(anchor="w", pady=(0, 8))

        button_row = tk.Frame(content, bg=self.background)
        button_row.pack(fill="x", pady=(4, 0))
        button_font = font.Font(family="Segoe UI", size=11, weight="bold")
        self.scan_button = tk.Button(
            button_row,
            text="Escaneo preventivo",
            command=self._start_scan,
            bg=self.blue,
            fg="#FFFFFF",
            activebackground=self.blue_hover,
            activeforeground="#FFFFFF",
            disabledforeground="#FFFFFF",
            relief="flat",
            borderwidth=0,
            font=button_font,
            padx=14,
            pady=13,
            cursor="hand2",
            state="disabled",
        )
        self.scan_button.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.threat_scan_button = tk.Button(
            button_row,
            text="Análisis de amenazas",
            command=self._start_threat_scan,
            bg=self.blue,
            fg="#FFFFFF",
            activebackground=self.blue_hover,
            activeforeground="#FFFFFF",
            disabledforeground="#FFFFFF",
            relief="flat",
            borderwidth=0,
            font=button_font,
            padx=14,
            pady=13,
            cursor="hand2",
            state="disabled",
        )
        self.threat_scan_button.pack(side="left", fill="x", expand=True, padx=(6, 0))

        self.progress_frame = tk.Frame(content, bg=self.background)
        self.progress_status = tk.StringVar(value="")
        tk.Label(
            self.progress_frame,
            textvariable=self.progress_status,
            bg=self.background,
            fg=self.muted,
            font=small_font,
            anchor="w",
        ).pack(fill="x", pady=(8, 3))
        self.progress_bar = ttk.Progressbar(self.progress_frame, mode="indeterminate", maximum=100)
        self.progress_bar.pack(fill="x")

        self.status = tk.StringVar(value="Autoriza cada análisis para habilitar su botón.")
        tk.Label(
            content,
            textvariable=self.status,
            bg=self.background,
            fg=self.muted,
            font=body_font,
            wraplength=560,
            justify="center",
        ).pack(pady=(12, 8))

        report_directory = default_report_directory()
        report_location = tk.Frame(content, bg=self.background)
        report_location.pack(pady=(2, 0))
        tk.Label(
            report_location,
            text="Los reportes se guardan en:",
            bg=self.background,
            fg=self.muted,
            font=small_font,
        ).pack(side="left", padx=(0, 5))
        self.report_link = tk.Label(
            report_location,
            text=str(report_directory),
            bg=self.background,
            fg=self.blue,
            font=link_font,
            cursor="hand2",
        )
        self.report_link.pack(side="left")
        self.report_link.bind("<Button-1>", self._open_report_directory)
        self.report_link.bind("<Enter>", lambda _event: self.report_link.configure(fg=self.blue_hover))
        self.report_link.bind("<Leave>", lambda _event: self.report_link.configure(fg=self.blue))

    def _update_button_state(self) -> None:
        self.scan_button.configure(state="normal" if self.consent.get() else "disabled")
        self.threat_scan_button.configure(
            state="normal" if self.threat_consent.get() and self.selected_os.get() else "disabled"
        )
        if self.selected_os.get() == "Windows":
            if not self.windows_engine_frame.winfo_manager():
                self.windows_engine_frame.pack(fill="x", after=self.os_selector.master, pady=(0, 8))
        else:
            self.windows_engine_frame.pack_forget()

    def _open_report_directory(self, _event: tk.Event) -> str:
        report_directory = default_report_directory()
        report_directory.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(str(report_directory))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(report_directory)])
            else:
                subprocess.Popen(["xdg-open", str(report_directory)])
        except OSError as error:
            self.status.set(f"No se pudo abrir la carpeta: {error}")
        return "break"

    def _start_scan(self) -> None:
        if not self.consent.get():
            return
        self._set_busy(True, show_progress=False, active_button="preventive")
        scan_status = "Recopilando señales locales y consultando Defender..." if self.is_windows else "Recopilando señales locales..."
        self.status.set(scan_status)
        threading.Thread(
            target=self._scan_in_background,
            args=(self.include_paths.get(), self.quick_scan.get(), self.groq_consent.get()),
            daemon=True,
        ).start()
        self.root.after(150, self._check_result)

    def _scan_in_background(self, include_executable_paths: bool, start_quick_scan: bool, use_groq: bool) -> None:
        try:
            report = run_security_scan(
                include_executable_paths=include_executable_paths,
                start_quick_scan=start_quick_scan,
                use_groq=use_groq,
            )
            report_path = save_report(report)
            dashboard_path = write_dashboard(report, report_path)
            self.results.put(("preventive_success", (report, report_path, dashboard_path)))
        except Exception as error:
            self.results.put(("preventive_error", error))

    def _check_result(self) -> None:
        try:
            status, result = self.results.get_nowait()
        except queue.Empty:
            self.root.after(150, self._check_result)
            return

        if status == "preventive_success":
            report, report_path, dashboard_path = result
            self.status.set(
                f"Escaneo completado: {len(report.processes)} procesos y "
                f"{len(report.connections)} conexiones.\nJSON: {report_path}"
            )
            self._open_dashboard(dashboard_path)
            self._set_busy(False)
        elif status == "threat_success":
            report, report_path = result
            if report.engine == "ClamAV" and report.detections:
                should_quarantine = messagebox.askyesno(
                    "Detecciones encontradas",
                    f"ClamAV encontró {len(report.detections)} archivo(s). "
                    "¿Quieres volver a comprobarlos y mover los que sigan detectados a cuarentena?",
                    parent=self.root,
                )
                if should_quarantine:
                    self._start_quarantine(report, report_path)
                    return
            self.status.set(
                f"Análisis de amenazas: {report.scan_status}. "
                f"Detecciones: {len(report.detections)}.\nJSON: {report_path}"
            )
            self._open_dashboard(report_path.with_suffix(".html"))
            self._set_busy(False)
        elif status == "quarantine_success":
            report, report_path = result
            moved = sum(item.action_status == "quarantined" for item in report.detections)
            self.status.set(
                f"Cuarentena finalizada: {moved} archivo(s) movido(s). "
                f"Revisa el estado de cada archivo en el reporte.\nJSON: {report_path}"
            )
            self._open_dashboard(report_path.with_suffix(".html"))
            self._set_busy(False)
        else:
            self.status.set(f"No se pudo completar el escaneo: {result}")
            self._set_busy(False)

    def _start_threat_scan(self) -> None:
        if not self.threat_consent.get():
            return
        self._set_busy(True, show_progress=True, active_button="threat")
        selected_os = self.selected_os.get()
        selected_engine = self.selected_windows_engine.get() if selected_os == "Windows" else "defender"
        if selected_os != self.detected_os:
            self.results.put(
                (
                    "threat_error",
                    ValueError(
                        f"Seleccionaste {selected_os}, pero el sistema detectado es "
                        f"{self.detected_os or 'no compatible'}. Solo se puede analizar el equipo local."
                    ),
                )
            )
            self.root.after(150, self._check_result)
            return
        self.status.set(
            "Ejecutando el análisis completo de Defender; puede tardar horas."
            if selected_os == "Windows" and selected_engine == "defender"
            else "ClamAV revisará ubicaciones frecuentes del perfil. El escaneo es más acotado y puede omitir amenazas fuera de ellas."
            if selected_os == "Windows"
            else "ClamAV está revisando el sistema. Puede tardar varias horas; deja la aplicación abierta."
        )
        threading.Thread(
            target=self._threat_scan_in_background,
            args=(selected_os, selected_engine),
            daemon=True,
        ).start()
        self.root.after(150, self._check_result)

    def _threat_scan_in_background(self, selected_os: str, selected_engine: str) -> None:
        try:
            report = run_threat_scan(selected_os, windows_engine=selected_engine)
            report_path = save_threat_report(report)
            write_threat_dashboard(report, report_path)
            self.results.put(("threat_success", (report, report_path)))
        except Exception as error:
            self.results.put(("threat_error", error))

    def _start_quarantine(self, report: ThreatScanReport, report_path: Path) -> None:
        self._set_busy(True, show_progress=True, active_button="threat")
        threading.Thread(
            target=self._quarantine_in_background,
            args=(report, report_path),
            daemon=True,
        ).start()
        self.root.after(150, self._check_result)

    def _quarantine_in_background(self, report: ThreatScanReport, report_path: Path) -> None:
        try:
            updated_report = quarantine_with_clamav(report)
            update_threat_report(updated_report, report_path)
            write_threat_dashboard(updated_report, report_path)
            self.results.put(("quarantine_success", (updated_report, report_path)))
        except Exception as error:
            self.results.put(("threat_error", error))

    def _set_busy(
        self,
        busy: bool,
        show_progress: bool = False,
        active_button: str | None = None,
    ) -> None:
        self.scan_button.configure(
            state="disabled" if busy or not self.consent.get() else "normal",
            text="Escaneando..." if busy and active_button == "preventive" else "Escaneo preventivo",
        )
        self.threat_scan_button.configure(
            state="disabled"
            if busy or not self.threat_consent.get() or not self.selected_os.get()
            else "normal",
            text="Analizando amenazas..." if busy and active_button == "threat" else "Análisis de amenazas",
        )
        state = "disabled" if busy else "normal"
        self.consent_check.configure(state=state)
        self.threat_consent_check.configure(state=state)
        self.os_selector.configure(state="disabled" if busy else "readonly")
        for radio in (self.defender_radio, self.clamav_radio):
            radio.configure(state="disabled" if busy else "normal")
        if busy and show_progress:
            self._start_progress()
        else:
            self._stop_progress()

    def _start_progress(self) -> None:
        self._progress_started_at = time.monotonic()
        self.progress_frame.pack(fill="x", pady=(0, 6), after=self.threat_scan_button.master)
        self.progress_bar.start(12)
        self._update_progress_elapsed()

    def _update_progress_elapsed(self) -> None:
        if self._progress_started_at is None:
            return
        elapsed = int(time.monotonic() - self._progress_started_at)
        hours, remainder = divmod(elapsed, 3600)
        minutes, seconds = divmod(remainder, 60)
        self.progress_status.set(
            f"Análisis en curso · Tiempo transcurrido: {hours:02}:{minutes:02}:{seconds:02}. "
            "El motor no informa un porcentaje fiable."
        )
        self._progress_after_id = self.root.after(1000, self._update_progress_elapsed)

    def _stop_progress(self) -> None:
        self.progress_bar.stop()
        if self._progress_after_id is not None:
            self.root.after_cancel(self._progress_after_id)
            self._progress_after_id = None
        self._progress_started_at = None
        self.progress_status.set("")
        self.progress_frame.pack_forget()

    def _open_dashboard(self, dashboard_path: Path) -> None:
        try:
            browser_opened = webbrowser.open(dashboard_path.resolve().as_uri())
        except OSError:
            browser_opened = False
        if not browser_opened:
            self.status.set(f"{self.status.get()}\nAbre el dashboard: {dashboard_path}")


def main() -> int:
    root = tk.Tk()
    NetThreatApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
