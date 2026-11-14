import os
import platform
import queue
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import font
import webbrowser

from .dashboard import write_dashboard
from .groq_client import has_groq_api_key
from .report_store import default_report_directory, save_report
from .scanner import run_security_scan


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
        self.root.geometry(f"760x560+{int(ws/2 - 760/2)}+{int(hs/2 - 540/2)}")
        self.root.minsize(620, 500)
        self.root.configure(bg=self.background)

        self.consent = tk.BooleanVar(value=False)
        self.quick_scan = tk.BooleanVar(value=False)
        self.groq_consent = tk.BooleanVar(value=False)
        self.include_paths = tk.BooleanVar(value=False)
        self.results: queue.Queue[tuple[str, object]] = queue.Queue()
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
        content.place(relx=0.5, rely=0.43, anchor="center")

        self.consent_check = tk.Checkbutton(
            content,
            text="Confirmo que tengo autorización para revisar este equipo",
            variable=self.consent,
            command=self._update_button_state,
            bg=self.background,
            fg=self.text,
            activebackground=self.background,
            selectcolor=self.background,
            font=body_font,
            cursor="hand2",
        )
        self.consent_check.pack(pady=(0, 22))

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

        if platform.system() == "Windows":
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

        self.scan_button = tk.Button(
            content,
            text="Iniciar escaneo",
            command=self._start_scan,
            bg=self.blue,
            fg="#FFFFFF",
            activebackground=self.blue_hover,
            activeforeground="#FFFFFF",
            disabledforeground="#FFFFFF",
            relief="flat",
            borderwidth=0,
            font=font.Font(family="Segoe UI", size=12, weight="bold"),
            padx=36,
            pady=15,
            cursor="hand2",
            state="disabled",
        )
        self.scan_button.pack()

        self.status = tk.StringVar(value="Autoriza la revisión para continuar.")
        tk.Label(
            content,
            textvariable=self.status,
            bg=self.background,
            fg=self.muted,
            font=body_font,
            wraplength=560,
            justify="center",
        ).pack(pady=(22, 8))

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
        self.scan_button.configure(state="disabled", text="Escaneando...")
        self.consent_check.configure(state="disabled")
        self.status.set("Recopilando señales locales y consultando Defender...")
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
            self.results.put(("success", (report, report_path, dashboard_path)))
        except Exception as error:
            self.results.put(("error", error))

    def _check_result(self) -> None:
        try:
            status, result = self.results.get_nowait()
        except queue.Empty:
            self.root.after(150, self._check_result)
            return

        if status == "success":
            report, report_path, dashboard_path = result
            try:
                browser_opened = webbrowser.open(dashboard_path.resolve().as_uri())
            except OSError:
                browser_opened = False
            browser_status = "Dashboard abierto en el navegador." if browser_opened else f"Abre el dashboard: {dashboard_path}"
            self.status.set(
                f"Escaneo completado: {len(report.processes)} procesos y "
                f"{len(report.connections)} conexiones.\n{browser_status}\nJSON: {report_path}"
            )
        else:
            self.status.set(f"No se pudo completar el escaneo: {result}")

        self.scan_button.configure(state="normal", text="Iniciar escaneo")
        self.consent_check.configure(state="normal")


def main() -> int:
    root = tk.Tk()
    NetThreatApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
