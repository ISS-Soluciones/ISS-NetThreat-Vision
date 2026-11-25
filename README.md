# NetThreat Vision - agente local

Este folder contiene el componente que se ejecuta en el equipo auditado. El navegador no puede inspeccionar procesos ni conexiones del sistema operativo; por eso el flujo es híbrido. El agente detecta Windows, Linux o macOS y habilita únicamente las funciones disponibles para ese sistema:

```text
Agente local (con consentimiento) -> reporte JSON -> API backend -> dashboard
                                                -> motor de análisis/IA
```

El agente realiza una captura local de solo lectura. En Windows consulta el estado e historial de Microsoft Defender y, opcionalmente, puede solicitar un análisis rápido nativo. También permite iniciar un análisis puntual de amenazas: en Windows se puede elegir entre Microsoft Defender Full Scan y un análisis ClamAV rápido de ubicaciones frecuentes del perfil; en Linux/macOS se usa ClamAV recursivo. El usuario elige el sistema operativo en la interfaz; la selección debe coincidir con el equipo local. No bloquea puertos ni inicia escaneos contra otros equipos.

## Alcance actual

- Identifica sistema operativo y arquitectura.
- Recoge nombres/PID de procesos y sockets TCP/UDP visibles al usuario que ejecuta el agente.
- Las rutas de ejecutables solo se incluyen al marcar la opción de la interfaz o con `--include-executable-paths`.
- En Windows consulta Defender, sus firmas y hasta 50 registros de detección; el Quick Scan está desmarcado por defecto.
- En Linux y macOS omite por completo la integración Defender y sus métricas en el dashboard.
- El análisis de amenazas es un flujo independiente: en Windows permite elegir Defender Full Scan o ClamAV rápido (Descargas, Escritorio, Documentos, temporales y carpeta de inicio del perfil); Linux/macOS usan ClamAV recursivo. El análisis rápido tiene menor cobertura y no revisa el sistema completo. ClamAV debe instalarse y tener firmas disponibles; el wizard de instalación aún está pendiente.
- Los resultados del análisis de amenazas se guardan en JSON y HTML propios. ClamAV puede ofrecer mover detecciones a cuarentena después de una confirmación; Defender administra su propia remediación.
- Durante el análisis de amenazas, la interfaz muestra una barra animada y el tiempo transcurrido. No muestra un porcentaje porque los motores usados no exponen un progreso global fiable.
- Genera hallazgos de postura y evidencia conocida; los procesos y conexiones no se clasifican por sí mismos como maliciosos.
- Puede crear un reporte HTML autónomo junto al JSON, sin servicios externos ni recursos web.

Esto ofrece señales puntuales, no vigilancia continua. El historial de Defender no confirma que una amenaza siga activa. El análisis de amenazas puede tardar horas; los errores de acceso o una ejecución incompleta se reportan y no equivalen a un resultado limpio. No evalúa CVE/parches ni usa YARA en esta etapa. Las detecciones deben verificarse antes de recomendar acciones.

## Ejecutar

Requiere Python 3.11 o posterior. En Linux, Tkinter debe estar instalado para abrir la interfaz gráfica (en algunas distribuciones se ofrece como paquete `python3-tk`).

Windows (PowerShell):

```powershell
python -m pip install -e .
python -m netthreat_agent gui
```

Linux (terminal):

```bash
python3 -m pip install -e .
python3 -m netthreat_agent gui
```

La interfaz requiere confirmar la autorización antes de habilitar el botón de escaneo. En Windows, los reportes se guardan en `%LOCALAPPDATA%/NetThreatVision/reports`; en Linux usan `$XDG_DATA_HOME/netthreat-vision/reports` o, si no está definido, `~/.local/share/netthreat-vision/reports`. Los nombres mantienen el formato `reporte_MM_DD_YYYY_HH_MM.json`; si ya existe uno de ese minuto, agrega un sufijo para no sobrescribirlo.

Al terminar, la GUI abre el HTML local en el navegador. El archivo incluye la información del reporte y funciona sin conexión; los datos se insertan como texto, no como HTML ejecutable.

### Interpretación con Groq

La interpretación es opcional. La casilla de Groq permanece deshabilitada hasta que `GROQ_API_KEY` esté configurada en el entorno. Configura la clave en la misma sesión desde la que inicias la aplicación (no la pegues en el código ni en el reporte). PowerShell:

7mWWGdyb3FY92hvMZTSXAkk3Pv1UpH90ipt



```powershell
$env:GROQ_API_KEY = "tu-clave"
$env:GROQ_MODEL = "openai/gpt-oss-120b"
$env:GROQ_USER_AGENT = "NetThreatVision/0.1"
python -m netthreat_agent groq-test
python -m netthreat_agent gui
```

Linux:

```bash
export GROQ_API_KEY="tu-clave"
export GROQ_MODEL="openai/gpt-oss-120b"
export GROQ_USER_AGENT="NetThreatVision/0.1"
python3 -m netthreat_agent groq-test
python3 -m netthreat_agent gui
```

gsk_96xZDj3gHKE4IAI3A


`groq-test` comprueba clave, modelo y conexión enviando solo el texto fijo `Responde únicamente: OK`; no envía datos del equipo. Ejecuta la prueba en la misma terminal desde la que abrirás la GUI, porque el proceso hereda sus variables de entorno. Si la prueba da 403, verifica que `GROQ_API_KEY` sea la misma clave usada en Postman. Si funciona pero el análisis falla, revisa el detalle del error del reporte.

El cliente envía `Accept: application/json` y un `User-Agent` explícito. Si la política de red exige el mismo agente que Postman, copia únicamente el valor de su header `User-Agent` a `GROQ_USER_AGENT`; no copies ni compartas el header `Authorization`. El diagnóstico también muestra el `CF-Ray` si el rechazo viene de Cloudflare.

`GROQ_MODEL` es opcional; `openai/gpt-oss-120b` es el modelo predeterminado y se puede cambiar si tu cuenta usa otro identificador disponible. La clave se envía solo en el encabezado HTTPS y nunca se escribe en el JSON o el HTML. Si se marca la casilla de Groq, se envía una selección limitada del reporte (estado del sistema, hallazgos, hasta 80 procesos y 120 conexiones, y registros de Defender) al servicio externo de Groq. No marques esa opción si no autorizas compartir esos datos.

También se puede pedir la interpretación desde la terminal con `--interpret-with-groq`; el HTML se puede abrir con `--open-dashboard`. El análisis rápido nativo se solicita por separado con `--defender-quick-scan`, opción disponible solo en Windows. El análisis de amenazas está disponible desde la interfaz gráfica.

La captura también puede iniciarse desde la terminal:

```powershell
python -m netthreat_agent scan --consent --output report.json
```

Para incluir rutas de ejecutables, que pueden revelar nombres de usuario o estructura de carpetas:

```powershell
python -m netthreat_agent scan --consent --include-executable-paths --output report.json
```

El consentimiento se solicita explícitamente mediante `--consent`. El reporte puede contener nombres de procesos e IP/puertos remotos; debe tratarse como información sensible. Por defecto el agente no lo transmite a ningún servidor.

## Estructura

- `src/netthreat_agent/cli.py`: interfaz y control de consentimiento.
- `src/netthreat_agent/collector.py`: recolección local de procesos y conexiones con `psutil`.
- `src/netthreat_agent/windows_security.py`: consulta de Defender y solicitud opcional de Quick Scan.
- `src/netthreat_agent/groq_client.py`: interpretación opt-in con clave de entorno.
- `src/netthreat_agent/dashboard.py`: HTML autónomo del reporte.
- `src/netthreat_agent/models.py`: contrato JSON versionado 1.1.
- `src/netthreat_agent/threat_scanner.py`: selección del proveedor según sistema operativo y motor elegido.
- `src/netthreat_agent/windows_threat_scanner.py`: análisis completo y resultados de Microsoft Defender.
- `src/netthreat_agent/clamav_scanner.py`: análisis puntual con ClamAV y cuarentena confirmada por el usuario.
- `src/netthreat_agent/threat_models.py`: contrato versionado para los reportes de amenazas.
- `src/netthreat_agent/threat_report_store.py`: almacenamiento independiente de los reportes de amenazas.
- `src/netthreat_agent/threat_dashboard.py`: HTML autónomo del análisis de amenazas.
- `tests/`: pruebas del contrato y de la interfaz.

## Siguientes etapas

1. Añadir inventario de software/parches por sistema operativo y correlación con fuentes CVE; etiquetar evidencia y cobertura.
2. Añadir detección opcional con YARA/Osquery con reglas fijadas y resultados verificables.
3. Acordar el contrato HTTPS del backend (sesión temporal, expiración, límites y autenticación) antes de habilitar envíos.
4. Empaquetar para Windows/macOS/Linux y firmar los artefactos de distribución.
5. Mantener las recomendaciones de IA como texto para revisión humana; nunca ejecutar comandos generados automáticamente.

Los escaneos de red con Nmap/OpenVAS deben ejecutarse en el backend separado, con autorización explícita y alcance de objetivos validado. No forman parte de este agente local.