from .models import DefenderObservation, Finding


def build_findings(defender: DefenderObservation) -> list[Finding]:
    findings: list[Finding] = []

    if not defender.available:
        findings.append(
            Finding(
                finding_id="defender_unavailable",
                severity="unknown",
                title="No se pudo verificar Microsoft Defender",
                detail="La cobertura antimalware de este equipo no pudo confirmarse.",
                evidence=[defender.error or "Defender no devolvió datos."],
                recommended_actions=[
                    "Comprueba el estado del antivirus en Seguridad de Windows.",
                    "Vuelve a ejecutar el análisis con una cuenta autorizada si el acceso fue denegado.",
                ],
                confidence="high",
            )
        )
        return findings

    disabled_protections = []
    if defender.antivirus_enabled is False:
        disabled_protections.append("Antivirus de Microsoft Defender desactivado")
    if defender.real_time_protection_enabled is False:
        disabled_protections.append("Protección en tiempo real desactivada")
    if disabled_protections:
        findings.append(
            Finding(
                finding_id="defender_protection_disabled",
                severity="high",
                title="Protección antimalware desactivada",
                detail="El estado de Defender reduce la protección preventiva del equipo; esto no prueba que exista una infección.",
                evidence=disabled_protections,
                recommended_actions=[
                    "Revisa Seguridad de Windows y activa la protección si corresponde a la política del equipo.",
                    "Si la opción está administrada por una organización, consulta con su equipo de TI.",
                ],
                confidence="high",
            )
        )

    if defender.detections:
        failed_actions = sum(detection.action_success is False for detection in defender.detections)
        findings.append(
            Finding(
                finding_id="defender_detection_history",
                severity="high" if failed_actions else "medium",
                title="Defender registra detecciones antimalware",
                detail=(
                    f"Se encontraron {len(defender.detections)} registros en el historial consultado. "
                    "El historial por sí solo no confirma una amenaza activa."
                ),
                evidence=[
                    f"Threat ID {detection.threat_id or 'desconocido'}; "
                    f"fecha {detection.detection_time or 'no disponible'}; "
                    f"acción correcta: {detection.action_success if detection.action_success is not None else 'desconocido'}"
                    for detection in defender.detections[:10]
                ],
                recommended_actions=[
                    "Revisa el historial de protección y el estado de cuarentena en Seguridad de Windows.",
                    "Si una acción de limpieza falló, sigue el flujo de remediación de Microsoft Defender o de TI.",
                ],
                confidence="high",
            )
        )

    if defender.quick_scan_status == "failed":
        findings.append(
            Finding(
                finding_id="defender_quick_scan_failed",
                severity="warning",
                title="No se pudo iniciar el análisis rápido",
                detail="Defender devolvió un error al solicitar el análisis rápido.",
                evidence=[defender.error or "No se recibió el motivo del error."],
                recommended_actions=[
                    "Abre Seguridad de Windows y ejecuta un análisis desde la sección Protección contra virus y amenazas."
                ],
                confidence="high",
            )
        )

    return findings