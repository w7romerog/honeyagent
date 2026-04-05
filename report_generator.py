"""
report_generator.py
--------------------
Genera el reporte final del análisis de un incidente de honeypot.

Produce dos formatos:
  1. JSON  — máquina legible, útil para integrar con SIEMs o dashboards.
  2. PDF   — legible para humanos, incluible en la tesis directamente.

El PDF usa ReportLab (puro Python, sin dependencias de LaTeX ni browsers).
El JSON se guarda junto al PDF con el mismo nombre base.

Uso:
    from report_generator import generate_report
    paths = generate_report(event, agent_result, output_dir="reports/")
    # paths = {"json": "reports/incident_xxx.json", "pdf": "reports/incident_xxx.pdf"}
"""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

logger = logging.getLogger(__name__)

# ── Paleta de colores por severidad ────────────────────────────────────────────
SEVERITY_COLORS = {
    "low":      colors.HexColor("#2ecc71"),
    "medium":   colors.HexColor("#f39c12"),
    "high":     colors.HexColor("#e74c3c"),
    "critical": colors.HexColor("#7b0000"),
}


def generate_report(
    event: dict,
    agent_result: dict,
    output_dir: str = "reports",
) -> dict:
    """
    Genera el reporte del incidente en formato JSON y PDF.

    Args:
        event:        Evento original del honeypot (ver agent.py).
        agent_result: Resultado del agente (ver agent.run_agent()).
        output_dir:   Directorio donde guardar los archivos generados.

    Returns:
        Dict con las rutas de los archivos generados:
            {"json": "reports/incident_xxx.json", "pdf": "reports/incident_xxx.pdf"}
    """
    Path(output_dir).mkdir(parents=True, exist_ok=True)

    # Nombre base del archivo: incident_YYYYMMDD_HHMMSS
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    base_name = f"incident_{timestamp}"

    json_path = os.path.join(output_dir, f"{base_name}.json")
    pdf_path  = os.path.join(output_dir, f"{base_name}.pdf")

    # Generar ambos formatos
    _write_json(event, agent_result, json_path)
    _write_pdf(event, agent_result, pdf_path)

    logger.info("Reporte generado: %s | %s", json_path, pdf_path)
    return {"json": json_path, "pdf": pdf_path}


# ── JSON ────────────────────────────────────────────────────────────────────────

def _write_json(event: dict, agent_result: dict, path: str) -> None:
    """Escribe el reporte estructurado en JSON."""
    report = {
        "report_metadata": {
            "generated_at":  datetime.now(timezone.utc).isoformat(),
            "framework":     "HoneyAgent v0.1",
            "report_format": "json",
        },
        "incident": {
            "honeypot_name": event.get("honeypot_name"),
            "event_name":    event.get("event_name"),
            "event_time":    event.get("event_time"),
            "source_ip":     event.get("source_ip"),
            "aws_user":      event.get("aws_user"),
            "aws_region":    event.get("aws_region"),
            "resources":     event.get("resources", []),
        },
        "agent_analysis": {
            "success":      agent_result.get("success"),
            "iterations":   agent_result.get("iterations"),
            "tools_called": agent_result.get("tools_called", []),
            "final_analysis": agent_result.get("final_analysis"),
        },
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    logger.info("JSON generado: %s", path)


# ── PDF ─────────────────────────────────────────────────────────────────────────

def _write_pdf(event: dict, agent_result: dict, path: str) -> None:
    """Genera el reporte PDF usando ReportLab."""
    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )

    styles = _build_styles()
    story  = []

    # ── Encabezado ──────────────────────────────────────────────────────────────
    story.append(Paragraph("HoneyAgent", styles["title"]))
    story.append(Paragraph("Reporte de Incidente de Seguridad", styles["subtitle"]))
    story.append(Paragraph(
        f"Generado: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}",
        styles["meta"],
    ))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#2c3e50")))
    story.append(Spacer(1, 0.5 * cm))

    # ── Severidad (badge destacado) ─────────────────────────────────────────────
    # Determinamos la severidad desde las tools_called (send_alert guarda el campo)
    severity = _extract_severity(agent_result)
    sev_color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["medium"])
    story.append(Paragraph(
        f'<font color="white"><b>SEVERIDAD: {severity.upper()}</b></font>',
        ParagraphStyle(
            "severity_badge",
            parent=styles["Normal"],
            backColor=sev_color,
            textColor=colors.white,
            fontSize=14,
            leading=20,
            alignment=TA_CENTER,
            spaceAfter=12,
            borderPadding=(6, 10, 6, 10),
        ),
    ))
    story.append(Spacer(1, 0.3 * cm))

    # ── Resumen del incidente ───────────────────────────────────────────────────
    story.append(Paragraph("1. Datos del Incidente", styles["section"]))
    story.append(Spacer(1, 0.2 * cm))

    incident_data = [
        ["Campo",             "Valor"],
        ["Honeypot activado", event.get("honeypot_name", "N/A")],
        ["Evento CloudTrail", event.get("event_name", "N/A")],
        ["Hora del evento",   event.get("event_time", "N/A")],
        ["IP de origen",      event.get("source_ip", "N/A")],
        ["Usuario/Rol IAM",   event.get("aws_user", "N/A")],
        ["Región AWS",        event.get("aws_region", "N/A")],
    ]

    resources = event.get("resources", [])
    if resources:
        incident_data.append(["Recursos afectados", "\n".join(resources)])

    story.append(_build_table(incident_data, styles))
    story.append(Spacer(1, 0.5 * cm))

    # ── Herramientas ejecutadas ─────────────────────────────────────────────────
    story.append(Paragraph("2. Herramientas Ejecutadas por el Agente", styles["section"]))
    story.append(Spacer(1, 0.2 * cm))

    tools_called = agent_result.get("tools_called", [])
    if tools_called:
        tools_data = [["#", "Herramienta", "Argumentos"]]
        for i, t in enumerate(tools_called, 1):
            args_str = json.dumps(t.get("input", {}), ensure_ascii=False)
            # Truncar si es muy largo para que entre en la tabla
            if len(args_str) > 80:
                args_str = args_str[:77] + "..."
            tools_data.append([str(i), t.get("tool", ""), args_str])
        story.append(_build_table(tools_data, styles))
    else:
        story.append(Paragraph("No se ejecutaron herramientas.", styles["body"]))

    story.append(Paragraph(
        f"Iteraciones del loop de tool use: {agent_result.get('iterations', 0)}",
        styles["meta"],
    ))
    story.append(Spacer(1, 0.5 * cm))

    # ── Análisis del agente ─────────────────────────────────────────────────────
    story.append(Paragraph("3. Análisis del Agente LLM", styles["section"]))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
    story.append(Spacer(1, 0.2 * cm))

    analysis_text = agent_result.get("final_analysis", "Sin análisis disponible.")
    # Escapar caracteres especiales de XML que ReportLab no acepta
    analysis_text = analysis_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    # Convertir **texto** a negrita en ReportLab
    analysis_text = _markdown_to_reportlab(analysis_text)

    story.append(Paragraph(analysis_text, styles["analysis"]))
    story.append(Spacer(1, 0.5 * cm))

    # ── Pie de página ───────────────────────────────────────────────────────────
    story.append(HRFlowable(width="100%", thickness=1, color=colors.lightgrey))
    story.append(Spacer(1, 0.2 * cm))
    story.append(Paragraph(
        "Generado automáticamente por HoneyAgent · Framework de Honeypots con Agente LLM · Tesis de Licenciatura",
        styles["footer"],
    ))

    doc.build(story)
    logger.info("PDF generado: %s", path)


def _build_styles() -> dict:
    """Define los estilos tipográficos del PDF."""
    base = getSampleStyleSheet()
    dark = colors.HexColor("#2c3e50")

    return {
        "Normal": base["Normal"],
        "title": ParagraphStyle("title", fontSize=22, textColor=dark,
                                alignment=TA_CENTER, spaceAfter=4, fontName="Helvetica-Bold"),
        "subtitle": ParagraphStyle("subtitle", fontSize=13, textColor=colors.HexColor("#7f8c8d"),
                                   alignment=TA_CENTER, spaceAfter=4),
        "meta": ParagraphStyle("meta", fontSize=8, textColor=colors.grey,
                               alignment=TA_CENTER, spaceAfter=8),
        "section": ParagraphStyle("section", fontSize=13, textColor=dark,
                                  fontName="Helvetica-Bold", spaceBefore=8, spaceAfter=4),
        "body": ParagraphStyle("body", fontSize=10, textColor=dark, leading=14),
        "analysis": ParagraphStyle("analysis", fontSize=10, textColor=dark,
                                   leading=16, leftIndent=10),
        "footer": ParagraphStyle("footer", fontSize=7, textColor=colors.grey,
                                 alignment=TA_CENTER),
    }


def _build_table(data: list, styles: dict) -> Table:
    """Crea una tabla con estilo consistente."""
    col_widths = None
    if len(data[0]) == 2:
        col_widths = [4.5 * cm, 12 * cm]
    elif len(data[0]) == 3:
        col_widths = [1 * cm, 4.5 * cm, 11 * cm]

    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(TableStyle([
        # Encabezado
        ("BACKGROUND",   (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ("TEXTCOLOR",    (0, 0), (-1, 0), colors.white),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0), 10),
        ("ALIGN",        (0, 0), (-1, 0), "LEFT"),
        # Cuerpo
        ("FONTSIZE",     (0, 1), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
        ("GRID",         (0, 0), (-1, -1), 0.5, colors.HexColor("#dee2e6")),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ]))
    return table


def _extract_severity(agent_result: dict) -> str:
    """Extrae la severidad de los argumentos de la tool send_alert."""
    for tool_call in agent_result.get("tools_called", []):
        if tool_call.get("tool") == "send_alert":
            return tool_call.get("input", {}).get("severity", "medium")
    return "medium"


def _markdown_to_reportlab(text: str) -> str:
    """Convierte negrita Markdown (**texto**) a tags de ReportLab (<b>texto</b>)."""
    import re
    return re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)


# ── Test standalone ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    test_event = {
        "honeypot_name": "hp-fake-credentials-bucket",
        "event_name":    "GetObject",
        "event_time":    "2024-01-15T03:22:11+00:00",
        "source_ip":     "203.0.113.42",
        "aws_user":      "hp-admin-backup-user",
        "aws_region":    "us-east-1",
        "resources":     ["arn:aws:s3:::hp-fake-credentials-bucket/credentials/aws_keys_backup.csv"],
    }

    test_agent_result = {
        "success":    True,
        "iterations": 3,
        "tools_called": [
            {"tool": "ip_reputation_lookup",  "input": {"ip_address": "203.0.113.42"}},
            {"tool": "cloudtrail_query",       "input": {"source_ip": "203.0.113.42", "hours_back": 24}},
            {"tool": "iam_user_history",       "input": {"username": "hp-admin-backup-user"}},
            {"tool": "send_alert",             "input": {
                "honeypot_name": "hp-fake-credentials-bucket",
                "severity":      "high",
                "source_ip":     "203.0.113.42",
                "aws_user":      "hp-admin-backup-user",
                "event_name":    "GetObject",
                "event_time":    "2024-01-15T03:22:11+00:00",
                "analysis":      "Análisis de prueba para el reporte.",
            }},
        ],
        "final_analysis": (
            "**Qué ocurrió**: La IP 203.0.113.42 accedió al archivo "
            "`credentials/aws_keys_backup.csv` del bucket honeypot.\n\n"
            "**Indicadores de amenaza**: Score AbuseIPDB 87/100, país China, "
            "categorías: Port Scan, Brute-Force. El usuario IAM es un honeypot "
            "que nunca debería tener actividad.\n\n"
            "**Nivel de riesgo**: HIGH — IP maliciosa conocida accediendo a honeypot "
            "con nombre de credenciales.\n\n"
            "**Acciones recomendadas**: Bloquear 203.0.113.42 en WAF, revocar "
            "access keys del usuario IAM, revisar CloudTrail de las últimas 24h."
        ),
        "error": None,
    }

    paths = generate_report(test_event, test_agent_result, output_dir="reports")
    print(f"JSON: {paths['json']}")
    print(f"PDF:  {paths['pdf']}")
