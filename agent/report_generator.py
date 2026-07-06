"""
agent/report_generator.py
---------------------------
Genera el reporte final del análisis de un evento del honeypot de identidad.

Produce dos formatos (alcance del Cap. 4 — sin PDF, sin dashboard):
  1. Markdown — lectura humana, con secciones fijas: resumen del evento,
     enriquecimiento mediante herramientas externas, razonamiento, veredicto,
     recomendación.
  2. JSON     — integración/trazabilidad: resumen del evento, evento original
     de CloudTrail sin procesar, y el informe completo del agente. Autocontenido:
     no depende de la retención de CloudTrail.

Convención de nombre de archivo (usada también para la key de S3):
    reports/iam_identity/{yyyy}/{mm}/{dd}/{timestamp}_{identity}_{event_id}.md
    reports/iam_identity/{yyyy}/{mm}/{dd}/{timestamp}_{identity}_{event_id}.json

El sufijo {event_id} (primeros 8 caracteres del eventID de CloudTrail, único
por evento) evita colisiones cuando dos ataques con la misma identidad señuelo
caen en el mismo segundo (ej. ataques simultáneos): sin ese sufijo, el segundo
reporte pisaría al primero en S3.
"""

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)


def report_key_prefix(event: dict, raw_event: dict | None = None) -> str:
    """
    Construye el prefijo de la convención de nombres a partir del timestamp
    del evento, la identidad involucrada, y el eventID de CloudTrail (no la
    hora de generación del reporte, para poder correlacionar el reporte con
    el evento original).

    El eventID es el desempatador ante ataques simultáneos: dos eventos de la
    misma identidad señuelo pueden caer en el mismo segundo, pero CloudTrail
    siempre les asigna un eventID distinto.
    """
    event_time = _parse_event_time(event.get("event_time"))
    identity = _sanitize_identity(event.get("aws_identity", "unknown"))
    timestamp = event_time.strftime("%Y%m%dT%H%M%SZ")
    event_id = _short_event_id(raw_event)

    return (
        f"reports/iam_identity/{event_time:%Y}/{event_time:%m}/{event_time:%d}/"
        f"{timestamp}_{identity}_{event_id}"
    )


def generate_report(
    event: dict,
    agent_result: dict,
    raw_event: dict | None = None,
    output_dir: str = "reports",
) -> dict:
    """
    Genera el reporte del evento en formato Markdown y JSON.

    Args:
        event:        Resumen estructurado del evento (ver agent/lambda_handler.py).
        agent_result: Resultado del agente (ver agent/agent.py::HoneyAgent.run).
        raw_event:    Evento crudo de CloudTrail/EventBridge (si está disponible),
                      para incluirlo sin procesar en el JSON.
        output_dir:   Directorio donde guardar los archivos generados.

    Returns:
        Dict {"markdown": path, "json": path} con las rutas locales generadas.
        El nombre base sigue report_key_prefix(event).
    """
    key_prefix = report_key_prefix(event, raw_event)
    base_name = key_prefix.rsplit("/", 1)[-1]

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    md_path = out_dir / f"{base_name}.md"
    json_path = out_dir / f"{base_name}.json"

    _write_markdown(event, agent_result, md_path)
    _write_json(event, agent_result, raw_event, json_path)

    logger.info("Reporte generado: %s | %s", md_path, json_path)
    return {"markdown": str(md_path), "json": str(json_path), "key_prefix": key_prefix}


# ── Markdown ─────────────────────────────────────────────────────────────────────

def _write_markdown(event: dict, agent_result: dict, path: Path) -> None:
    analysis_text = agent_result.get("final_analysis", "Sin análisis disponible.")

    lines = [
        "# HoneyAgent — Reporte de Incidente (Honeypot de Identidad)",
        "",
        f"_Generado: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}_",
        "",
        "## 1. Resumen del evento",
        "",
        f"- **Honeypot**: {event.get('honeypot_name', 'N/A')}",
        f"- **Identidad invocadora**: {event.get('aws_identity', 'N/A')}",
        f"- **Servicio**: {event.get('event_source', 'N/A')}",
        f"- **Operación**: {event.get('event_name', 'N/A')}",
        f"- **IP de origen**: {event.get('source_ip', 'N/A')}",
        f"- **Momento del evento**: {event.get('event_time', 'N/A')}",
        f"- **Región**: {event.get('aws_region', 'N/A')}",
        f"- **Resultado**: {event.get('result', 'N/A')}",
        f"- **Parámetros relevantes**: `{json.dumps(event.get('parameters', {}), ensure_ascii=False)}`",
        "",
        "## 2. Enriquecimiento mediante herramientas externas",
        "",
        _render_tools_table(agent_result.get("tools_called", [])),
        "",
        "## 3. Razonamiento",
        "",
        "> Texto tal cual generado por el agente, sin resumir:",
        "",
        analysis_text,
        "",
        "## 4. Veredicto",
        "",
        _extract_section(analysis_text, "Veredicto"),
        "",
        "## 5. Recomendación",
        "",
        _extract_section(analysis_text, "Recomendación"),
        "",
    ]

    path.write_text("\n".join(lines), encoding="utf-8")


def _render_tools_table(tools_called: list) -> str:
    if not tools_called:
        return "El agente no invocó herramientas externas para este evento."

    rows = ["| Herramienta | Argumentos |", "|---|---|"]
    for t in tools_called:
        args = json.dumps(t.get("input", {}), ensure_ascii=False)
        rows.append(f"| {t.get('tool', '')} | `{args}` |")
    return "\n".join(rows)


def _extract_section(text: str, label: str) -> str:
    """
    Extrae el contenido de una sección del texto del agente, tolerando las dos
    formas en que Claude la marca en la práctica (el system prompt de
    agent/agent.py pide negrita, pero el modelo a veces usa encabezado
    markdown en su lugar):

      - Encabezado propio: "### Veredicto" en su propia línea, contenido hasta
        el próximo encabezado (de igual o menor nivel) o el final del texto.
      - Negrita inline: "**Veredicto**: texto...", contenido hasta la próxima
        negrita en línea nueva o el final del texto.
    """
    heading_match = re.search(
        rf"^#{{1,6}}\s*{re.escape(label)}\s*$", text, re.IGNORECASE | re.MULTILINE,
    )
    if heading_match:
        start = heading_match.end()
        rest = text[start:]
        next_heading = re.search(r"^#{1,6}\s+\S", rest, re.MULTILINE)
        content = rest[: next_heading.start() if next_heading else None].strip()
        if content:
            return content

    bold_match = re.search(
        rf"\*\*{re.escape(label)}\*\*:?\s*(.+?)(?=\n\s*-?\s*\*\*|\n#{{1,6}}\s|\Z)",
        text, re.IGNORECASE | re.DOTALL,
    )
    if bold_match:
        return bold_match.group(1).strip()

    return f"(No se pudo extraer la sección '{label}' del análisis; ver Razonamiento completo arriba.)"


# ── JSON ────────────────────────────────────────────────────────────────────────

def _write_json(event: dict, agent_result: dict, raw_event: dict | None, path: Path) -> None:
    report = {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "framework": "HoneyAgent — MVP Cap. 4 (honeypot de identidad)",
            "report_format": "json",
        },
        "event_summary": event,
        "raw_cloudtrail_event": raw_event,
        "agent_report": {
            "success": agent_result.get("success"),
            "iterations": agent_result.get("iterations"),
            "tools_called": agent_result.get("tools_called", []),
            "final_analysis": agent_result.get("final_analysis"),
        },
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


# ── Helpers ──────────────────────────────────────────────────────────────────────

def _parse_event_time(value) -> datetime:
    if not value:
        return datetime.now(timezone.utc)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(timezone.utc)


def _sanitize_identity(identity: str) -> str:
    """Convierte un ARN/username en un fragmento seguro para nombre de archivo."""
    name = identity.rsplit("/", 1)[-1]
    return re.sub(r"[^A-Za-z0-9_.-]", "_", name) or "unknown"


def _short_event_id(raw_event: dict | None) -> str:
    """
    Primeros 8 caracteres del eventID de CloudTrail (único por evento). Si no
    hay evento crudo disponible (ej. tests unitarios sin raw_event), usa
    "noeventid" — solo pasa en ese escenario, nunca en producción, donde el
    eventID siempre lo provee CloudTrail.
    """
    event_id = (raw_event or {}).get("eventID")
    if not event_id:
        return "noeventid"
    return re.sub(r"[^A-Za-z0-9]", "", event_id)[:8] or "noeventid"


# ── Test standalone ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    test_event = {
        "honeypot_name": "hp-billing-readonly",
        "event_source":  "sts.amazonaws.com",
        "event_name":    "GetCallerIdentity",
        "event_time":    "2024-01-15T03:22:11+00:00",
        "source_ip":     "203.0.113.42",
        "aws_identity":  "arn:aws:iam::123456789012:user/billing-readonly",
        "aws_region":    "us-east-1",
        "parameters":    {},
        "result":        "success",
    }

    test_agent_result = {
        "success":    True,
        "iterations": 2,
        "tools_called": [
            {"tool": "lookup_ip_reputation", "input": {"ip": "203.0.113.42"}},
        ],
        "final_analysis": (
            "**Qué observé**: la identidad señuelo billing-readonly invocó "
            "sts:GetCallerIdentity, algo que nunca debería ocurrir legítimamente.\n\n"
            "**Qué busqué y por qué**: consulté lookup_ip_reputation para el origen, "
            "para descartar que fuera tráfico interno de AWS.\n\n"
            "**Cómo cambió mi evaluación**: la IP resultó ser de un proveedor de "
            "hosting en China, sin relación con la operación esperada del honeypot.\n\n"
            "**Veredicto**: critical — uso de credenciales señuelo desde origen externo "
            "no vinculado a ninguna operación legítima.\n\n"
            "**Recomendación**: revocar de inmediato las access keys de "
            "billing-readonly y revisar el resto de la sesión del atacante en CloudTrail."
        ),
        "error": None,
    }

    paths = generate_report(
        test_event, test_agent_result,
        raw_event={"eventID": "12345678-abcd-ef01-2345-6789abcdef01"},
        output_dir="reports",
    )
    print(f"Markdown: {paths['markdown']}")
    print(f"JSON:     {paths['json']}")
