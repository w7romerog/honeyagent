"""
tools/send_alert.py
--------------------
Tool del agente: envía la alerta final de seguridad vía Slack.

Es la última tool que el agente llama en su loop, después de completar
el análisis con las otras herramientas.
"""

import json
import logging
import os

from slack_notifier import send_slack_alert
from tools.base import HoneyTool

logger = logging.getLogger(__name__)


class SendAlertTool(HoneyTool):
    """Envía una alerta de seguridad al canal de Slack del equipo."""

    @property
    def definition(self) -> dict:
        return {
            "name": "send_alert",
            "description": (
                "Envía una alerta de seguridad al canal de Slack del equipo con el análisis "
                "completo del incidente. Llamar esta tool es la acción final del agente, "
                "después de haber recopilado contexto con las otras herramientas. "
                "El campo 'analysis' debe contener el razonamiento completo: qué ocurrió, "
                "por qué es sospechoso, y qué acciones se recomiendan."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "honeypot_name": {"type": "string", "description": "Nombre del honeypot activado."},
                    "severity":      {"type": "string", "enum": ["low", "medium", "high", "critical"], "description": "Severidad evaluada por el agente."},
                    "source_ip":     {"type": "string", "description": "IP de origen del acceso sospechoso."},
                    "aws_user":      {"type": "string", "description": "Usuario o rol IAM involucrado."},
                    "event_name":    {"type": "string", "description": "Nombre del evento CloudTrail que disparó la alerta."},
                    "event_time":    {"type": "string", "description": "Timestamp ISO 8601 del evento original."},
                    "analysis":      {"type": "string", "description": "Análisis completo del incidente: qué ocurrió, indicadores de amenaza, nivel de riesgo y acciones recomendadas."},
                },
                "required": ["honeypot_name", "severity", "source_ip", "aws_user", "event_name", "event_time", "analysis"],
            },
        }

    def execute(
        self,
        honeypot_name: str,
        severity: str,
        source_ip: str,
        aws_user: str,
        event_name: str,
        event_time: str,
        analysis: str,
    ) -> dict:
        """
        Envía la alerta final al canal de Slack.

        Returns:
            Dict con 'sent' (bool), 'channel' (str), 'error' (None si OK).
        """
        if os.getenv("HONEYAGENT_MOCK", "false").lower() == "true":
            logger.info("[MOCK] Alerta simulada para '%s' (severidad: %s).", honeypot_name, severity)
            return {"sent": True, "channel": "slack (mock)", "error": None}

        event_data = {
            "honeypot_name": honeypot_name,
            "severity":      severity,
            "source_ip":     source_ip,
            "aws_user":      aws_user,
            "event_name":    event_name,
            "event_time":    event_time,
        }

        success = send_slack_alert(event_data, summary=analysis)
        if success:
            return {"sent": True, "channel": "slack", "error": None}
        return {"sent": False, "channel": "slack", "error": "Fallo al enviar a Slack (ver logs)."}


# ── Test standalone ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    os.environ["HONEYAGENT_MOCK"] = "true"

    tool = SendAlertTool()
    result = tool.safe_execute(
        honeypot_name="hp-fake-credentials-bucket",
        severity="high",
        source_ip="203.0.113.42",
        aws_user="hp-admin-backup-user",
        event_name="GetObject",
        event_time="2024-01-15T03:22:11+00:00",
        analysis="Análisis de prueba.",
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
