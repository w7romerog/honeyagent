"""
slack_notifier.py
-----------------
Envía alertas al canal de Slack configurado via Incoming Webhook.

Diseño:
  - El webhook URL se obtiene de AWS Secrets Manager (nunca hardcodeado).
  - Cada alerta incluye: severidad, honeypot afectado, IP de origen, resumen del agente.
  - Los colores del mensaje siguen el estándar de severidad de seguridad.

Uso standalone (testing):
    python slack_notifier.py

Uso desde el agente:
    from slack_notifier import send_slack_alert
    send_slack_alert(event_data, summary="El agente detectó X")
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3
import requests
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)

# Colores de los mensajes Slack según severidad (formato hex de Slack)
SEVERITY_COLORS = {
    "low":      "#36a64f",   # verde
    "medium":   "#ff9900",   # naranja
    "high":     "#e01563",   # rojo
    "critical": "#7b0000",   # rojo oscuro
}

SEVERITY_EMOJIS = {
    "low":      ":white_check_mark:",
    "medium":   ":warning:",
    "high":     ":rotating_light:",
    "critical": ":skull:",
}


def _get_webhook_url() -> str:
    """
    Recupera el webhook URL desde AWS Secrets Manager.

    Para desarrollo local, acepta la variable de entorno SLACK_WEBHOOK_URL
    como fallback (útil antes de tener AWS configurado).
    """
    # Fallback para desarrollo local sin AWS
    local_url = os.getenv("SLACK_WEBHOOK_URL")
    if local_url:
        logger.debug("Usando SLACK_WEBHOOK_URL del entorno local.")
        return local_url

    # Producción: leer de Secrets Manager
    secret_name = os.getenv("SLACK_WEBHOOK_SECRET", "honeyagent/slack/webhook")
    region = os.getenv("AWS_REGION", "us-east-1")

    client = boto3.client("secretsmanager", region_name=region)
    try:
        response = client.get_secret_value(SecretId=secret_name)
        secret = json.loads(response["SecretString"])
        return secret["webhook_url"]
    except ClientError as e:
        logger.error("No se pudo obtener el webhook de Secrets Manager: %s", e)
        raise


def _build_slack_payload(event_data: dict, summary: str) -> dict:
    """
    Construye el payload JSON para la Slack Incoming Webhook API.

    Args:
        event_data: Diccionario con los campos del evento de honeypot.
            Campos esperados (todos opcionales con fallback):
                - honeypot_name  : nombre del honeypot activado
                - severity       : low | medium | high | critical
                - source_ip      : IP del actor
                - aws_user       : usuario/rol IAM involucrado
                - event_name     : nombre del evento de CloudTrail
                - event_time     : timestamp ISO del evento
        summary: Análisis en texto libre generado por el agente LLM.

    Returns:
        Dict listo para serializar como JSON y enviar a Slack.
    """
    severity = event_data.get("severity", "medium").lower()
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["medium"])
    emoji = SEVERITY_EMOJIS.get(severity, ":warning:")

    honeypot = event_data.get("honeypot_name", "desconocido")
    source_ip = event_data.get("source_ip", "N/A")
    aws_user = event_data.get("aws_user", "N/A")
    event_name = event_data.get("event_name", "N/A")
    event_time = event_data.get("event_time", datetime.now(timezone.utc).isoformat())

    return {
        "text": f"{emoji} *HoneyAgent — Alerta [{severity.upper()}]*",
        "attachments": [
            {
                "color": color,
                "fields": [
                    {"title": "Honeypot activado", "value": honeypot,    "short": True},
                    {"title": "Severidad",          "value": severity.upper(), "short": True},
                    {"title": "IP de origen",       "value": source_ip,  "short": True},
                    {"title": "Usuario/Rol AWS",    "value": aws_user,   "short": True},
                    {"title": "Evento CloudTrail",  "value": event_name, "short": True},
                    {"title": "Hora del evento",    "value": event_time, "short": True},
                ],
                "footer": "HoneyAgent · AWS Honeypot Framework",
                "footer_icon": "https://a.slack-edge.com/80588/img/services/outgoing-webhook_128.png",
            },
            {
                "color": color,
                "title": "Análisis del agente LLM",
                "text": summary,
                "mrkdwn_in": ["text"],
            },
        ],
    }


def send_slack_alert(event_data: dict, summary: str) -> bool:
    """
    Envía una alerta de seguridad al canal de Slack configurado.

    Args:
        event_data: Datos del evento de honeypot (ver _build_slack_payload).
        summary:    Análisis generado por el agente LLM.

    Returns:
        True si el mensaje fue enviado correctamente, False si hubo error.
    """
    try:
        webhook_url = _get_webhook_url()
    except Exception as e:
        logger.error("Imposible obtener webhook URL: %s", e)
        return False

    payload = _build_slack_payload(event_data, summary)

    try:
        response = requests.post(
            webhook_url,
            json=payload,
            timeout=10,
        )
        response.raise_for_status()
        logger.info("Alerta Slack enviada correctamente (HTTP %s).", response.status_code)
        return True
    except requests.RequestException as e:
        logger.error("Error al enviar alerta a Slack: %s", e)
        return False


# ── Test standalone ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    # Evento de prueba: simula acceso al bucket honeypot
    test_event = {
        "honeypot_name":  "hp-fake-credentials-bucket",
        "severity":       "high",
        "source_ip":      "203.0.113.42",
        "aws_user":       "arn:aws:iam::123456789:user/suspicious-user",
        "event_name":     "GetObject",
        "event_time":     datetime.now(timezone.utc).isoformat(),
    }

    test_summary = (
        "La IP 203.0.113.42 accedió al archivo `credentials/aws_keys_backup.csv` "
        "del bucket honeypot. Score de reputación AbuseIPDB: 87/100 (alta confianza maliciosa). "
        "El usuario IAM no tiene historial previo de acceso a S3. "
        "**Recomendación**: bloquear IP en WAF y revocar credenciales del usuario."
    )

    success = send_slack_alert(test_event, test_summary)
    print("✓ Alerta enviada." if success else "✗ Fallo al enviar alerta.")
