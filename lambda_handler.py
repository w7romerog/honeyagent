"""
lambda_handler.py
------------------
Entry point de AWS Lambda para HoneyAgent.

EventBridge invoca esta función cuando detecta actividad en un honeypot.
Su única responsabilidad es adaptar el evento de Lambda al formato
que espera HoneyAgent y devolver el resultado.

Decisión de diseño (SRP):
  Este módulo no contiene lógica de análisis. Solo:
    1. Recibe el evento de EventBridge/Lambda.
    2. Carga los secrets de AWS al entorno (para que el agente los use).
    3. Invoca al agente.
    4. Guarda el reporte en S3.
    5. Devuelve una respuesta HTTP-like a Lambda.
"""

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

# Configurar logging antes de importar el agente
log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def handler(event: dict, context) -> dict:
    """
    Entry point de Lambda. Invocado por EventBridge.

    Args:
        event:   Evento de EventBridge transformado por el input_transformer
                 de cloudtrail.tf. Campos: honeypot_name, event_name,
                 source_ip, aws_user, event_time, aws_region, severity.
        context: Contexto de Lambda (tiempo restante, request ID, etc.).

    Returns:
        Dict con statusCode y body (convenio Lambda → API Gateway, aunque
        esta Lambda no está detrás de API Gateway).
    """
    logger.info("Lambda invocada | request_id: %s | honeypot: %s",
                context.aws_request_id if context else "local",
                event.get("honeypot_name", "desconocido"))

    # 1. Cargar secrets de AWS Secrets Manager al entorno
    #    (solo en Lambda; en local se usa .env)
    if os.getenv("AWS_EXECUTION_ENV"):   # solo dentro de Lambda real
        _load_secrets_to_env()

    # 2. Importar el agente aquí para asegurarse de que los secrets
    #    ya están en el entorno cuando se inicializa el cliente de Anthropic
    from agent import create_agent
    from report_generator import generate_report

    # 3. Ejecutar el agente
    try:
        agent = create_agent()
        result = agent.run(event)
    except Exception as e:
        logger.exception("Error fatal en el agente: %s", e)
        return _response(500, {"error": str(e), "honeypot": event.get("honeypot_name")})

    # 4. Guardar el reporte en /tmp (único directorio escribible en Lambda)
    try:
        paths = generate_report(event, result, output_dir="/tmp/reports")
        _upload_report_to_s3(paths)
    except Exception as e:
        # El reporte es secundario; no fallamos si no se puede guardar
        logger.warning("No se pudo guardar el reporte: %s", e)

    logger.info("Análisis completado | iteraciones: %d | tools: %s",
                result.get("iterations", 0),
                [t["tool"] for t in result.get("tools_called", [])])

    return _response(200, {
        "honeypot":   event.get("honeypot_name"),
        "iterations": result.get("iterations"),
        "success":    result.get("success"),
    })


def _load_secrets_to_env() -> None:
    """
    Carga las API keys desde Secrets Manager al entorno de la Lambda.

    Se ejecuta una sola vez por instancia Lambda (warm start no repite esto
    si las variables ya están seteadas).
    """
    region = os.getenv("AWS_REGION_NAME", "us-east-1")
    client = boto3.client("secretsmanager", region_name=region)

    secrets_to_load = {
        "ANTHROPIC_API_KEY":  os.getenv("ANTHROPIC_SECRET_NAME", "honeyagent/anthropic/api-key"),
        "ABUSEIPDB_API_KEY":  os.getenv("ABUSEIPDB_SECRET_NAME", "honeyagent/abuseipdb/api-key"),
    }

    for env_var, secret_name in secrets_to_load.items():
        if os.getenv(env_var):
            continue  # ya está cargado (warm start)
        try:
            resp = client.get_secret_value(SecretId=secret_name)
            secret = json.loads(resp["SecretString"])
            # Cada secret tiene una clave distinta según main.tf
            value = secret.get("api_key") or secret.get("webhook_url", "")
            os.environ[env_var] = value
            logger.debug("Secret '%s' cargado correctamente.", secret_name)
        except ClientError as e:
            logger.error("No se pudo cargar el secret '%s': %s", secret_name, e)


def _upload_report_to_s3(paths: dict) -> None:
    """Sube el reporte JSON a S3 para persistencia."""
    bucket = os.getenv("REPORT_BUCKET")
    if not bucket:
        return

    s3 = boto3.client("s3")
    for fmt, local_path in paths.items():
        if not os.path.exists(local_path):
            continue
        s3_key = f"reports/{os.path.basename(local_path)}"
        s3.upload_file(local_path, bucket, s3_key)
        logger.info("Reporte subido a s3://%s/%s", bucket, s3_key)


def _response(status_code: int, body: dict) -> dict:
    return {
        "statusCode": status_code,
        "body":       json.dumps(body, ensure_ascii=False),
    }


# ── Test local ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    from datetime import datetime, timezone

    os.environ["HONEYAGENT_MOCK"] = "true"

    test_event = {
        "honeypot_name": "hp-fake-credentials-bucket",
        "event_name":    "GetObject",
        "source_ip":     "203.0.113.42",
        "aws_user":      "arn:aws:iam::123456789012:user/hp-admin-backup-user",
        "aws_username":  "hp-admin-backup-user",
        "event_time":    datetime.now(timezone.utc).isoformat(),
        "aws_region":    "us-east-1",
        "severity":      "high",
        "resources":     [],
    }

    # Simular el contexto de Lambda con un objeto mínimo
    class MockContext:
        aws_request_id = "local-test-001"

    result = handler(test_event, MockContext())
    print(json.dumps(result, indent=2, ensure_ascii=False))
