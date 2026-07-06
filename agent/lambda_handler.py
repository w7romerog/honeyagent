"""
agent/lambda_handler.py
-------------------------
Entry point de AWS Lambda para HoneyAgent.

EventBridge invoca esta función cuando CloudTrail registra actividad con las
credenciales del honeypot de identidad (IAM). Responsabilidades (SRP):

    1. Recibir el evento ya filtrado por EventBridge.
    2. Traducirlo a un resumen estructurado (identidad invocadora, operación,
       servicio, parámetros relevantes, IP de origen, momento, resultado).
    3. Invocar al agente (agent/agent.py).
    4. Persistir los reportes .md y .json en el bucket S3 de reportes, con la
       convención de nombre de agent/report_generator.py.
"""

import json
import logging
import os

import boto3

log_level = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=getattr(logging, log_level, logging.INFO),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def summarize_event(eventbridge_event: dict) -> tuple[dict, dict]:
    """
    Traduce el evento de EventBridge (detalle de CloudTrail) a un resumen
    estructurado que consume el agente.

    Args:
        eventbridge_event: Evento entregado a la Lambda. Puede venir ya
            resumido por el input_transformer de infra/eventbridge.tf, o con
            el detalle crudo de CloudTrail bajo la clave "detail".

    Returns:
        Tupla (resumen_estructurado, evento_crudo_cloudtrail).
    """
    detail = eventbridge_event.get("detail", eventbridge_event)

    summary = {
        "honeypot_name": eventbridge_event.get("honeypot_name", "hp-billing-readonly"),
        "event_source":  detail.get("eventSource", eventbridge_event.get("event_source", "desconocido")),
        "event_name":    detail.get("eventName", eventbridge_event.get("event_name", "desconocido")),
        "source_ip":     detail.get("sourceIPAddress", eventbridge_event.get("source_ip", "desconocida")),
        "aws_identity":  detail.get("userIdentity", {}).get("arn", eventbridge_event.get("aws_identity", "desconocida")),
        "event_time":    detail.get("eventTime", eventbridge_event.get("event_time")),
        "aws_region":    detail.get("awsRegion", eventbridge_event.get("aws_region", "us-east-1")),
        "parameters":    detail.get("requestParameters") or eventbridge_event.get("parameters") or {},
        "result":        "error" if detail.get("errorCode") else "success",
    }
    return summary, detail


def handler(event: dict, context) -> dict:
    """
    Entry point de Lambda. Invocado por EventBridge.

    Returns:
        Dict con statusCode y body.
    """
    logger.info(
        "Lambda invocada | request_id: %s",
        context.aws_request_id if context else "local",
    )

    # El agente usa Amazon Bedrock (agent/agent.py): no hace falta cargar ningún
    # secret al entorno, las credenciales las resuelve el rol de ejecución de
    # la Lambda (infra/lambda.tf le da permiso bedrock:InvokeModel).
    from agent.agent import create_agent
    from agent.report_generator import generate_report

    event_summary, raw_event = summarize_event(event)

    try:
        agent = create_agent()
        result = agent.run(event_summary)
    except Exception as e:
        logger.exception("Error fatal en el agente: %s", e)
        return _response(500, {"error": str(e), "honeypot": event_summary.get("honeypot_name")})

    try:
        paths = generate_report(event_summary, result, raw_event=raw_event, output_dir="/tmp/reports")
        _upload_reports_to_s3(paths)
    except Exception as e:
        # El reporte es secundario; no fallamos la invocación si no se puede guardar
        logger.warning("No se pudo guardar el reporte: %s", e)

    logger.info(
        "Análisis completado | iteraciones: %d | tools: %s",
        result.get("iterations", 0),
        [t["tool"] for t in result.get("tools_called", [])],
    )

    return _response(200, {
        "honeypot":   event_summary.get("honeypot_name"),
        "iterations": result.get("iterations"),
        "success":    result.get("success"),
    })


def _upload_reports_to_s3(paths: dict) -> None:
    """Sube los reportes .md/.json a S3 usando la convención de nombres de report_generator."""
    bucket = os.getenv("REPORT_BUCKET")
    if not bucket:
        return

    s3 = boto3.client("s3")
    key_prefix = paths["key_prefix"]
    for fmt in ("markdown", "json"):
        local_path = paths[fmt]
        ext = "md" if fmt == "markdown" else "json"
        s3_key = f"{key_prefix}.{ext}"
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
        "detail": {
            "eventSource":    "sts.amazonaws.com",
            "eventName":      "GetCallerIdentity",
            "sourceIPAddress": "203.0.113.42",
            "userIdentity":   {"arn": "arn:aws:iam::123456789012:user/billing-readonly"},
            "eventTime":      datetime.now(timezone.utc).isoformat(),
            "awsRegion":      "us-east-1",
            "requestParameters": {},
        },
        "honeypot_name": "hp-billing-readonly",
    }

    class MockContext:
        aws_request_id = "local-test-001"

    result = handler(test_event, MockContext())
    print(json.dumps(result, indent=2, ensure_ascii=False))
