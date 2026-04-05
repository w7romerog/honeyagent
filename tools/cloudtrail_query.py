"""
tools/cloudtrail_query.py
--------------------------
Tool del agente: consulta CloudTrail para obtener el historial de eventos
de una IP de origen o usuario IAM.

Usa CloudTrail LookupEvents (no S3 + Athena): menor latencia y sin
infraestructura adicional. Límite: últimos 90 días, 50 eventos por llamada.
"""

import json
import logging
import os
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

from tools.base import HoneyTool

logger = logging.getLogger(__name__)


class CloudTrailQueryTool(HoneyTool):
    """Consulta el historial de eventos de CloudTrail por IP o usuario IAM."""

    @property
    def definition(self) -> dict:
        return {
            "name": "cloudtrail_query",
            "description": (
                "Consulta AWS CloudTrail para obtener el historial de eventos recientes "
                "asociados a una IP de origen o un usuario IAM. Útil para entender el "
                "patrón de comportamiento del actor antes y después del acceso al honeypot."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "source_ip": {
                        "type": "string",
                        "description": "Dirección IP de origen a buscar en CloudTrail.",
                    },
                    "username": {
                        "type": "string",
                        "description": "Nombre de usuario IAM cuyas acciones se quieren consultar.",
                    },
                    "hours_back": {
                        "type": "integer",
                        "description": "Ventana de tiempo hacia atrás en horas (default: 24).",
                        "default": 24,
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Máximo de eventos a devolver (default: 20).",
                        "default": 20,
                    },
                },
                "required": [],
            },
        }

    def execute(
        self,
        source_ip: str | None = None,
        username: str | None = None,
        hours_back: int = 24,
        max_results: int = 20,
    ) -> dict:
        """
        Busca eventos de CloudTrail filtrando por IP o usuario.

        Returns:
            Dict con 'events', 'total_found', 'query_params', 'error'.
        """
        if not source_ip and not username:
            return {"events": [], "total_found": 0, "query_params": {}, "error": "Se requiere source_ip o username"}

        if os.getenv("HONEYAGENT_MOCK", "false").lower() == "true":
            return self._mock_response(source_ip, username)

        region = os.getenv("AWS_REGION", "us-east-1")
        client = boto3.client("cloudtrail", region_name=region)

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)

        # LookupEvents acepta un solo atributo; priorizamos IP (más específica)
        if source_ip:
            lookup_attr = [{"AttributeKey": "SourceIPAddress", "AttributeValue": source_ip}]
        else:
            lookup_attr = [{"AttributeKey": "Username", "AttributeValue": username}]

        query_params = {
            "filter": "source_ip" if source_ip else "username",
            "value": source_ip or username,
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
        }

        try:
            response = client.lookup_events(
                LookupAttributes=lookup_attr,
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=min(max_results, 50),
            )
        except ClientError as e:
            logger.error("Error al consultar CloudTrail: %s", e)
            return {"events": [], "total_found": 0, "query_params": query_params, "error": str(e)}

        events = [self._simplify_event(e) for e in response.get("Events", [])]
        return {"events": events, "total_found": len(events), "query_params": query_params, "error": None}

    def _simplify_event(self, raw: dict) -> dict:
        detail = {}
        if "CloudTrailEvent" in raw:
            try:
                detail = json.loads(raw["CloudTrailEvent"])
            except json.JSONDecodeError:
                pass
        return {
            "event_time":   raw.get("EventTime", "").isoformat() if hasattr(raw.get("EventTime"), "isoformat") else str(raw.get("EventTime", "")),
            "event_name":   raw.get("EventName", ""),
            "event_source": raw.get("EventSource", ""),
            "username":     raw.get("Username", ""),
            "source_ip":    detail.get("sourceIPAddress", ""),
            "resources":    [r.get("ARN", "") for r in raw.get("Resources", [])],
            "error_code":   detail.get("errorCode"),
        }

    def _mock_response(self, source_ip: str | None, username: str | None) -> dict:
        return {
            "events": [
                {
                    "event_time":   "2024-01-15T03:20:00+00:00",
                    "event_name":   "ListBuckets",
                    "event_source": "s3.amazonaws.com",
                    "username":     username or "mock-user",
                    "source_ip":    source_ip or "203.0.113.42",
                    "resources":    [],
                    "error_code":   None,
                },
                {
                    "event_time":   "2024-01-15T03:22:11+00:00",
                    "event_name":   "GetObject",
                    "event_source": "s3.amazonaws.com",
                    "username":     username or "mock-user",
                    "source_ip":    source_ip or "203.0.113.42",
                    "resources":    ["arn:aws:s3:::hp-fake-credentials-bucket/credentials/aws_keys_backup.csv"],
                    "error_code":   None,
                },
            ],
            "total_found": 2,
            "query_params": {"filter": "mock", "value": source_ip or username},
            "error": None,
        }


# ── Test standalone ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    os.environ["HONEYAGENT_MOCK"] = "true"

    tool = CloudTrailQueryTool()
    result = tool.safe_execute(source_ip="203.0.113.42", hours_back=24)
    print(json.dumps(result, indent=2, ensure_ascii=False))
