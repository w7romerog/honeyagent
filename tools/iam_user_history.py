"""
tools/iam_user_history.py
--------------------------
Tool del agente: obtiene el perfil de riesgo de un usuario IAM.

Consulta: metadatos del usuario, políticas adjuntas, y estado de access keys.
Genera señales de riesgo automáticas para orientar el análisis del agente.
"""

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

from tools.base import HoneyTool

logger = logging.getLogger(__name__)


class IAMUserHistoryTool(HoneyTool):
    """Obtiene el perfil de seguridad de un usuario IAM."""

    @property
    def definition(self) -> dict:
        return {
            "name": "iam_user_history",
            "description": (
                "Obtiene el perfil de seguridad de un usuario IAM: metadatos, políticas "
                "adjuntas, estado de sus access keys y señales de riesgo automáticas. "
                "Útil para determinar si el usuario involucrado es un honeypot "
                "o una cuenta legítima comprometida."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Nombre del usuario IAM a consultar (sin ARN, solo el nombre).",
                    }
                },
                "required": ["username"],
            },
        }

    def execute(self, username: str) -> dict:
        """
        Devuelve el perfil de seguridad de un usuario IAM.

        Returns:
            Dict con 'user_info', 'policies', 'access_keys', 'risk_signals', 'error'.
        """
        if os.getenv("HONEYAGENT_MOCK", "false").lower() == "true":
            return self._mock_response(username)

        region = os.getenv("AWS_REGION", "us-east-1")
        iam = boto3.client("iam", region_name=region)

        try:
            user = iam.get_user(UserName=username)["User"]
        except ClientError as e:
            logger.error("No se encontró el usuario IAM '%s': %s", username, e)
            return {"user_info": {}, "policies": [], "access_keys": [], "risk_signals": [], "error": str(e)}

        user_info = {
            "username":           user.get("UserName"),
            "arn":                user.get("Arn"),
            "created_at":         self._fmt_date(user.get("CreateDate")),
            "last_console_login": self._fmt_date(user.get("PasswordLastUsed")),
            "tags":               {t["Key"]: t["Value"] for t in user.get("Tags", [])},
        }

        policies = self._get_policies(iam, username)
        access_keys = self._get_access_keys(iam, username)
        risk_signals = self._detect_risk_signals(user_info, access_keys)

        return {
            "user_info":    user_info,
            "policies":     policies,
            "access_keys":  access_keys,
            "risk_signals": risk_signals,
            "error":        None,
        }

    def _get_policies(self, iam, username: str) -> list:
        policies = []
        try:
            for p in iam.list_attached_user_policies(UserName=username).get("AttachedPolicies", []):
                policies.append({"type": "managed", "name": p["PolicyName"], "arn": p["PolicyArn"]})
            for name in iam.list_user_policies(UserName=username).get("PolicyNames", []):
                policies.append({"type": "inline", "name": name, "arn": None})
        except ClientError as e:
            logger.warning("No se pudieron obtener políticas de '%s': %s", username, e)
        return policies

    def _get_access_keys(self, iam, username: str) -> list:
        access_keys = []
        try:
            for key_meta in iam.list_access_keys(UserName=username).get("AccessKeyMetadata", []):
                key_id = key_meta["AccessKeyId"]
                last_used = iam.get_access_key_last_used(AccessKeyId=key_id).get("AccessKeyLastUsed", {})
                access_keys.append({
                    "key_id":       key_id,
                    "status":       key_meta.get("Status"),
                    "created_at":   self._fmt_date(key_meta.get("CreateDate")),
                    "last_used_at": self._fmt_date(last_used.get("LastUsedDate")),
                    "last_service": last_used.get("ServiceName"),
                    "last_region":  last_used.get("Region"),
                })
        except ClientError as e:
            logger.warning("No se pudieron obtener access keys de '%s': %s", username, e)
        return access_keys

    def _detect_risk_signals(self, user_info: dict, access_keys: list) -> list[str]:
        signals = []
        if user_info.get("tags", {}).get("HoneyAgent") == "true":
            signals.append("HONEYPOT: Este usuario es una trampa; cualquier actividad es sospechosa.")
        for key in access_keys:
            if key["status"] == "Active" and key["last_used_at"] and key["last_used_at"] != "Nunca":
                signals.append(f"Access key {key['key_id']} fue usada recientemente (último uso: {key['last_used_at']}).")
        active_keys = [k for k in access_keys if k["status"] == "Active"]
        if len(active_keys) > 1:
            signals.append(f"El usuario tiene {len(active_keys)} access keys activas (máximo recomendado: 1).")
        return signals

    def _fmt_date(self, dt) -> str:
        if dt is None:
            return "Nunca"
        return dt.isoformat() if hasattr(dt, "isoformat") else str(dt)

    def _mock_response(self, username: str) -> dict:
        return {
            "user_info": {
                "username":           username,
                "arn":                f"arn:aws:iam::123456789012:user/{username}",
                "created_at":         "2024-01-01T00:00:00+00:00",
                "last_console_login": "Nunca",
                "tags":               {"HoneyAgent": "true", "Purpose": "honeypot"},
            },
            "policies": [
                {"type": "managed", "name": "ReadOnlyAccess", "arn": "arn:aws:iam::aws:policy/ReadOnlyAccess"}
            ],
            "access_keys": [
                {
                    "key_id":       "AKIAIOSFODNN7EXAMPLE",
                    "status":       "Active",
                    "created_at":   "2024-01-01T00:00:00+00:00",
                    "last_used_at": "2024-01-15T03:22:00+00:00",
                    "last_service": "s3",
                    "last_region":  "us-east-1",
                }
            ],
            "risk_signals": [
                "HONEYPOT: Este usuario es una trampa; cualquier actividad es sospechosa.",
                "Access key AKIAIOSFODNN7EXAMPLE fue usada recientemente (último uso: 2024-01-15T03:22:00+00:00).",
            ],
            "error": None,
        }


# ── Test standalone ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    os.environ["HONEYAGENT_MOCK"] = "true"

    tool = IAMUserHistoryTool()
    result = tool.safe_execute(username="hp-admin-backup-user")
    print(json.dumps(result, indent=2, ensure_ascii=False))
