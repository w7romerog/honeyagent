"""
agent/tools/lookup_ip_reputation.py
-------------------------------------
Tool del agente: consulta geolocalización/reputación pública de una IP.

Elección de proveedor (decisión no fijada por el TFC, resuelta según la
instrucción de tomar la opción más simple que no requiera credenciales
adicionales): ip-api.com. Es una API gratuita, sin API key, sin registro,
que expone país, proveedor (ISP) y organización asociada al rango de IP —
suficiente para el enriquecimiento que describe el Cap. 4 (no expone un
score de abuso como AbuseIPDB, que sí requiere key).
"""

import json
import logging
import os

import requests

from agent.tools.base import HoneyTool

logger = logging.getLogger(__name__)

IP_API_BASE_URL = "http://ip-api.com/json/{ip}"
IP_API_FIELDS = "status,message,country,countryCode,isp,org,as,query"


class LookupIPReputationTool(HoneyTool):
    """Consulta geolocalización y proveedor de una IP en ip-api.com (sin API key)."""

    @property
    def definition(self) -> dict:
        return {
            "name": "lookup_ip_reputation",
            "description": (
                "Consulta información pública de geolocalización y reputación de una "
                "dirección IP (país, proveedor/ISP, organización asociada al rango). "
                "Útil para determinar el origen de un acceso al honeypot de identidad "
                "y si es compatible con el uso legítimo esperado de esas credenciales."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "ip": {
                        "type": "string",
                        "description": "Dirección IP a consultar (IPv4 o IPv6).",
                    },
                },
                "required": ["ip"],
            },
        }

    def execute(self, ip: str) -> dict:
        """
        Consulta ip-api.com y retorna país, ISP y organización de la IP.

        Returns:
            Dict con 'ip', 'country', 'country_code', 'isp', 'org', 'as', 'error'.
        """
        if os.getenv("HONEYAGENT_MOCK", "false").lower() == "true":
            return self._mock_response(ip)

        try:
            response = requests.get(
                IP_API_BASE_URL.format(ip=ip),
                params={"fields": IP_API_FIELDS},
                timeout=10,
            )
            response.raise_for_status()
        except requests.RequestException as e:
            logger.error("Error al consultar ip-api.com para %s: %s", ip, e)
            return self._error_response(ip, str(e))

        data = response.json()
        if data.get("status") != "success":
            return self._error_response(ip, data.get("message", "consulta fallida"))

        return {
            "ip":           data.get("query", ip),
            "country":      data.get("country"),
            "country_code": data.get("countryCode"),
            "isp":          data.get("isp"),
            "org":          data.get("org"),
            "as":           data.get("as"),
            "error":        None,
        }

    def _error_response(self, ip: str, error: str) -> dict:
        return {
            "ip": ip, "country": None, "country_code": None,
            "isp": None, "org": None, "as": None, "error": error,
        }

    def _mock_response(self, ip: str) -> dict:
        return {
            "ip":           ip,
            "country":      "China",
            "country_code": "CN",
            "isp":          "China Unicom",
            "org":          "China Unicom Beijing Province Network",
            "as":           "AS4837 CHINA UNICOM China169 Backbone",
            "error":        None,
        }


# ── Test standalone ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    os.environ["HONEYAGENT_MOCK"] = "true"

    tool = LookupIPReputationTool()
    result = tool.safe_execute(ip="203.0.113.42")
    print(json.dumps(result, indent=2, ensure_ascii=False))
