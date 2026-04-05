"""
tools/ip_reputation_lookup.py
------------------------------
Tool del agente: consulta la reputación de una IP en AbuseIPDB.

Score de 0 (limpia) a 100 (100% maliciosa). Free tier: 1000 checks/día.
"""

import json
import logging
import os

import requests

from tools.base import HoneyTool

logger = logging.getLogger(__name__)

ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2/check"
MALICIOUS_THRESHOLD = 25

CATEGORY_NAMES = {
    3: "Fraud Orders", 4: "DDoS Attack", 5: "FTP Brute-Force",
    6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam",
    12: "Blog Spam", 13: "VPN IP", 14: "Port Scan",
    15: "Hacking", 16: "SQL Injection", 17: "Spoofing",
    18: "Brute-Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH", 23: "IoT Targeted",
}


class IPReputationLookupTool(HoneyTool):
    """Consulta la reputación de una IP en AbuseIPDB."""

    @property
    def definition(self) -> dict:
        return {
            "name": "ip_reputation_lookup",
            "description": (
                "Consulta la reputación de una dirección IP en AbuseIPDB. "
                "Devuelve un score de 0 a 100 (mayor = más maliciosa), el país de origen, "
                "el ISP, y las categorías de abuso reportadas por la comunidad. "
                "Útil para determinar si el acceso al honeypot proviene de un actor malicioso conocido."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "ip_address": {
                        "type": "string",
                        "description": "Dirección IP a consultar (IPv4 o IPv6).",
                    },
                    "max_age_days": {
                        "type": "integer",
                        "description": "Ventana de tiempo para buscar reportes en días (default: 90).",
                        "default": 90,
                    },
                },
                "required": ["ip_address"],
            },
        }

    def execute(self, ip_address: str, max_age_days: int = 90) -> dict:
        """
        Consulta AbuseIPDB y retorna el perfil de reputación de la IP.

        Returns:
            Dict con 'abuse_score', 'is_malicious', 'verdict', 'country_code',
            'isp', 'categories', 'total_reports', 'last_reported', 'error'.
        """
        if os.getenv("HONEYAGENT_MOCK", "false").lower() == "true":
            return self._mock_response(ip_address)

        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if not api_key:
            return self._error_response(ip_address, "ABUSEIPDB_API_KEY no configurada.")

        try:
            response = requests.get(
                ABUSEIPDB_BASE_URL,
                headers={"Accept": "application/json", "Key": api_key},
                params={"ipAddress": ip_address, "maxAgeInDays": max_age_days, "verbose": ""},
                timeout=10,
            )
            response.raise_for_status()
        except requests.RequestException as e:
            logger.error("Error al consultar AbuseIPDB para %s: %s", ip_address, e)
            return self._error_response(ip_address, str(e))

        data = response.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)

        return {
            "ip_address":    data.get("ipAddress", ip_address),
            "abuse_score":   score,
            "is_malicious":  score >= MALICIOUS_THRESHOLD,
            "total_reports": data.get("totalReports", 0),
            "last_reported": data.get("lastReportedAt"),
            "country_code":  data.get("countryCode"),
            "isp":           data.get("isp"),
            "usage_type":    data.get("usageType"),
            "categories":    self._decode_categories(data.get("reports", [])),
            "verdict":       self._verdict(score),
            "error":         None,
        }

    def _verdict(self, score: int) -> str:
        if score == 0:
            return "LIMPIA"
        if score < MALICIOUS_THRESHOLD:
            return "SOSPECHOSA"
        return "MALICIOSA"

    def _decode_categories(self, reports: list) -> list[str]:
        seen, result = set(), []
        for report in reports:
            for cat_id in report.get("categories", []):
                if cat_id not in seen:
                    seen.add(cat_id)
                    result.append(CATEGORY_NAMES.get(cat_id, f"Categoría {cat_id}"))
        return result

    def _error_response(self, ip_address: str, error: str) -> dict:
        return {
            "ip_address": ip_address, "abuse_score": -1, "is_malicious": False,
            "total_reports": 0, "last_reported": None, "country_code": None,
            "isp": None, "usage_type": None, "categories": [],
            "verdict": "DESCONOCIDA", "error": error,
        }

    def _mock_response(self, ip_address: str) -> dict:
        return {
            "ip_address":    ip_address,
            "abuse_score":   87,
            "is_malicious":  True,
            "total_reports": 142,
            "last_reported": "2024-01-14T18:30:00+00:00",
            "country_code":  "CN",
            "isp":           "China Unicom",
            "usage_type":    "Data Center/Web Hosting/Transit",
            "categories":    ["Port Scan", "Brute-Force", "SSH", "Web App Attack"],
            "verdict":       "MALICIOSA",
            "error":         None,
        }


# ── Test standalone ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    os.environ["HONEYAGENT_MOCK"] = "true"

    tool = IPReputationLookupTool()
    result = tool.safe_execute(ip_address="203.0.113.42")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    print(f"\nVeredicto: {result['verdict']} (score: {result['abuse_score']}/100)")
