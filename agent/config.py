"""Carga y valida el esquema de honeypots.yaml."""

from pathlib import Path

import yaml

VALID_HONEYPOT_TYPES = {"iam_identity", "s3_bucket", "secrets_manager", "rds_endpoint"}
REQUIRED_HONEYPOT_FIELDS = {"type", "name", "enabled"}

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "honeypots.yaml"


class ConfigValidationError(ValueError):
    """El contenido de honeypots.yaml no respeta el esquema esperado."""


def load_honeypots_config(path: str | Path = DEFAULT_CONFIG_PATH) -> dict:
    """Carga honeypots.yaml y valida su esquema. No filtra deshabilitados."""
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    for section in ("honeypots", "detection", "agent"):
        if section not in raw:
            raise ConfigValidationError(f"Falta la sección '{section}' en honeypots.yaml")

    for hp in raw["honeypots"]:
        missing = REQUIRED_HONEYPOT_FIELDS - hp.keys()
        if missing:
            raise ConfigValidationError(
                f"Honeypot '{hp.get('name', '?')}' no tiene los campos requeridos: {missing}"
            )
        if hp["type"] not in VALID_HONEYPOT_TYPES:
            raise ConfigValidationError(
                f"Tipo de honeypot inválido: '{hp['type']}' (válidos: {VALID_HONEYPOT_TYPES})"
            )

    return raw


def enabled_honeypots(config: dict) -> list[dict]:
    """Filtra los honeypots con enabled: true (en el MVP, solo iam_identity)."""
    return [hp for hp in config["honeypots"] if hp.get("enabled", False)]
