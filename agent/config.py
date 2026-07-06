"""
agent/config.py
-----------------
Carga y valida honeypots.yaml.

El TFC (Cap. 4) define 4 tipos de honeypot posibles; el MVP implementa uno solo
(iam_identity) y documenta los otros tres con `enabled: false`. Este módulo valida
que el esquema esté completo (incluso para los tipos deshabilitados) y expone
solo los honeypots activos al resto del sistema (infra los lee vía Terraform
`yamldecode`; el agente/lambda_handler los lee vía este módulo).
"""

from pathlib import Path

import yaml

VALID_HONEYPOT_TYPES = {"iam_identity", "s3_bucket", "secrets_manager", "rds_endpoint"}
REQUIRED_HONEYPOT_FIELDS = {"type", "name", "enabled"}

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "honeypots.yaml"


class ConfigValidationError(ValueError):
    """El contenido de honeypots.yaml no respeta el esquema esperado."""


def load_honeypots_config(path: str | Path = DEFAULT_CONFIG_PATH) -> dict:
    """
    Carga honeypots.yaml y valida su esquema.

    Returns:
        Dict con las claves 'honeypots', 'detection', 'agent' tal como están
        en el YAML (sin filtrar deshabilitados — usar `enabled_honeypots` para eso).

    Raises:
        ConfigValidationError: si falta alguna sección o un honeypot no cumple
        el esquema mínimo.
    """
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
