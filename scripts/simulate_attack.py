"""
scripts/simulate_attack.py
----------------------------
Script de validación end-to-end del MVP (Cap. 4, paso 6 del plan de ejecución).

Simula el escenario de ataque más simple posible sobre el honeypot de
identidad: usa las credenciales señuelo (de larga duración, generadas por
Terraform pero nunca usadas legítimamente) para invocar una API de AWS que no
requiere ningún permiso adicional (`sts:GetCallerIdentity`).

Esa sola llamada, hecha con las credenciales del usuario IAM señuelo, debería
disparar el pipeline completo:

    CloudTrail registra el evento
        -> EventBridge lo enruta a la Lambda (infra/eventbridge.tf)
            -> la Lambda invoca al agente (agent/lambda_handler.py)
                -> el agente razona y opcionalmente llama a lookup_ip_reputation
                    -> se persisten reports/iam_identity/.../*.md y *.json en S3

Requiere credenciales del operador (con permiso para leer el secret) ya
configuradas en el entorno (perfil de AWS CLI, variables de entorno, etc.).
No requiere ANTHROPIC_API_KEY ni HONEYAGENT_MOCK: esas variables las usa la
Lambda, no este script.

Uso:
    python scripts/simulate_attack.py
    python scripts/simulate_attack.py --honeypot hp-billing-readonly --action list-buckets
"""

import argparse
import json
import sys

import boto3
from botocore.exceptions import ClientError

DEFAULT_PROJECT_NAME = "honeyagent"
DEFAULT_HONEYPOT = "hp-billing-readonly"


def load_decoy_credentials(project_name: str, honeypot_name: str, region: str) -> dict:
    """Lee las credenciales señuelo desde Secrets Manager (creadas por infra/iam_identity.tf)."""
    secret_name = f"{project_name}/honeypot/{honeypot_name}-keys"
    client = boto3.client("secretsmanager", region_name=region)

    try:
        response = client.get_secret_value(SecretId=secret_name)
    except ClientError as e:
        print(f"No se pudo leer el secret '{secret_name}': {e}", file=sys.stderr)
        print("¿Se corrió `terraform apply` en infra/ con el honeypot habilitado?", file=sys.stderr)
        sys.exit(1)

    return json.loads(response["SecretString"])


def run_decoy_action(credentials: dict, region: str, action: str) -> dict:
    """Arma una sesión de boto3 con las credenciales señuelo e invoca la API elegida."""
    session = boto3.Session(
        aws_access_key_id=credentials["access_key_id"],
        aws_secret_access_key=credentials["secret_access_key"],
        region_name=region,
    )

    if action == "get-caller-identity":
        return session.client("sts").get_caller_identity()
    if action == "list-buckets":
        return session.client("s3").list_buckets()

    raise ValueError(f"Acción desconocida: {action}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-name", default=DEFAULT_PROJECT_NAME)
    parser.add_argument("--honeypot", default=DEFAULT_HONEYPOT)
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument(
        "--action",
        choices=["get-caller-identity", "list-buckets"],
        default="get-caller-identity",
    )
    args = parser.parse_args()

    print(f"[simulate_attack] Leyendo credenciales señuelo de '{args.honeypot}'...")
    credentials = load_decoy_credentials(args.project_name, args.honeypot, args.region)
    print(f"[simulate_attack] Usuario señuelo: {credentials['username']}")

    print(f"[simulate_attack] Invocando '{args.action}' con las credenciales señuelo...")
    try:
        result = run_decoy_action(credentials, args.region, args.action)
    except ClientError as e:
        # Con ReadOnlyAccess, la mayoría de las llamadas de solo lectura funcionan.
        # Si la API elegida requiere un permiso no incluido, igual queda el intento
        # registrado en CloudTrail (lo que dispara el pipeline).
        print(f"[simulate_attack] La llamada falló (esperable con permisos mínimos): {e}")
        result = {"error": str(e)}

    print(json.dumps(result, indent=2, default=str))
    print(
        "\n[simulate_attack] Listo. Revisá el bucket de reportes en unos segundos "
        "(CloudTrail -> EventBridge -> Lambda -> agente puede tardar ~1 minuto)."
    )


if __name__ == "__main__":
    main()
