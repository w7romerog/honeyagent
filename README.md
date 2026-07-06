# HoneyAgent

Prototipo de honeypots en AWS con agente LLM para detección y respuesta a amenazas.

Trabajo Final de Carrera (Licenciatura en Gestión de Sistemas Informáticos, UAI),
sustento del Capítulo 4. Implementa de punta a punta un honeypot de identidad
(IAM); S3, Secrets Manager y RDS quedan documentados en `honeypots.yaml` con
`enabled: false`.

---

## Alcance

**Implementado:**
- Honeypot de identidad (IAM): usuario señuelo, permisos mínimos, credenciales
  de larga duración nunca usadas legítimamente.
- Pipeline de detección: CloudTrail → EventBridge → Lambda.
- Agente LLM (Claude vía Amazon Bedrock) con tool use (`lookup_ip_reputation`)
  y razonamiento explícito.
- Reportes en Markdown + JSON.
- `scripts/simulate_attack.py`: dispara el flujo completo.

**Documentado, no implementado:** honeypot S3, Secrets Manager, RDS (esquema
en `honeypots.yaml`, stubs en `infra/*.tf.disabled_stub`).

**Fuera de alcance:** GuardDuty, multi-nube, CI/CD productivo, dashboard/UI.

---

## Arquitectura

```
Atacante usa credenciales del honeypot de identidad
        │
        ▼
   CloudTrail  ──► EventBridge Rule (userIdentity == usuario señuelo)
                          │
                          ▼
                    Lambda (agent/lambda_handler.py)
                          │
                          ▼
              HoneyAgent (LLM, Claude vía Amazon Bedrock)
              ┌───────────┴───────────┐
              │   Tool use loop       │
              │  lookup_ip_reputation │  (ip-api.com, sin API key)
              └───────────┬───────────┘
                          │
                          ▼
              Reporte .md + .json en S3
        (reports/iam_identity/{yyyy}/{mm}/{dd}/{ts}_{identity}_{event_id}.*)
```

## Stack

- Python 3.12 + boto3
- Claude vía Amazon Bedrock (`us.anthropic.claude-sonnet-4-5-20250929-v1:0`),
  autenticado con credenciales/rol de IAM. Los modelos Haiku requieren
  completar un formulario de "intended use case" en la consola de Bedrock
  antes de poder invocarse.
- Terraform
- AWS: CloudTrail, EventBridge, Lambda, IAM, S3, Bedrock
- ip-api.com para enriquecimiento de IP (gratis, sin API key)

---

## Inicio rápido

### Requisitos

- Python 3.12+, Terraform 1.5+
- Cuenta AWS con acceso a Bedrock habilitado para Claude Sonnet 4.5

### 1. Instalar dependencias

```bash
git clone https://github.com/w7romerog/honeyagent.git
cd honeyagent
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Variables de entorno

```bash
cp .env.example .env
# completar con credenciales AWS
```

### 3. Probar el agente en local

```bash
# corre como módulo, no como script (agent/agent.py usa imports absolutos)
HONEYAGENT_MOCK=true python -m agent.agent
```

### 4. Desplegar infraestructura

```bash
./scripts/build_lambda_package.sh
cd infra
terraform init
terraform apply
```

### 5. Validar el flujo end-to-end

```bash
python scripts/simulate_attack.py
```

Usa las credenciales del usuario IAM señuelo para invocar `sts:GetCallerIdentity`,
disparando CloudTrail → EventBridge → Lambda → agente. CloudTrail puede tardar
10-15 minutos en propagar el evento.

### 6. Tests

```bash
python -m pytest tests/ -v -m unit          # sin AWS
python -m pytest tests/ -v -m integration   # requiere acceso a Bedrock
```

---

## Estructura

```
honeyagent/
├── honeypots.yaml              # honeypots, detection, agent
├── infra/                      # Terraform
│   ├── main.tf
│   ├── iam_identity.tf         # único tipo implementado
│   ├── s3_bucket.tf.disabled_stub
│   ├── secrets_manager.tf.disabled_stub
│   ├── rds_endpoint.tf.disabled_stub
│   ├── eventbridge.tf
│   ├── cloudtrail.tf
│   ├── lambda.tf
│   └── variables.tf
├── agent/
│   ├── agent.py                 # loop de tool use
│   ├── lambda_handler.py        # entry point de Lambda
│   ├── report_generator.py      # reportes Markdown + JSON
│   ├── config.py                # validador de honeypots.yaml
│   └── tools/
│       ├── base.py
│       ├── registry.py
│       └── lookup_ip_reputation.py
├── scripts/
│   ├── build_lambda_package.sh
│   └── simulate_attack.py
├── reports/                     # salida local, no versionada
└── tests/
    └── test_agent.py
```

## Diseño

| Principio | Aplicación |
|-----------|-----------|
| Single Responsibility | `HoneyAgent` orquesta, `HoneyTool` ejecuta, `ToolRegistry` administra |
| Open/Closed | Agregar tools no requiere modificar `agent.py` |
| Liskov Substitution | Cualquier `HoneyTool` es intercambiable |
| Interface Segregation | Interfaz mínima: `execute()` + `definition` |
| Dependency Inversion | `HoneyAgent` depende de `ToolRegistry`, no de tools concretas |

El razonamiento del agente queda textual en el reporte (sin resumir), para
poder evaluarse contra PCI DSS v4.0.1 y la Comunicación "A" 8398 del BCRA. El
prototipo no implementa controles de esos marcos, solo documenta con el nivel
de detalle que un auditor esperaría encontrar.

### Seguridad

- Sin API keys de terceros: el agente usa Bedrock con credenciales/rol de IAM
- `.env` excluido del repositorio
- IAM de mínimo privilegio (honeypot de solo lectura; la Lambda solo puede
  invocar Bedrock y escribir en el prefijo de reportes de S3)
- Inputs validados en `HoneyTool.safe_execute()`

`agent/agent.py` carga `.env` al importarse (`python-dotenv`). Con
credenciales reales en `.env`, cualquier código que importe `agent.agent`
—incluidos tests— puede leerlas sin exportarlas a mano; los tests mockean
la subida a S3 por este motivo.

---

## Licencia

MIT — ver [LICENSE](LICENSE)
