# HoneyAgent

**Framework de honeypots en AWS con agente LLM para detección y respuesta automatizada a amenazas.**

Trabajo de tesis de licenciatura — implementación de un sistema de honeypots declarativo sobre AWS, integrado con un agente de inteligencia artificial (Claude API) que analiza eventos de seguridad en tiempo real, investiga el contexto del atacante y genera alertas automáticas.

---

## Arquitectura

```
Atacante accede a honeypot
        │
        ▼
   CloudTrail  ──► EventBridge Rule
                          │
                          ▼
                    Lambda (trigger)
                          │
                          ▼
                   HoneyAgent (LLM)
              ┌───────────┴───────────┐
              │   Tool use loop       │
              │  ┌─────────────────┐  │
              │  │ cloudtrail_query│  │
              │  │ iam_user_history│  │
              │  │ ip_reputation   │  │
              │  │ send_alert      │  │
              │  └─────────────────┘  │
              └───────────┬───────────┘
                          │
              ┌───────────┴───────────┐
              ▼                       ▼
        Slack alert            Reporte PDF/JSON
```

## Honeypots incluidos

| Honeypot | Tipo | Severidad | Qué detecta |
|----------|------|-----------|-------------|
| `hp-fake-credentials-bucket` | S3 Bucket | High | Exfiltración de datos, credential harvesting |
| `hp-admin-backup-user` | IAM User | Critical | Uso de credenciales comprometidas |
| `hp-prod-db-password` | Secrets Manager | High | Acceso post-compromiso a secretos |
| `hp-cloudtrail-tampering` | Monitor | Critical | Intentos de evasión (borrar logs) |

## Stack tecnológico

- **Python 3.12** + boto3
- **Claude API** (Anthropic) con tool use / function calling
- **Terraform** para infraestructura AWS
- **AWS**: CloudTrail, EventBridge, Lambda, S3, IAM, Secrets Manager
- **AbuseIPDB** para IP reputation lookup
- **Slack** webhooks para alertas

---

## Inicio rápido

### Requisitos previos

- Python 3.12+
- Terraform 1.5+
- Cuenta AWS (free tier)
- API key de [Anthropic](https://console.anthropic.com/)
- API key de [AbuseIPDB](https://www.abuseipdb.com/register) (free tier)
- Slack Incoming Webhook

### 1. Clonar e instalar dependencias

```bash
git clone https://github.com/w7romerog/honeyagent.git
cd honeyagent
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configurar variables de entorno

```bash
cp .env.example .env
# Editar .env con tus API keys
```

### 3. Probar el agente en local (sin AWS)

```bash
HONEYAGENT_MOCK=true python agent.py
```

### 4. Desplegar infraestructura en AWS

```bash
cd terraform
terraform init
terraform apply \
  -var="slack_webhook_url=https://hooks.slack.com/..." \
  -var="anthropic_api_key=sk-ant-..." \
  -var="abuseipdb_api_key=..."
```

### 5. Correr los tests

```bash
# Tests unitarios (sin AWS ni APIs externas)
HONEYAGENT_MOCK=true python -m pytest tests/ -v -m unit

# Tests de integración (requiere ANTHROPIC_API_KEY configurada)
HONEYAGENT_MOCK=true python -m pytest tests/ -v -m integration
```

---

## Estructura del proyecto

```
honeyagent/
├── honeypots.yaml          # Configuración declarativa de honeypots
├── agent.py                # Agente LLM central (tool use loop)
├── lambda_handler.py       # Entry point de AWS Lambda
├── slack_notifier.py       # Notificaciones Slack
├── report_generator.py     # Generador de reportes PDF/JSON
├── tools/
│   ├── base.py             # Interfaz abstracta HoneyTool (SOLID)
│   ├── registry.py         # ToolRegistry — Open/Closed + DI
│   ├── cloudtrail_query.py # Consulta historial de CloudTrail
│   ├── iam_user_history.py # Perfil de riesgo de usuarios IAM
│   ├── ip_reputation_lookup.py  # Reputación de IPs (AbuseIPDB)
│   └── send_alert.py       # Envío de alertas
├── terraform/
│   ├── main.tf             # Provider, S3 logs, Secrets Manager
│   ├── honeypots.tf        # Recursos honeypot (S3, IAM, SM)
│   ├── cloudtrail.tf       # Trail + EventBridge rules
│   ├── lambda.tf           # Lambda + IAM role
│   └── variables.tf
└── tests/
    ├── test_agent.py       # 20 tests unitarios e integración
    └── mock_events/        # Eventos de prueba por tipo de honeypot
```

## Principios de diseño

### SOLID

| Principio | Aplicación |
|-----------|-----------|
| **S** Single Responsibility | Cada clase tiene una responsabilidad: `HoneyAgent` orquesta, `HoneyTool` ejecuta, `ToolRegistry` administra |
| **O** Open/Closed | Agregar una nueva tool no requiere modificar `agent.py`; solo crear la clase y registrarla |
| **L** Liskov Substitution | Cualquier `HoneyTool` es intercambiable en el agente |
| **I** Interface Segregation | Interfaz mínima: `execute()` + `definition` |
| **D** Dependency Inversion | `HoneyAgent` depende de `ToolRegistry` (abstracción), no de tools concretas |

### Seguridad

- Credenciales siempre en AWS Secrets Manager o variables de entorno, nunca en código
- `.env` excluido del repositorio (solo `.env.example` se versiona)
- Terraform state local (sensible — no commitear)
- IAM con principio de mínimo privilegio
- Inputs validados en `HoneyTool.safe_execute()` antes de ejecutar

---

## Costos estimados (AWS Free Tier)

| Servicio | Uso estimado | Costo |
|----------|-------------|-------|
| CloudTrail | 1 trail (primero gratis) | $0 |
| Lambda | < 1M invocaciones/mes | $0 |
| S3 | < 5 GB | $0 |
| Secrets Manager | 4 secrets × $0.40/mes | ~$1.60/mes |
| CloudWatch Logs | < 5 GB/mes | $0 |

> **Nota**: Activar un billing alert en $5 antes de desplegar.

---

## Licencia

MIT — ver [LICENSE](LICENSE)
