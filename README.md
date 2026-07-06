# HoneyAgent

**Prototipo MVP de un framework de honeypots en AWS con agente LLM para detección y
respuesta a amenazas.**

Trabajo Final de Carrera (Licenciatura en Gestión de Sistemas Informáticos, UAI) —
sustento empírico del Capítulo 4 (Propuesta de Intervención). Este prototipo implementa
de punta a punta **un único tipo de señuelo — el honeypot de identidad (IAM)** — y
documenta los tres restantes (S3, Secrets Manager, RDS) como entradas deshabilitadas en
`honeypots.yaml`, mostrando cómo se extendería el patrón sin alterar el pipeline de
detección ni el agente.

---

## Alcance del MVP

**Implementado de punta a punta:**
- Honeypot de identidad (IAM): usuario señuelo con permisos mínimos y credenciales de
  larga duración nunca usadas legítimamente.
- Pipeline de detección: CloudTrail → EventBridge → Lambda.
- Agente LLM (Claude, vía Amazon Bedrock) con tool use, una sola herramienta
  (`lookup_ip_reputation`), y razonamiento explícito y trazable.
- Reportes en Markdown (lectura humana) + JSON (integración/trazabilidad).
- `scripts/simulate_attack.py`: dispara el flujo completo usando las credenciales
  señuelo.

**Documentado, no implementado** (esquema completo en `honeypots.yaml`, stubs de
Terraform en `infra/*.tf.disabled_stub`, `enabled: false`):
- Honeypot S3, Secrets Manager, RDS.

**Fuera de alcance** (no implementado): Amazon GuardDuty (capa complementaria del
pipeline, descrita en paralelo por el TFC), multi-nube, CI/CD productivo, dashboard/UI.

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

## Stack tecnológico

- **Python 3.12** + boto3
- **Claude (Amazon Bedrock)** con tool use / function calling — modelo Claude Sonnet 4.5
  (`us.anthropic.claude-sonnet-4-5-20250929-v1:0`). Los modelos Haiku son más
  económicos pero requieren completar un formulario de "intended use case" en la
  consola de Bedrock (Model access) antes de poder invocarse; Sonnet 4.5 funciona
  sin ese trámite y su costo es marginal para el volumen de este MVP. Se accede vía
  `AnthropicBedrock` (SDK de Anthropic), autenticando con credenciales/rol de IAM —
  sin API key ni cuenta separada de Anthropic.
- **Terraform** para infraestructura AWS (elegido sobre CDK por simplicidad de setup)
- **AWS**: CloudTrail, EventBridge, Lambda, IAM, S3, Bedrock
- **ip-api.com** para enriquecimiento de IP (gratis, sin API key)

---

## Inicio rápido

### Requisitos previos

- Python 3.12+
- Terraform 1.5+
- Cuenta AWS con acceso a Amazon Bedrock habilitado para Claude Sonnet 4.5 en la
  región elegida (Model access en la consola de Bedrock)

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
# Editar .env con tus credenciales AWS (el agente usa Bedrock, no hay API key de Anthropic)
```

### 3. Probar el agente en local (sin AWS)

```bash
# Se ejecuta como módulo (python -m), no como script, porque agent/agent.py
# vive dentro del paquete agent/ y usa imports absolutos (agent.tools....).
HONEYAGENT_MOCK=true python -m agent.agent
```

### 4. Desplegar infraestructura en AWS

```bash
./scripts/build_lambda_package.sh    # empaqueta agent/ + dependencias (incluye el SDK de Anthropic, para AnthropicBedrock)

cd infra
terraform init
terraform apply
```

### 5. Validar el flujo end-to-end

```bash
python scripts/simulate_attack.py
```

Esto usa las credenciales del usuario IAM señuelo para invocar `sts:GetCallerIdentity`,
lo que dispara CloudTrail → EventBridge → Lambda → agente, y termina en un reporte
`.md`/`.json` en el bucket de reportes. **CloudTrail no es instantáneo**: en las
pruebas reales contra una cuenta AWS, el evento tardó entre 10 y 15 minutos en
propagarse hasta la Lambda — no esperes verlo en el bucket enseguida.

### 6. Correr los tests

```bash
# Tests unitarios (sin AWS ni APIs externas)
python -m pytest tests/ -v -m unit

# Tests de integración (requiere credenciales AWS con acceso a Bedrock)
python -m pytest tests/ -v -m integration
```

---

## Estructura del proyecto

```
honeyagent/
├── honeypots.yaml              # Configuración declarativa: honeypots, detection, agent
├── infra/                      # Terraform
│   ├── main.tf                 # Provider, lectura de honeypots.yaml, bucket de reportes
│   ├── iam_identity.tf         # Honeypot de identidad (único tipo implementado)
│   ├── s3_bucket.tf.disabled_stub
│   ├── secrets_manager.tf.disabled_stub
│   ├── rds_endpoint.tf.disabled_stub
│   ├── eventbridge.tf
│   ├── cloudtrail.tf
│   ├── lambda.tf
│   └── variables.tf
├── agent/
│   ├── agent.py                 # HoneyAgent: system prompt (PCI DSS/BCRA) + loop de tool use
│   ├── lambda_handler.py        # Entry point de Lambda: traduce evento, invoca agente, persiste reportes
│   ├── report_generator.py      # Reportes Markdown + JSON
│   ├── config.py                # Carga y valida honeypots.yaml
│   └── tools/
│       ├── base.py              # Interfaz abstracta HoneyTool (SOLID)
│       ├── registry.py          # ToolRegistry — Open/Closed + DI
│       └── lookup_ip_reputation.py
├── scripts/
│   ├── build_lambda_package.sh  # Empaquetado simple de la Lambda (incluye anthropic SDK)
│   └── simulate_attack.py       # Simula el uso de las credenciales señuelo
├── reports/                     # Directorio de salida local (no se versiona; se crea al correr el agente)
└── tests/
    └── test_agent.py
```

## Principios de diseño

### SOLID

| Principio | Aplicación |
|-----------|-----------|
| **S** Single Responsibility | `HoneyAgent` orquesta, `HoneyTool` ejecuta, `ToolRegistry` administra |
| **O** Open/Closed | Agregar una nueva tool no requiere modificar `agent.py`; solo crear la clase y registrarla |
| **L** Liskov Substitution | Cualquier `HoneyTool` es intercambiable en el agente |
| **I** Interface Segregation | Interfaz mínima: `execute()` + `definition` |
| **D** Dependency Inversion | `HoneyAgent` depende de `ToolRegistry` (abstracción), no de tools concretas |

### Trazabilidad regulatoria

El razonamiento del agente (qué observó, qué buscó y por qué, cómo cambió su
evaluación, conclusión) queda **textual** en el reporte, no resumido — pensado para
poder evaluarse contra requisitos de documentación de incidentes de PCI DSS v4.0.1 y
la Comunicación "A" 8398 del BCRA. El prototipo no implementa controles de esos
marcos: solo documenta con el nivel de detalle que un auditor esperaría encontrar.

### Seguridad

- Sin API keys de terceros: el agente usa Amazon Bedrock, autenticado con
  credenciales/rol de IAM (las credenciales del honeypot sí se guardan en Secrets
  Manager, nunca en código)
- `.env` excluido del repositorio (solo `.env.example` se versiona)
- IAM con principio de mínimo privilegio (el honeypot de identidad tiene permisos de
  solo lectura: ninguna acción real tiene efecto; el rol de la Lambda solo puede
  invocar modelos Bedrock y escribir en el prefijo de reportes de S3)
- Inputs validados en `HoneyTool.safe_execute()` antes de ejecutar

> **Nota para quien corra los tests localmente**: `agent/agent.py` carga `.env`
> automáticamente al importarse (`python-dotenv`). Si tenés un `.env` con
> credenciales AWS reales y `REPORT_BUCKET` configurado, cualquier código que
> importe `agent.agent` — incluidos los tests — puede terminar leyendo esas
> variables sin que las hayas exportado a mano. Los tests unitarios de
> `tests/test_agent.py` mockean explícitamente la subida a S3 por esta razón;
> si agregás un test nuevo que ejercite `agent/lambda_handler.py`, mockeá
> `_upload_reports_to_s3` para no escribir en un bucket real por accidente.

---

## Licencia

MIT — ver [LICENSE](LICENSE)
