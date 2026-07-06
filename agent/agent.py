"""Agente LLM: loop de tool use sobre el evento del honeypot de identidad."""

import json
import logging
import os
from datetime import datetime, timezone

import anthropic
from dotenv import load_dotenv

from agent.tools.registry import ToolRegistry, build_default_registry

load_dotenv()
logger = logging.getLogger(__name__)

# Límite de iteraciones del loop de tool use
MAX_ITERATIONS = 10

SYSTEM_PROMPT = """Eres HoneyAgent, un agente de análisis de amenazas para un honeypot de \
identidad (IAM) desplegado en AWS.

## Contexto regulatorio

El informe que redactes es un artefacto de trazabilidad de seguridad. Debe contener \
suficiente detalle como para evaluarse contra dos marcos:
- PCI DSS v4.0.1 (requisitos de detección, respuesta y documentación de incidentes).
- Comunicación "A" 8398 del BCRA (gestión de incidentes de ciberseguridad en entidades \
financieras).
No implementes controles de estos marcos: solo asegurate de que el informe documente \
el evento, la investigación y la conclusión con el nivel de detalle que un auditor \
de cualquiera de los dos marcos esperaría encontrar.

## Qué recibís

Un resumen estructurado de un evento de CloudTrail: identidad invocadora, operación, \
servicio, parámetros relevantes, IP de origen, momento y resultado. La identidad \
invocadora es siempre el usuario IAM señuelo (activo señuelo): nunca debería \
autenticarse legítimamente, así que el evento en sí ya es la señal de compromiso.

## Proceso de análisis

1. Observá el evento: qué operación se intentó, desde qué IP, con qué resultado.
2. Decidí si necesitás enriquecer el origen con `lookup_ip_reputation` (país, ISP, \
organización) para evaluar si es compatible con un uso legítimo o no.
3. Concluí con un veredicto de severidad (low | medium | high | critical) y una \
recomendación concreta.

## Formato de la respuesta final

Exponé tu razonamiento de forma explícita y trazable, con estas secciones exactas \
(en español), usando ese texto tal cual (sin resumirlo después):

- **Qué observé**: descripción del evento.
- **Qué busqué y por qué**: qué herramienta invocaste (si alguna) y qué esperabas \
confirmar o descartar con ese dato.
- **Cómo cambió mi evaluación**: cómo el resultado de la herramienta (o su ausencia) \
modificó o confirmó tu hipótesis inicial.
- **Veredicto**: severidad (low | medium | high | critical) y justificación.
- **Recomendación**: acciones concretas para el equipo de seguridad (ej. revocar \
las credenciales del usuario señuelo, revisar el resto de la sesión del atacante).

Sé directo y técnico. Este análisis va a un equipo de seguridad, no al usuario final."""


class HoneyAgent:
    """Orquestador del loop de tool use (Claude vía Amazon Bedrock)."""

    def __init__(
        self,
        registry: ToolRegistry,
        model: str | None = None,
        max_iterations: int = MAX_ITERATIONS,
    ) -> None:
        self._registry = registry
        self._model = model or os.getenv("AGENT_MODEL", "us.anthropic.claude-sonnet-4-5-20250929-v1:0")
        self._max_iterations = max_iterations
        # Bedrock: autenticación por credenciales/rol de IAM, sin API key.
        self._client = anthropic.AnthropicBedrock(aws_region=os.getenv("AWS_REGION", "us-east-1"))

        logger.info(
            "HoneyAgent inicializado | modelo: %s | tools: %s",
            self._model, self._registry.tool_names,
        )

    def run(self, event: dict) -> dict:
        """Ejecuta el loop sobre el resumen de evento (ver lambda_handler.summarize_event)."""
        logger.info(
            "Iniciando análisis | evento: %s | honeypot: %s",
            event.get("event_name"), event.get("honeypot_name"),
        )

        messages = [{"role": "user", "content": self._build_initial_message(event)}]
        tools_called: list[dict] = []

        for iteration in range(1, self._max_iterations + 1):
            logger.info("Iteración %d/%d", iteration, self._max_iterations)

            response = self._client.messages.create(
                model=self._model,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                tools=self._registry.get_definitions(),
                messages=messages,
            )

            messages.append({"role": "assistant", "content": response.content})

            if response.stop_reason == "end_turn":
                final_analysis = self._extract_text(response.content)
                logger.info("Análisis completado en %d iteraciones.", iteration)
                return self._success_result(final_analysis, tools_called, iteration)

            if response.stop_reason == "tool_use":
                tool_results = self._dispatch_tools(response.content, tools_called)
                messages.append({"role": "user", "content": tool_results})
                continue

            logger.warning("stop_reason inesperado: %s", response.stop_reason)
            break

        logger.warning("Límite de %d iteraciones alcanzado.", self._max_iterations)
        return self._success_result(
            f"[Análisis incompleto: límite de {self._max_iterations} iteraciones alcanzado]",
            tools_called,
            self._max_iterations,
        )

    def _dispatch_tools(self, content: list, tools_called: list) -> list[dict]:
        """Ejecuta todas las tools solicitadas por Claude en un bloque tool_use."""
        results = []
        for block in content:
            if block.type != "tool_use":
                continue

            tool_input = block.input
            logger.info("Claude solicita: %s(%s)", block.name, list(tool_input.keys()))
            tools_called.append({"tool": block.name, "input": tool_input})

            result = self._registry.execute(block.name, **tool_input)
            logger.debug("Resultado de %s: %s", block.name, json.dumps(result)[:200])

            results.append({
                "type":        "tool_result",
                "tool_use_id": block.id,
                "content":     json.dumps(result, ensure_ascii=False),
            })
        return results

    def _build_initial_message(self, event: dict) -> str:
        return (
            f"Se detectó actividad en el honeypot de identidad (IAM). Analiza el "
            f"siguiente evento:\n\n"
            f"**Honeypot activado**: {event.get('honeypot_name', 'desconocido')}\n"
            f"**Servicio/operación**: {event.get('event_source', 'desconocido')} / "
            f"{event.get('event_name', 'desconocido')}\n"
            f"**IP de origen**: {event.get('source_ip', 'desconocida')}\n"
            f"**Identidad invocadora**: {event.get('aws_identity', 'desconocida')}\n"
            f"**Hora del evento**: {event.get('event_time', datetime.now(timezone.utc).isoformat())}\n"
            f"**Región**: {event.get('aws_region', 'us-east-1')}\n"
            f"**Parámetros relevantes**: {json.dumps(event.get('parameters', {}), ensure_ascii=False)}\n"
            f"**Resultado de la operación**: {event.get('result', 'desconocido')}\n\n"
            f"Investigá este evento y redactá tu análisis en el formato solicitado."
        )

    def _extract_text(self, content: list) -> str:
        for block in content:
            if hasattr(block, "text"):
                return block.text
        return ""

    def _success_result(self, analysis: str, tools_called: list, iterations: int) -> dict:
        return {
            "success":        bool(analysis),
            "final_analysis": analysis,
            "tools_called":   tools_called,
            "iterations":     iterations,
            "error":          None,
        }


def create_agent(registry: ToolRegistry | None = None) -> HoneyAgent:
    """Crea un HoneyAgent con el registry por defecto (o uno custom para tests)."""
    return HoneyAgent(registry=registry or build_default_registry())


# ── Test standalone ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    os.environ["HONEYAGENT_MOCK"] = "true"

    test_event = {
        "honeypot_name": "hp-billing-readonly",
        "event_source":  "sts.amazonaws.com",
        "event_name":    "GetCallerIdentity",
        "source_ip":     "203.0.113.42",
        "aws_identity":  "arn:aws:iam::123456789012:user/billing-readonly",
        "event_time":    datetime.now(timezone.utc).isoformat(),
        "aws_region":    "us-east-1",
        "parameters":    {},
        "result":        "success",
    }

    print("=" * 60)
    print("HoneyAgent — Test del loop de tool use")
    print("=" * 60)

    agent = create_agent()
    result = agent.run(test_event)

    print(f"\nIteraciones: {result['iterations']}")
    print(f"Tools usadas: {[t['tool'] for t in result['tools_called']]}")
    print("\n--- Análisis final ---")
    print(result["final_analysis"])

    sys.exit(0 if result["success"] else 1)
