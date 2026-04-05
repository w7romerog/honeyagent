"""
agent.py
---------
Agente LLM central de HoneyAgent.

Implementa el loop de tool use (function calling) de la Claude API.
Cuando un honeypot es activado, este agente:

  1. Recibe el evento de CloudTrail (vía Lambda o directamente).
  2. Le pide a Claude que analice el evento usando las tools registradas.
  3. Ejecuta las tools que Claude solicita vía el ToolRegistry.
  4. Devuelve los resultados a Claude para que continúe el razonamiento.
  5. Repite hasta que Claude emite stop_reason == "end_turn".

## Principios SOLID aplicados

**S — Single Responsibility**
    HoneyAgent solo orquesta el loop de tool use.
    La lógica de cada herramienta vive en su propia clase (tools/).
    El registro de herramientas vive en ToolRegistry.

**D — Dependency Inversion**
    HoneyAgent recibe un ToolRegistry en su constructor.
    No importa ni conoce CloudTrailQueryTool, IAMUserHistoryTool, etc.
    Para testear: se puede pasar un registry con tools mock.

## Diagrama del loop

  evento
    │
    ▼
  [HoneyAgent.__init__]  ← recibe ToolRegistry por DI
    │
    ▼
  [run(event)]
    │
    ├─ construye mensaje inicial
    │
    └─ loop:
         ├─ llama a Claude API con historial + tools
         ├─ si stop_reason == "end_turn" → fin
         └─ si stop_reason == "tool_use":
              ├─ para cada tool_use block:
              │    └─ registry.execute(tool_name, **args)
              └─ agrega resultados al historial → siguiente iteración
"""

import json
import logging
import os
from datetime import datetime, timezone

import anthropic
from dotenv import load_dotenv

from tools.registry import ToolRegistry, build_default_registry

load_dotenv()
logger = logging.getLogger(__name__)

# Máximo de iteraciones del loop (safety net contra bucles infinitos)
MAX_ITERATIONS = 10

SYSTEM_PROMPT = """Eres HoneyAgent, un agente especializado en análisis de seguridad para AWS.

Tu rol es investigar eventos de seguridad detectados por honeypots en la infraestructura AWS
y determinar si representan una amenaza real.

## Proceso de análisis

Cuando recibas un evento de honeypot, debes:

1. **Verificar la IP de origen** con `ip_reputation_lookup` para saber si es un actor malicioso conocido.
2. **Consultar CloudTrail** con `cloudtrail_query` para ver qué otras acciones realizó esa IP o usuario.
3. **Analizar el usuario IAM** con `iam_user_history` si hay un usuario involucrado.
4. **Enviar la alerta** con `send_alert` incluyendo tu análisis completo.

## Criterios de severidad

- **critical**: acceso a recursos críticos + IP maliciosa conocida, O intento de deshabilitar CloudTrail.
- **high**: acceso a honeypot + IP sospechosa O usuario IAM comprometido.
- **medium**: acceso a honeypot desde IP desconocida (sin historial de abuso).
- **low**: acceso a honeypot desde IP interna o sin señales adicionales de compromiso.

## Formato del análisis (campo 'analysis' de send_alert)

Escribe el análisis en español, con estas secciones:
- **Qué ocurrió**: descripción del evento.
- **Indicadores de amenaza**: IP score, historial del usuario, patrones en CloudTrail.
- **Nivel de riesgo**: justificación de la severidad elegida.
- **Acciones recomendadas**: pasos concretos para el equipo de seguridad.

Sé directo y técnico. Este análisis va al equipo de seguridad, no al usuario final."""


class HoneyAgent:
    """
    Orquestador del loop de tool use con la Claude API.

    Recibe un ToolRegistry por dependency injection: no conoce las
    implementaciones concretas de las tools, solo trabaja con la
    abstracción que el registry expone.
    """

    def __init__(
        self,
        registry: ToolRegistry,
        model: str | None = None,
        max_iterations: int = MAX_ITERATIONS,
    ) -> None:
        """
        Args:
            registry:       Registry con las tools disponibles para el agente.
            model:          Modelo Claude a usar. Si es None, usa AGENT_MODEL del entorno.
            max_iterations: Límite de iteraciones del loop (default: 10).
        """
        self._registry = registry
        self._model = model or os.getenv("AGENT_MODEL", "claude-sonnet-4-6")
        self._max_iterations = max_iterations
        self._client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

        logger.info(
            "HoneyAgent inicializado | modelo: %s | tools: %s",
            self._model, self._registry.tool_names,
        )

    def run(self, event: dict) -> dict:
        """
        Ejecuta el agente sobre un evento de honeypot.

        Args:
            event: Datos del evento de CloudTrail/EventBridge.
                   Campos esperados: honeypot_name, event_name, source_ip,
                   aws_user, event_time, aws_region, resources.

        Returns:
            Dict con:
                - success        : True si el agente completó el análisis
                - final_analysis : texto final (respuesta end_turn de Claude)
                - tools_called   : lista de {tool, input} por iteración
                - iterations     : cantidad de iteraciones del loop
                - error          : mensaje de error si falló (None si OK)
        """
        logger.info(
            "Iniciando análisis | evento: %s | honeypot: %s",
            event.get("event_name"), event.get("honeypot_name"),
        )

        messages = [{"role": "user", "content": self._build_initial_message(event)}]
        tools_called: list[dict] = []
        final_analysis = ""

        for iteration in range(1, self._max_iterations + 1):
            logger.info("Iteración %d/%d", iteration, self._max_iterations)

            response = self._client.messages.create(
                model=self._model,
                max_tokens=4096,
                system=SYSTEM_PROMPT,
                tools=self._registry.get_definitions(),
                messages=messages,
            )

            # Agregar la respuesta de Claude al historial
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

        # Loop excedió el límite
        logger.warning("Límite de %d iteraciones alcanzado.", self._max_iterations)
        return self._success_result(
            f"[Análisis incompleto: límite de {self._max_iterations} iteraciones alcanzado]",
            tools_called,
            self._max_iterations,
        )

    def _dispatch_tools(self, content: list, tools_called: list) -> list[dict]:
        """
        Ejecuta todas las tools solicitadas por Claude en un bloque tool_use.

        Args:
            content:      Lista de bloques de la respuesta de Claude.
            tools_called: Lista acumuladora para el reporte final (modificada in-place).

        Returns:
            Lista de tool_result blocks listos para incluir en el historial.
        """
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
            f"Se detectó actividad sospechosa en un honeypot de AWS. Analiza el siguiente evento:\n\n"
            f"**Honeypot activado**: {event.get('honeypot_name', 'desconocido')}\n"
            f"**Evento CloudTrail**: {event.get('event_name', 'desconocido')}\n"
            f"**IP de origen**: {event.get('source_ip', 'desconocida')}\n"
            f"**Usuario/Rol IAM**: {event.get('aws_user', 'desconocido')}\n"
            f"**Hora del evento**: {event.get('event_time', datetime.now(timezone.utc).isoformat())}\n"
            f"**Región**: {event.get('aws_region', 'us-east-1')}\n"
            f"**Recursos afectados**: {json.dumps(event.get('resources', []), ensure_ascii=False)}\n\n"
            f"Investiga este evento usando las herramientas disponibles y envía una alerta al equipo."
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


# ── Factory function (punto de entrada principal) ───────────────────────────────

def create_agent(registry: ToolRegistry | None = None) -> HoneyAgent:
    """
    Crea un HoneyAgent con el registry predeterminado.

    Permite pasar un registry personalizado para testing o extensión:
        agent = create_agent(registry=my_custom_registry)
    """
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
        "honeypot_name": "hp-fake-credentials-bucket",
        "event_name":    "GetObject",
        "source_ip":     "203.0.113.42",
        "aws_user":      "hp-admin-backup-user",
        "event_time":    datetime.now(timezone.utc).isoformat(),
        "aws_region":    "us-east-1",
        "resources":     ["arn:aws:s3:::hp-fake-credentials-bucket/credentials/aws_keys_backup.csv"],
    }

    print("=" * 60)
    print("HoneyAgent — Test del loop de tool use")
    print("=" * 60)

    agent = create_agent()
    result = agent.run(test_event)

    print(f"\nIteraciones: {result['iterations']}")
    print(f"Tools usadas: {[t['tool'] for t in result['tools_called']]}")
    print(f"\n--- Análisis final ---")
    print(result["final_analysis"])

    sys.exit(0 if result["success"] else 1)
