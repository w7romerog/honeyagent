"""
tools/registry.py
------------------
Registro de herramientas del agente. Aplica Open/Closed y Dependency Inversion.

## Por qué existe este módulo

Sin el registry, agregar una nueva tool al agente requeriría modificar agent.py:
    - importar la nueva clase
    - agregarla al dict TOOL_FUNCTIONS
    - agregarla a la lista ALL_TOOLS

Con el registry, agregar una tool es:
    1. Crear la clase que hereda de HoneyTool
    2. Registrarla en este archivo (o usar auto-discovery)

agent.py no se toca. Eso es Open/Closed.

## Uso

    from tools.registry import ToolRegistry
    from tools.cloudtrail_query import CloudTrailQueryTool

    registry = ToolRegistry()
    registry.register(CloudTrailQueryTool())

    # El agente pide los schemas para pasarle a la Claude API
    schemas = registry.get_definitions()

    # El agente ejecuta una tool por nombre (despacho)
    result = registry.execute("cloudtrail_query", source_ip="1.2.3.4")
"""

import logging
from typing import Any

from tools.base import HoneyTool

logger = logging.getLogger(__name__)


class ToolRegistry:
    """
    Registro central de herramientas disponibles para el agente.

    Principios aplicados:
      - OCP: el agente no se modifica al agregar tools; solo el registry.
      - DIP: el agente depende de ToolRegistry (abstracción), no de clases concretas.
      - SRP: este módulo solo administra el registro; no ejecuta lógica de negocio.
    """

    def __init__(self) -> None:
        # Mapa de nombre → instancia de HoneyTool
        self._tools: dict[str, HoneyTool] = {}

    def register(self, tool: HoneyTool) -> "ToolRegistry":
        """
        Registra una herramienta en el registry.

        Permite encadenamiento:
            registry.register(ToolA()).register(ToolB())

        Args:
            tool: Instancia de cualquier subclase de HoneyTool.

        Raises:
            TypeError: Si el objeto no es una instancia de HoneyTool.
            ValueError: Si ya existe una tool con el mismo nombre.
        """
        if not isinstance(tool, HoneyTool):
            raise TypeError(f"{type(tool).__name__} no hereda de HoneyTool.")

        name = tool.name
        if name in self._tools:
            raise ValueError(f"Ya existe una tool registrada con el nombre '{name}'.")

        self._tools[name] = tool
        logger.debug("Tool registrada: '%s'", name)
        return self

    def get_definitions(self) -> list[dict]:
        """
        Retorna la lista de schemas JSON para pasarle a la Claude API.

        Returns:
            Lista de dicts con el formato que espera el parámetro `tools`
            de client.messages.create().
        """
        return [tool.definition for tool in self._tools.values()]

    def execute(self, tool_name: str, **kwargs) -> dict:
        """
        Ejecuta una tool por nombre con los argumentos dados.

        Usa safe_execute() de HoneyTool, que valida inputs y captura excepciones.

        Args:
            tool_name: Nombre de la tool a ejecutar (debe coincidir con definition["name"]).
            **kwargs:  Argumentos que Claude pasó en el tool_use block.

        Returns:
            Dict con el resultado de la tool, siempre con clave "error".
        """
        tool = self._tools.get(tool_name)
        if tool is None:
            logger.error("Tool desconocida solicitada: '%s'", tool_name)
            return {"error": f"Tool '{tool_name}' no está registrada.", "result": None}

        logger.info("Ejecutando tool: '%s' con args: %s", tool_name, list(kwargs.keys()))
        return tool.safe_execute(**kwargs)

    @property
    def tool_names(self) -> list[str]:
        """Lista de nombres de tools registradas."""
        return list(self._tools.keys())

    def __len__(self) -> int:
        return len(self._tools)

    def __repr__(self) -> str:
        return f"ToolRegistry(tools={self.tool_names})"


def build_default_registry() -> ToolRegistry:
    """
    Construye el registry con las tools predeterminadas del agente.

    Punto de extensión: para agregar una nueva tool al sistema,
    importarla aquí y agregarla con .register(). No se modifica
    ningún otro archivo.
    """
    from tools.cloudtrail_query import CloudTrailQueryTool
    from tools.iam_user_history import IAMUserHistoryTool
    from tools.ip_reputation_lookup import IPReputationLookupTool
    from tools.send_alert import SendAlertTool

    return (
        ToolRegistry()
        .register(CloudTrailQueryTool())
        .register(IAMUserHistoryTool())
        .register(IPReputationLookupTool())
        .register(SendAlertTool())
    )
