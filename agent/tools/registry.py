"""
agent/tools/registry.py
------------------------
Registro de herramientas del agente. Aplica Open/Closed y Dependency Inversion.

## Por qué existe este módulo

Sin el registry, agregar una nueva tool al agente requeriría modificar agent.py.
Con el registry, agregar una tool es:
    1. Crear la clase que hereda de HoneyTool
    2. Registrarla en build_default_registry()

agent.py no se toca. Eso es Open/Closed.

## Uso

    from agent.tools.registry import ToolRegistry
    from agent.tools.lookup_ip_reputation import LookupIPReputationTool

    registry = ToolRegistry()
    registry.register(LookupIPReputationTool())

    schemas = registry.get_definitions()
    result = registry.execute("lookup_ip_reputation", ip="1.2.3.4")
"""

import logging

from agent.tools.base import HoneyTool

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
        self._tools: dict[str, HoneyTool] = {}

    def register(self, tool: HoneyTool) -> "ToolRegistry":
        """
        Registra una herramienta en el registry.

        Permite encadenamiento: registry.register(ToolA()).register(ToolB())

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
        """Retorna la lista de schemas JSON para pasarle a la Claude API."""
        return [tool.definition for tool in self._tools.values()]

    def execute(self, tool_name: str, **kwargs) -> dict:
        """Ejecuta una tool por nombre con los argumentos dados (vía safe_execute)."""
        tool = self._tools.get(tool_name)
        if tool is None:
            logger.error("Tool desconocida solicitada: '%s'", tool_name)
            return {"error": f"Tool '{tool_name}' no está registrada.", "result": None}

        logger.info("Ejecutando tool: '%s' con args: %s", tool_name, list(kwargs.keys()))
        return tool.safe_execute(**kwargs)

    @property
    def tool_names(self) -> list[str]:
        return list(self._tools.keys())

    def __len__(self) -> int:
        return len(self._tools)

    def __repr__(self) -> str:
        return f"ToolRegistry(tools={self.tool_names})"


def build_default_registry() -> ToolRegistry:
    """
    Construye el registry con las tools del MVP.

    El alcance del Cap. 4 define una única tool para el agente:
    lookup_ip_reputation. Agregar herramientas nuevas no requiere tocar
    agent.py, solo registrarlas acá.
    """
    from agent.tools.lookup_ip_reputation import LookupIPReputationTool

    return ToolRegistry().register(LookupIPReputationTool())
