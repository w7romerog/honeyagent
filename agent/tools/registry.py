"""Registro de tools disponibles para el agente."""

import logging

from agent.tools.base import HoneyTool

logger = logging.getLogger(__name__)


class ToolRegistry:
    """Registra y despacha tools por nombre."""

    def __init__(self) -> None:
        self._tools: dict[str, HoneyTool] = {}

    def register(self, tool: HoneyTool) -> "ToolRegistry":
        """Registra una tool. Encadenable: registry.register(A()).register(B())."""
        if not isinstance(tool, HoneyTool):
            raise TypeError(f"{type(tool).__name__} no hereda de HoneyTool.")

        name = tool.name
        if name in self._tools:
            raise ValueError(f"Ya existe una tool registrada con el nombre '{name}'.")

        self._tools[name] = tool
        logger.debug("Tool registrada: '%s'", name)
        return self

    def get_definitions(self) -> list[dict]:
        """Schemas JSON de todas las tools (formato Claude API)."""
        return [tool.definition for tool in self._tools.values()]

    def execute(self, tool_name: str, **kwargs) -> dict:
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
    """Registry del MVP: una sola tool, lookup_ip_reputation."""
    from agent.tools.lookup_ip_reputation import LookupIPReputationTool

    return ToolRegistry().register(LookupIPReputationTool())
