"""Interfaz abstracta para las tools del agente."""

from abc import ABC, abstractmethod


class HoneyTool(ABC):
    """Contrato mínimo que debe cumplir toda tool del agente."""

    @property
    @abstractmethod
    def definition(self) -> dict:
        """Schema JSON de la tool (formato Claude API: name/description/input_schema)."""

    @abstractmethod
    def execute(self, **kwargs) -> dict:
        """
        Lógica de la tool. No debe lanzar excepciones; ante error retorna
        {"error": "...", ...} para que el agente siga razonando.
        """

    @property
    def name(self) -> str:
        return self.definition["name"]

    def safe_execute(self, **kwargs) -> dict:
        """Valida campos requeridos y tipos antes de llamar a execute()."""
        required_fields = self.definition.get("input_schema", {}).get("required", [])
        missing = [f for f in required_fields if f not in kwargs]
        if missing:
            return {
                "error": f"Campos requeridos faltantes: {missing}",
                "result": None,
            }

        properties = self.definition.get("input_schema", {}).get("properties", {})
        for field, value in kwargs.items():
            expected_type = properties.get(field, {}).get("type")
            if expected_type == "string" and not isinstance(value, str):
                return {
                    "error": f"El campo '{field}' debe ser string, recibido: {type(value).__name__}",
                    "result": None,
                }
            if expected_type == "integer" and not isinstance(value, int):
                try:
                    kwargs[field] = int(value)
                except (ValueError, TypeError):
                    return {
                        "error": f"El campo '{field}' debe ser entero.",
                        "result": None,
                    }

        try:
            return self.execute(**kwargs)
        except Exception as e:
            return {
                "error": f"Error inesperado en tool '{self.name}': {e}",
                "result": None,
            }
