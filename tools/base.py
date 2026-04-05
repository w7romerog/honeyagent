"""
tools/base.py
--------------
Define la interfaz abstracta que toda tool del agente debe implementar.

## Principios SOLID aplicados

**S — Single Responsibility**
    Cada subclase tiene una única responsabilidad (consultar CloudTrail,
    verificar reputación de IP, etc.). Esta clase base no hace nada por sí sola.

**O — Open/Closed**
    El agente está abierto a recibir nuevas tools sin modificar su código.
    Para agregar una tool: crear una subclase de HoneyTool y registrarla.

**L — Liskov Substitution**
    Cualquier HoneyTool puede reemplazar a otra en el agente sin romper el sistema,
    ya que todas cumplen el mismo contrato (execute + definition).

**I — Interface Segregation**
    La interfaz es mínima: solo dos miembros obligatorios (execute, definition).
    Las tools no están forzadas a implementar métodos que no necesitan.

**D — Dependency Inversion**
    HoneyAgent depende de esta abstracción, no de CloudTrailQueryTool ni de
    ninguna implementación concreta.
"""

from abc import ABC, abstractmethod


class HoneyTool(ABC):
    """
    Contrato que toda herramienta del agente debe cumplir.

    El agente LLM interactúa con tools a través de esta interfaz,
    sin conocer los detalles de implementación de cada una.
    """

    @property
    @abstractmethod
    def definition(self) -> dict:
        """
        Retorna el schema JSON de la tool en el formato que espera la Claude API.

        Estructura requerida:
            {
                "name": str,
                "description": str,
                "input_schema": {
                    "type": "object",
                    "properties": {...},
                    "required": [...]
                }
            }
        """

    @abstractmethod
    def execute(self, **kwargs) -> dict:
        """
        Ejecuta la lógica de la tool con los argumentos que Claude proporciona.

        Args:
            **kwargs: Los argumentos definidos en input_schema["properties"].

        Returns:
            Dict con el resultado. Debe incluir siempre:
                - "error": str | None  (None si la ejecución fue exitosa)
            El resto de los campos son específicos de cada tool.

        Note:
            Este método NUNCA debe lanzar excepciones no capturadas.
            Ante errores, retorna {"error": "descripción", ...} para que
            el agente pueda seguir razonando.
        """

    @property
    def name(self) -> str:
        """Atajo para obtener el nombre sin acceder al dict completo."""
        return self.definition["name"]

    def safe_execute(self, **kwargs) -> dict:
        """
        Wrapper de execute() con validación de inputs y manejo de errores.

        El agente llama a este método en lugar de execute() directamente.
        Garantiza que:
          1. Los campos requeridos están presentes.
          2. Los tipos básicos son correctos.
          3. Las excepciones no propagadas no rompen el loop del agente.
        """
        # Validar campos requeridos según el schema de la tool
        required_fields = self.definition.get("input_schema", {}).get("required", [])
        missing = [f for f in required_fields if f not in kwargs]
        if missing:
            return {
                "error": f"Campos requeridos faltantes: {missing}",
                "result": None,
            }

        # Validar tipos de los campos string (previene injection en queries)
        properties = self.definition.get("input_schema", {}).get("properties", {})
        for field, value in kwargs.items():
            expected_type = properties.get(field, {}).get("type")
            if expected_type == "string" and not isinstance(value, str):
                return {
                    "error": f"El campo '{field}' debe ser string, recibido: {type(value).__name__}",
                    "result": None,
                }
            if expected_type == "integer" and not isinstance(value, int):
                # Intentar coercionar si viene como float o string numérico
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
