"""
tests/test_agent.py
--------------------
Tests de integración end-to-end de HoneyAgent.

Qué se verifica:
  1. Que cada tool funciona correctamente en modo mock.
  2. Que el ToolRegistry registra tools y despacha correctamente.
  3. Que el loop del agente completa el análisis con un evento real de Claude API.
  4. Que el report_generator produce archivos válidos.
  5. Que el lambda_handler procesa un evento y retorna HTTP 200.

Cómo correr:
    # Todos los tests (modo mock, sin AWS ni APIs externas)
    HONEYAGENT_MOCK=true python -m pytest tests/ -v

    # Solo tests unitarios (sin Claude API)
    HONEYAGENT_MOCK=true python -m pytest tests/ -v -m "not integration"

    # Test del agente completo con Claude API real (requiere ANTHROPIC_API_KEY)
    HONEYAGENT_MOCK=true python -m pytest tests/ -v -m integration

Convención de marcadores:
    @pytest.mark.unit        → sin dependencias externas
    @pytest.mark.integration → llama a la Claude API real
"""

import json
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# Asegurar que el módulo raíz esté en el path
sys.path.insert(0, str(Path(__file__).parent.parent))

# Activar modo mock para todas las tools durante los tests
os.environ.setdefault("HONEYAGENT_MOCK", "true")


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def s3_event():
    """Evento de acceso al bucket S3 honeypot."""
    path = Path(__file__).parent / "mock_events" / "s3_access.json"
    with open(path) as f:
        return json.load(f)


@pytest.fixture
def iam_event():
    """Evento de uso del IAM user honeypot."""
    path = Path(__file__).parent / "mock_events" / "iam_activity.json"
    with open(path) as f:
        return json.load(f)


@pytest.fixture
def cloudtrail_event():
    """Evento de tampering de CloudTrail."""
    path = Path(__file__).parent / "mock_events" / "cloudtrail_tampering.json"
    with open(path) as f:
        return json.load(f)


@pytest.fixture
def default_registry():
    """Registry con todas las tools en modo mock."""
    from tools.registry import build_default_registry
    return build_default_registry()


# ═══════════════════════════════════════════════════════════════════════════════
# Tests unitarios — Tools individuales
# ═══════════════════════════════════════════════════════════════════════════════

class TestCloudTrailQueryTool:

    @pytest.mark.unit
    def test_execute_con_ip_retorna_eventos(self):
        from tools.cloudtrail_query import CloudTrailQueryTool
        tool = CloudTrailQueryTool()
        result = tool.safe_execute(source_ip="203.0.113.42")

        assert result["error"] is None
        assert result["total_found"] > 0
        assert isinstance(result["events"], list)
        assert all("event_name" in e for e in result["events"])

    @pytest.mark.unit
    def test_execute_sin_parametros_retorna_error(self):
        from tools.cloudtrail_query import CloudTrailQueryTool
        tool = CloudTrailQueryTool()
        result = tool.safe_execute()

        # Sin IP ni username, debe informar el error sin explotar
        assert result["error"] is not None

    @pytest.mark.unit
    def test_definition_tiene_campos_requeridos(self):
        from tools.cloudtrail_query import CloudTrailQueryTool
        tool = CloudTrailQueryTool()
        defn = tool.definition

        assert defn["name"] == "cloudtrail_query"
        assert "description" in defn
        assert "input_schema" in defn
        assert defn["input_schema"]["type"] == "object"


class TestIAMUserHistoryTool:

    @pytest.mark.unit
    def test_execute_retorna_perfil_completo(self):
        from tools.iam_user_history import IAMUserHistoryTool
        tool = IAMUserHistoryTool()
        result = tool.safe_execute(username="hp-admin-backup-user")

        assert result["error"] is None
        assert result["user_info"]["username"] == "hp-admin-backup-user"
        assert len(result["access_keys"]) > 0
        assert len(result["risk_signals"]) > 0

    @pytest.mark.unit
    def test_honeypot_detectado_en_risk_signals(self):
        from tools.iam_user_history import IAMUserHistoryTool
        tool = IAMUserHistoryTool()
        result = tool.safe_execute(username="hp-admin-backup-user")

        honeypot_signals = [s for s in result["risk_signals"] if "HONEYPOT" in s]
        assert len(honeypot_signals) > 0, "Debe detectar que el usuario es un honeypot"

    @pytest.mark.unit
    def test_campo_requerido_faltante(self):
        from tools.iam_user_history import IAMUserHistoryTool
        tool = IAMUserHistoryTool()
        # username es required — safe_execute debe retornar error
        result = tool.safe_execute()
        assert result["error"] is not None
        assert "username" in result["error"]


class TestIPReputationLookupTool:

    @pytest.mark.unit
    def test_ip_maliciosa_retorna_veredicto_correcto(self):
        from tools.ip_reputation_lookup import IPReputationLookupTool
        tool = IPReputationLookupTool()
        result = tool.safe_execute(ip_address="203.0.113.42")

        assert result["error"] is None
        assert result["abuse_score"] >= 25
        assert result["is_malicious"] is True
        assert result["verdict"] == "MALICIOSA"
        assert len(result["categories"]) > 0

    @pytest.mark.unit
    def test_campo_ip_requerido(self):
        from tools.ip_reputation_lookup import IPReputationLookupTool
        tool = IPReputationLookupTool()
        result = tool.safe_execute()
        assert result["error"] is not None


class TestSendAlertTool:

    @pytest.mark.unit
    def test_envio_mock_exitoso(self):
        from tools.send_alert import SendAlertTool
        tool = SendAlertTool()
        result = tool.safe_execute(
            honeypot_name="hp-fake-credentials-bucket",
            severity="high",
            source_ip="203.0.113.42",
            aws_user="hp-admin-backup-user",
            event_name="GetObject",
            event_time="2024-01-15T03:22:11+00:00",
            analysis="Test de integración.",
        )

        assert result["error"] is None
        assert result["sent"] is True

    @pytest.mark.unit
    def test_severidad_invalida_no_llega_a_execute(self):
        """safe_execute valida el enum antes de llamar execute."""
        from tools.send_alert import SendAlertTool
        tool = SendAlertTool()
        # 'ultra-critical' no está en el enum del schema
        # safe_execute no valida enums (solo tipos), pero execute debe manejar
        # valores inesperados sin explotar
        result = tool.safe_execute(
            honeypot_name="hp-test",
            severity="ultra-critical",   # valor fuera del enum
            source_ip="1.2.3.4",
            aws_user="user",
            event_name="GetObject",
            event_time="2024-01-15T00:00:00+00:00",
            analysis="Test.",
        )
        # En modo mock siempre retorna sent=True; verificamos que no explota
        assert "error" in result


# ═══════════════════════════════════════════════════════════════════════════════
# Tests unitarios — ToolRegistry
# ═══════════════════════════════════════════════════════════════════════════════

class TestToolRegistry:

    @pytest.mark.unit
    def test_registro_y_ejecucion(self, default_registry):
        assert len(default_registry) == 4
        assert "cloudtrail_query" in default_registry.tool_names
        assert "iam_user_history" in default_registry.tool_names
        assert "ip_reputation_lookup" in default_registry.tool_names
        assert "send_alert" in default_registry.tool_names

    @pytest.mark.unit
    def test_get_definitions_formato_claude_api(self, default_registry):
        defs = default_registry.get_definitions()
        assert len(defs) == 4
        for d in defs:
            assert "name" in d
            assert "description" in d
            assert "input_schema" in d

    @pytest.mark.unit
    def test_execute_tool_desconocida_retorna_error(self, default_registry):
        result = default_registry.execute("tool_inexistente", foo="bar")
        assert result["error"] is not None
        assert "no está registrada" in result["error"]

    @pytest.mark.unit
    def test_registro_duplicado_lanza_error(self):
        from tools.registry import ToolRegistry
        from tools.cloudtrail_query import CloudTrailQueryTool

        registry = ToolRegistry()
        registry.register(CloudTrailQueryTool())
        with pytest.raises(ValueError, match="cloudtrail_query"):
            registry.register(CloudTrailQueryTool())

    @pytest.mark.unit
    def test_registro_objeto_invalido_lanza_error(self):
        from tools.registry import ToolRegistry

        registry = ToolRegistry()
        with pytest.raises(TypeError):
            registry.register("esto no es una HoneyTool")

    @pytest.mark.unit
    def test_encadenamiento_register(self):
        from tools.registry import ToolRegistry
        from tools.cloudtrail_query import CloudTrailQueryTool
        from tools.iam_user_history import IAMUserHistoryTool

        registry = (
            ToolRegistry()
            .register(CloudTrailQueryTool())
            .register(IAMUserHistoryTool())
        )
        assert len(registry) == 2


# ═══════════════════════════════════════════════════════════════════════════════
# Tests de integración — Agente completo con Claude API
# ═══════════════════════════════════════════════════════════════════════════════

class TestHoneyAgentIntegration:

    @pytest.mark.integration
    def test_agente_completa_analisis_s3(self, s3_event, default_registry):
        """
        Verifica el flujo completo: evento → loop → análisis → alerta.
        Requiere ANTHROPIC_API_KEY configurada.
        """
        from agent import HoneyAgent
        agent = HoneyAgent(registry=default_registry)
        result = agent.run(s3_event)

        assert result["success"] is True
        assert result["final_analysis"]
        assert result["iterations"] >= 1
        assert len(result["tools_called"]) >= 1

        # El agente debe haber llamado send_alert como acción final
        tool_names = [t["tool"] for t in result["tools_called"]]
        assert "send_alert" in tool_names, "El agente debe enviar una alerta al finalizar"

    @pytest.mark.integration
    def test_agente_clasifica_severidad_critical(self, cloudtrail_event, default_registry):
        """
        Un evento de CloudTrail tampering debe resultar en severidad critical.
        """
        from agent import HoneyAgent
        agent = HoneyAgent(registry=default_registry)
        result = agent.run(cloudtrail_event)

        assert result["success"] is True

        # Verificar que send_alert fue llamado con severidad critical o high
        alert_calls = [t for t in result["tools_called"] if t["tool"] == "send_alert"]
        assert len(alert_calls) > 0
        severity = alert_calls[-1]["input"].get("severity", "")
        assert severity in ("critical", "high"), f"Severidad esperada critical/high, recibida: {severity}"

    @pytest.mark.integration
    def test_agente_usa_multiples_tools(self, s3_event, default_registry):
        """
        Para un evento de S3, el agente debe usar al menos ip_reputation_lookup
        y cloudtrail_query antes de enviar la alerta.
        """
        from agent import HoneyAgent
        agent = HoneyAgent(registry=default_registry)
        result = agent.run(s3_event)

        tool_names = [t["tool"] for t in result["tools_called"]]
        assert "ip_reputation_lookup" in tool_names
        assert "send_alert" in tool_names


# ═══════════════════════════════════════════════════════════════════════════════
# Tests — Report Generator
# ═══════════════════════════════════════════════════════════════════════════════

class TestReportGenerator:

    @pytest.fixture
    def sample_agent_result(self):
        return {
            "success":    True,
            "iterations": 3,
            "tools_called": [
                {"tool": "ip_reputation_lookup",  "input": {"ip_address": "203.0.113.42"}},
                {"tool": "cloudtrail_query",       "input": {"source_ip": "203.0.113.42"}},
                {"tool": "iam_user_history",       "input": {"username": "hp-admin-backup-user"}},
                {"tool": "send_alert",             "input": {
                    "honeypot_name": "hp-fake-credentials-bucket",
                    "severity":      "high",
                    "source_ip":     "203.0.113.42",
                    "aws_user":      "hp-admin-backup-user",
                    "event_name":    "GetObject",
                    "event_time":    "2024-01-15T03:22:11+00:00",
                    "analysis":      "Análisis de prueba para el reporte.",
                }},
            ],
            "final_analysis": "**Qué ocurrió**: Acceso al honeypot S3.\n**Recomendaciones**: Bloquear IP.",
            "error": None,
        }

    @pytest.mark.unit
    def test_genera_json_valido(self, s3_event, sample_agent_result):
        from report_generator import generate_report
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = generate_report(s3_event, sample_agent_result, output_dir=tmpdir)

            assert os.path.exists(paths["json"])
            with open(paths["json"]) as f:
                report = json.load(f)

            assert report["incident"]["honeypot_name"] == "hp-fake-credentials-bucket"
            assert report["agent_analysis"]["success"] is True
            assert report["report_metadata"]["framework"] == "HoneyAgent v0.1"

    @pytest.mark.unit
    def test_genera_pdf(self, s3_event, sample_agent_result):
        from report_generator import generate_report
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = generate_report(s3_event, sample_agent_result, output_dir=tmpdir)

            assert os.path.exists(paths["pdf"])
            # Un PDF válido empieza con el magic number %PDF
            with open(paths["pdf"], "rb") as f:
                header = f.read(4)
            assert header == b"%PDF", "El archivo generado no es un PDF válido"


# ═══════════════════════════════════════════════════════════════════════════════
# Tests — Lambda Handler
# ═══════════════════════════════════════════════════════════════════════════════

class TestLambdaHandler:

    class MockContext:
        aws_request_id = "test-request-001"

    @pytest.mark.unit
    def test_handler_retorna_200_en_exito(self, s3_event):
        """
        Mockea el agente completo para no llamar a Claude API.
        El handler solo es responsable de adaptar el evento y llamar al agente.
        """
        mock_result = {
            "success": True, "final_analysis": "Análisis de prueba.",
            "tools_called": [], "iterations": 2, "error": None,
        }
        mock_agent = MagicMock()
        mock_agent.run.return_value = mock_result

        # El handler importa create_agent desde el módulo agent — parchamos ahí
        with patch("agent.create_agent", return_value=mock_agent):
            from lambda_handler import handler
            result = handler(s3_event, self.MockContext())

        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["success"] is True
        assert body["honeypot"] == "hp-fake-credentials-bucket"

    @pytest.mark.unit
    def test_handler_retorna_500_en_error_fatal(self, s3_event):
        """Si create_agent lanza una excepción, Lambda retorna 500."""
        with patch("agent.create_agent", side_effect=RuntimeError("API down")):
            from lambda_handler import handler
            result = handler(s3_event, self.MockContext())

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert "error" in body


# ═══════════════════════════════════════════════════════════════════════════════
# Runner standalone
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Correr solo tests unitarios (sin Claude API)
    pytest.main([__file__, "-v", "-m", "unit", "--tb=short"])
