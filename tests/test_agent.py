"""
tests/test_agent.py
--------------------
Tests del MVP de HoneyAgent (Cap. 4 — honeypot de identidad).

Qué se verifica:
  1. La tool lookup_ip_reputation funciona en modo mock.
  2. El ToolRegistry registra y despacha correctamente.
  3. agent/config.py valida el esquema de honeypots.yaml.
  4. El loop del agente completa el análisis con un evento real de Claude API
     (tests de integración, no corren en CI por defecto).
  5. report_generator produce Markdown + JSON con las secciones fijas y la
     convención de nombres esperadas.
  6. lambda_handler traduce el evento de CloudTrail y responde 200/500.

Cómo correr:
    HONEYAGENT_MOCK=true python -m pytest tests/ -v -m unit
    HONEYAGENT_MOCK=true python -m pytest tests/ -v -m integration   # requiere credenciales AWS con acceso a Bedrock

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

sys.path.insert(0, str(Path(__file__).parent.parent))

os.environ.setdefault("HONEYAGENT_MOCK", "true")


# ═══════════════════════════════════════════════════════════════════════════════
# Fixtures
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def iam_identity_event():
    """Resumen estructurado de un evento del honeypot de identidad (ver agent/agent.py)."""
    return {
        "honeypot_name": "hp-billing-readonly",
        "event_source":  "sts.amazonaws.com",
        "event_name":    "GetCallerIdentity",
        "source_ip":     "203.0.113.42",
        "aws_identity":  "arn:aws:iam::123456789012:user/billing-readonly",
        "event_time":    "2024-01-15T03:22:11+00:00",
        "aws_region":    "us-east-1",
        "parameters":    {},
        "result":        "success",
    }


@pytest.fixture
def eventbridge_event():
    """Evento tal como lo entrega EventBridge (detalle crudo de CloudTrail)."""
    return {
        "honeypot_name": "hp-billing-readonly",
        "detail": {
            "eventSource":     "sts.amazonaws.com",
            "eventName":       "GetCallerIdentity",
            "sourceIPAddress": "203.0.113.42",
            "userIdentity":    {"arn": "arn:aws:iam::123456789012:user/billing-readonly"},
            "eventTime":       "2024-01-15T03:22:11+00:00",
            "awsRegion":       "us-east-1",
            "requestParameters": {},
        },
    }


@pytest.fixture
def default_registry():
    from agent.tools.registry import build_default_registry
    return build_default_registry()


# ═══════════════════════════════════════════════════════════════════════════════
# Tests unitarios — lookup_ip_reputation
# ═══════════════════════════════════════════════════════════════════════════════

class TestLookupIPReputationTool:

    @pytest.mark.unit
    def test_execute_retorna_perfil_en_modo_mock(self):
        from agent.tools.lookup_ip_reputation import LookupIPReputationTool
        tool = LookupIPReputationTool()
        result = tool.safe_execute(ip="203.0.113.42")

        assert result["error"] is None
        assert result["ip"] == "203.0.113.42"
        assert result["country_code"]
        assert result["isp"]

    @pytest.mark.unit
    def test_campo_ip_requerido(self):
        from agent.tools.lookup_ip_reputation import LookupIPReputationTool
        tool = LookupIPReputationTool()
        result = tool.safe_execute()
        assert result["error"] is not None

    @pytest.mark.unit
    def test_definition_tiene_campos_requeridos(self):
        from agent.tools.lookup_ip_reputation import LookupIPReputationTool
        tool = LookupIPReputationTool()
        defn = tool.definition

        assert defn["name"] == "lookup_ip_reputation"
        assert "description" in defn
        assert defn["input_schema"]["required"] == ["ip"]


# ═══════════════════════════════════════════════════════════════════════════════
# Tests unitarios — ToolRegistry
# ═══════════════════════════════════════════════════════════════════════════════

class TestToolRegistry:

    @pytest.mark.unit
    def test_registro_por_defecto_incluye_solo_lookup_ip_reputation(self, default_registry):
        """El MVP define una sola tool para el agente."""
        assert len(default_registry) == 1
        assert default_registry.tool_names == ["lookup_ip_reputation"]

    @pytest.mark.unit
    def test_get_definitions_formato_claude_api(self, default_registry):
        defs = default_registry.get_definitions()
        assert len(defs) == 1
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
        from agent.tools.registry import ToolRegistry
        from agent.tools.lookup_ip_reputation import LookupIPReputationTool

        registry = ToolRegistry()
        registry.register(LookupIPReputationTool())
        with pytest.raises(ValueError, match="lookup_ip_reputation"):
            registry.register(LookupIPReputationTool())

    @pytest.mark.unit
    def test_registro_objeto_invalido_lanza_error(self):
        from agent.tools.registry import ToolRegistry

        registry = ToolRegistry()
        with pytest.raises(TypeError):
            registry.register("esto no es una HoneyTool")

    @pytest.mark.unit
    def test_encadenamiento_register(self):
        from agent.tools.base import HoneyTool
        from agent.tools.registry import ToolRegistry

        class DummyTool(HoneyTool):
            @property
            def definition(self):
                return {"name": "dummy", "description": "d", "input_schema": {"type": "object", "properties": {}}}

            def execute(self, **kwargs):
                return {"error": None}

        registry = ToolRegistry().register(DummyTool())
        assert len(registry) == 1


# ═══════════════════════════════════════════════════════════════════════════════
# Tests unitarios — Config / esquema de honeypots.yaml
# ═══════════════════════════════════════════════════════════════════════════════

class TestHoneypotsConfig:

    @pytest.mark.unit
    def test_carga_config_default_valida(self):
        from agent.config import load_honeypots_config
        config = load_honeypots_config()

        assert "honeypots" in config
        assert "detection" in config
        assert "agent" in config

    @pytest.mark.unit
    def test_cuatro_tipos_documentados_uno_habilitado(self):
        from agent.config import enabled_honeypots, load_honeypots_config

        config = load_honeypots_config()
        types = {hp["type"] for hp in config["honeypots"]}
        assert types == {"iam_identity", "s3_bucket", "secrets_manager", "rds_endpoint"}

        enabled = enabled_honeypots(config)
        assert len(enabled) == 1
        assert enabled[0]["type"] == "iam_identity"

    @pytest.mark.unit
    def test_guardduty_documentado_como_deshabilitado(self):
        from agent.config import load_honeypots_config

        config = load_honeypots_config()
        assert config["detection"]["complementary_layer"]["name"] == "guardduty"
        assert config["detection"]["complementary_layer"]["enabled"] is False

    @pytest.mark.unit
    def test_tipo_invalido_lanza_error(self, tmp_path):
        from agent.config import ConfigValidationError, load_honeypots_config

        bad_config = tmp_path / "bad.yaml"
        bad_config.write_text(
            "honeypots:\n"
            "  - type: not_a_real_type\n"
            "    name: x\n"
            "    enabled: true\n"
            "detection: {}\n"
            "agent: {}\n"
        )
        with pytest.raises(ConfigValidationError):
            load_honeypots_config(bad_config)


# ═══════════════════════════════════════════════════════════════════════════════
# Tests de integración — Agente completo con Claude API
# ═══════════════════════════════════════════════════════════════════════════════

class TestHoneyAgentIntegration:

    @pytest.mark.integration
    def test_agente_completa_analisis_y_expone_razonamiento(self, iam_identity_event, default_registry):
        """
        Verifica el flujo completo: evento -> loop -> razonamiento explícito.
        Requiere credenciales AWS con acceso a Bedrock (invoca Claude Haiku 4.5 real).
        """
        from agent.agent import HoneyAgent
        agent = HoneyAgent(registry=default_registry)
        result = agent.run(iam_identity_event)

        assert result["success"] is True
        assert result["final_analysis"]
        assert result["iterations"] >= 1

        # El razonamiento debe quedar textual con las secciones pedidas en el system prompt
        for section in ("Veredicto", "Recomendación"):
            assert section in result["final_analysis"]


# ═══════════════════════════════════════════════════════════════════════════════
# Tests — Report Generator (Markdown + JSON)
# ═══════════════════════════════════════════════════════════════════════════════

class TestReportGenerator:

    @pytest.fixture
    def sample_agent_result(self):
        return {
            "success":    True,
            "iterations": 2,
            "tools_called": [
                {"tool": "lookup_ip_reputation", "input": {"ip": "203.0.113.42"}},
            ],
            "final_analysis": (
                "**Qué observé**: uso de credenciales señuelo desde origen externo.\n\n"
                "**Qué busqué y por qué**: reputación de la IP de origen.\n\n"
                "**Cómo cambió mi evaluación**: la IP no corresponde a un uso legítimo.\n\n"
                "**Veredicto**: critical — credenciales señuelo comprometidas.\n\n"
                "**Recomendación**: revocar las access keys de billing-readonly de inmediato."
            ),
            "error": None,
        }

    @pytest.mark.unit
    def test_genera_markdown_con_secciones_fijas(self, iam_identity_event, sample_agent_result):
        from agent.report_generator import generate_report
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = generate_report(iam_identity_event, sample_agent_result, output_dir=tmpdir)

            assert os.path.exists(paths["markdown"])
            content = Path(paths["markdown"]).read_text(encoding="utf-8")

            for heading in (
                "Resumen del evento",
                "Enriquecimiento mediante herramientas externas",
                "Razonamiento",
                "Veredicto",
                "Recomendación",
            ):
                assert heading in content

    @pytest.mark.unit
    def test_extrae_veredicto_y_recomendacion_con_encabezados_markdown(self, iam_identity_event):
        """
        Claude a veces devuelve '### Veredicto' (encabezado) en vez de
        '**Veredicto**:' (negrita), aunque el system prompt pida lo segundo.
        report_generator debe tolerar ambos formatos.
        """
        from agent.report_generator import generate_report

        agent_result = {
            "success": True,
            "iterations": 2,
            "tools_called": [],
            "final_analysis": (
                "### Qué observé\n\nUso de credenciales señuelo.\n\n"
                "### Veredicto\n\n**Severidad**: HIGH — compromiso confirmado.\n\n"
                "### Recomendación\n\nRevocar las access keys de inmediato.\n"
            ),
            "error": None,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            paths = generate_report(iam_identity_event, agent_result, output_dir=tmpdir)
            content = Path(paths["markdown"]).read_text(encoding="utf-8")

        assert "no se pudo extraer" not in content.lower()
        assert "HIGH — compromiso confirmado" in content
        assert "Revocar las access keys de inmediato" in content

    @pytest.mark.unit
    def test_genera_json_autocontenido(self, iam_identity_event, sample_agent_result):
        from agent.report_generator import generate_report
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = generate_report(
                iam_identity_event, sample_agent_result,
                raw_event={"eventID": "abc-123"}, output_dir=tmpdir,
            )

            assert os.path.exists(paths["json"])
            with open(paths["json"]) as f:
                report = json.load(f)

            assert report["event_summary"]["honeypot_name"] == "hp-billing-readonly"
            assert report["raw_cloudtrail_event"]["eventID"] == "abc-123"
            assert report["agent_report"]["success"] is True
            assert "billing-readonly" in report["agent_report"]["final_analysis"]

    @pytest.mark.unit
    def test_convencion_de_nombre_incluye_timestamp_identidad_y_event_id(self, iam_identity_event, sample_agent_result):
        from agent.report_generator import generate_report
        with tempfile.TemporaryDirectory() as tmpdir:
            paths = generate_report(
                iam_identity_event, sample_agent_result,
                raw_event={"eventID": "abcd1234-5678-90ab-cdef-1234567890ab"},
                output_dir=tmpdir,
            )

            assert paths["key_prefix"] == "reports/iam_identity/2024/01/15/20240115T032211Z_billing-readonly_abcd1234"
            assert Path(paths["markdown"]).name == "20240115T032211Z_billing-readonly_abcd1234.md"
            assert Path(paths["json"]).name == "20240115T032211Z_billing-readonly_abcd1234.json"

    @pytest.mark.unit
    def test_eventos_simultaneos_no_pisan_el_mismo_archivo(self, iam_identity_event, sample_agent_result):
        """
        Dos ataques con la misma identidad señuelo en el mismo segundo (mismo
        event_time) deben producir nombres de archivo distintos, gracias al
        sufijo del eventID de CloudTrail.
        """
        from agent.report_generator import generate_report
        with tempfile.TemporaryDirectory() as tmpdir:
            paths_1 = generate_report(
                iam_identity_event, sample_agent_result,
                raw_event={"eventID": "11111111-aaaa-bbbb-cccc-111111111111"},
                output_dir=tmpdir,
            )
            paths_2 = generate_report(
                iam_identity_event, sample_agent_result,
                raw_event={"eventID": "22222222-dddd-eeee-ffff-222222222222"},
                output_dir=tmpdir,
            )

            assert paths_1["key_prefix"] != paths_2["key_prefix"]
            assert os.path.exists(paths_1["markdown"])
            assert os.path.exists(paths_2["markdown"])


# ═══════════════════════════════════════════════════════════════════════════════
# Tests — Lambda Handler
# ═══════════════════════════════════════════════════════════════════════════════

class TestLambdaHandler:

    class MockContext:
        aws_request_id = "test-request-001"

    @pytest.mark.unit
    def test_summarize_event_traduce_detalle_cloudtrail(self, eventbridge_event):
        from agent.lambda_handler import summarize_event

        summary, raw = summarize_event(eventbridge_event)

        assert summary["event_name"] == "GetCallerIdentity"
        assert summary["event_source"] == "sts.amazonaws.com"
        assert summary["source_ip"] == "203.0.113.42"
        assert summary["aws_identity"] == "arn:aws:iam::123456789012:user/billing-readonly"
        assert summary["result"] == "success"
        assert raw["eventName"] == "GetCallerIdentity"

    @pytest.mark.unit
    def test_handler_retorna_200_en_exito(self, eventbridge_event):
        """
        El handler solo adapta el evento y llama al agente; se mockea create_agent.

        _upload_reports_to_s3 también se mockea explícitamente: si el proceso
        tiene un .env con REPORT_BUCKET/credenciales reales (agent/agent.py
        carga .env vía python-dotenv al importarse), este test NO debe subir
        nada a un bucket real — un test "unit" no toca AWS bajo ninguna
        circunstancia, sin importar qué haya en el entorno.
        """
        mock_result = {
            "success": True, "final_analysis": "Análisis de prueba.",
            "tools_called": [], "iterations": 2, "error": None,
        }
        mock_agent = MagicMock()
        mock_agent.run.return_value = mock_result

        with patch("agent.agent.create_agent", return_value=mock_agent), \
             patch("agent.lambda_handler._upload_reports_to_s3") as mock_upload:
            from agent.lambda_handler import handler
            result = handler(eventbridge_event, self.MockContext())

        mock_upload.assert_called_once()
        assert result["statusCode"] == 200
        body = json.loads(result["body"])
        assert body["success"] is True
        assert body["honeypot"] == "hp-billing-readonly"

    @pytest.mark.unit
    def test_handler_retorna_500_en_error_fatal(self, eventbridge_event):
        with patch("agent.agent.create_agent", side_effect=RuntimeError("API down")):
            from agent.lambda_handler import handler
            result = handler(eventbridge_event, self.MockContext())

        assert result["statusCode"] == 500
        body = json.loads(result["body"])
        assert "error" in body


# ═══════════════════════════════════════════════════════════════════════════════
# Runner standalone
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    pytest.main([__file__, "-v", "-m", "unit", "--tb=short"])
