# infra/lambda.tf
# Función Lambda: ejecutora del pipeline de detección (detection.executor en
# honeypots.yaml). EventBridge la invoca cuando detecta actividad en el
# honeypot de identidad.
#
# El ZIP se genera con scripts/build_lambda_package.sh (empaquetado simple:
# pip install -t + zip). No se usa el data source `archive_file` sobre el
# código fuente porque eso NO instala las dependencias de pip — y el runtime
# de Lambda no incluye el SDK de Anthropic por defecto. Correr el script antes
# de `terraform apply`.

locals {
  lambda_package_path = "${path.module}/lambda_package.zip"
}

resource "aws_iam_role" "lambda_honeyagent" {
  name = "${local.prefix}-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_honeyagent.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_honeyagent_policy" {
  name = "${local.prefix}-lambda-policy"
  role = aws_iam_role.lambda_honeyagent.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # El agente usa Amazon Bedrock (agent/agent.py::AnthropicBedrock) en vez
        # de la API directa de Anthropic — sin API key, sin secret. El modelo
        # (AGENT_MODEL) es un inference profile cross-region, así que se
        # necesita permiso tanto sobre el foundation model como sobre el
        # inference profile.
        Sid    = "BedrockInvokeClaude"
        Effect = "Allow"
        Action = ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"]
        Resource = [
          "arn:aws:bedrock:*::foundation-model/anthropic.*",
          "arn:aws:bedrock:*:${local.account_id}:inference-profile/*",
        ]
      },
      {
        Sid      = "S3WriteReports"
        Effect   = "Allow"
        Action   = ["s3:PutObject"]
        Resource = "${aws_s3_bucket.reports.arn}/reports/*"
      },
    ]
  })
}

resource "aws_lambda_function" "honeyagent" {
  function_name = "${local.prefix}-agent"
  description   = "Agente LLM de HoneyAgent: analiza eventos del honeypot de identidad"

  filename         = local.lambda_package_path
  source_code_hash = fileexists(local.lambda_package_path) ? filebase64sha256(local.lambda_package_path) : null

  handler = "agent.lambda_handler.handler"
  runtime = "python3.12"
  role    = aws_iam_role.lambda_honeyagent.arn

  # Timeout generoso: el agente hace llamadas a Bedrock + ip-api.com
  timeout     = 300   # 5 minutos (máximo de Lambda)
  memory_size = 256

  # AWS_REGION no se setea acá: es una variable reservada que Lambda inyecta
  # automáticamente con la región de despliegue (agent/agent.py la lee con
  # os.getenv("AWS_REGION", ...), que ya funciona sin configuración extra).
  environment {
    variables = {
      AGENT_MODEL     = "us.anthropic.claude-sonnet-4-5-20250929-v1:0"
      HONEYAGENT_MOCK = "false"
      LOG_LEVEL       = "INFO"
      REPORT_BUCKET   = aws_s3_bucket.reports.bucket
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic,
    aws_iam_role_policy.lambda_honeyagent_policy,
    aws_cloudwatch_log_group.lambda_logs,
  ]
}

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${local.prefix}-agent"
  retention_in_days = 7
}

# ── Outputs ─────────────────────────────────────────────────────────────────────

output "lambda_function_name" {
  value       = aws_lambda_function.honeyagent.function_name
  description = "Nombre de la función Lambda del agente."
}
