# terraform/lambda.tf
# Función Lambda que actúa como entry point del agente.
# EventBridge la invoca cuando detecta actividad en un honeypot.
#
# El código Python se empaqueta en un ZIP que Terraform sube automáticamente.
# En el Free Tier: 1M invocaciones/mes y 400.000 GB-segundos — suficiente para el lab.

# ── Empaquetado del código ──────────────────────────────────────────────────────
# Terraform empaqueta el código Python en un ZIP antes de subirlo a Lambda.
# El archivo lambda_handler.py debe estar en la raíz del proyecto.

data "archive_file" "lambda_zip" {
  type = "zip"

  # Incluir todos los archivos Python del proyecto
  source_dir  = "${path.module}/.."
  output_path = "${path.module}/lambda_package.zip"

  # Excluir archivos que no deben ir en el paquete de Lambda
  excludes = [
    ".git",
    ".gitignore",
    ".gitattributes",
    ".env",
    ".env.example",
    "__pycache__",
    "*.pyc",
    ".venv",          # entorno virtual local — las deps van en un Lambda Layer
    "terraform",
    "reports",
    "tests",
    "lambda_package.zip",
    ".pytest_cache",
    "pytest.ini",
    "README.md",
    "LICENSE",
    ".github",
  ]
}

# ── IAM Role para la Lambda ─────────────────────────────────────────────────────
# Principio de mínimo privilegio: la Lambda solo tiene los permisos que necesita.

resource "aws_iam_role" "lambda_honeyagent" {
  name = "${local.prefix}-lambda-role"

  # Trust policy: solo Lambda puede asumir este rol
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

# Política base de Lambda: permite escribir logs en CloudWatch
resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_honeyagent.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Política personalizada: permisos específicos que el agente necesita
resource "aws_iam_role_policy" "lambda_honeyagent_policy" {
  name = "${local.prefix}-lambda-policy"
  role = aws_iam_role.lambda_honeyagent.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Leer eventos de CloudTrail (para cloudtrail_query tool)
      {
        Sid      = "CloudTrailRead"
        Effect   = "Allow"
        Action   = ["cloudtrail:LookupEvents", "cloudtrail:GetTrailStatus"]
        Resource = "*"
      },
      # Leer información de usuarios IAM (para iam_user_history tool)
      {
        Sid    = "IAMRead"
        Effect = "Allow"
        Action = [
          "iam:GetUser",
          "iam:ListAttachedUserPolicies",
          "iam:ListUserPolicies",
          "iam:ListAccessKeys",
          "iam:GetAccessKeyLastUsed",
        ]
        Resource = "*"
      },
      # Leer secrets (webhook Slack, API keys)
      {
        Sid    = "SecretsManagerRead"
        Effect = "Allow"
        Action = ["secretsmanager:GetSecretValue"]
        Resource = [
          aws_secretsmanager_secret.slack_webhook.arn,
          aws_secretsmanager_secret.anthropic_api_key.arn,
          aws_secretsmanager_secret.abuseipdb_api_key.arn,
        ]
      },
      # Escribir reportes en el bucket de logs
      {
        Sid      = "S3WriteReports"
        Effect   = "Allow"
        Action   = ["s3:PutObject", "s3:GetObject"]
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/reports/*"
      },
    ]
  })
}

# ── Función Lambda ──────────────────────────────────────────────────────────────

resource "aws_lambda_function" "honeyagent" {
  function_name = "${local.prefix}-agent"
  description   = "Agente LLM de HoneyAgent: analiza eventos de honeypots y genera alertas"

  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  # El handler apunta a lambda_handler.py → función handler()
  handler = "lambda_handler.handler"
  runtime = "python3.12"
  role    = aws_iam_role.lambda_honeyagent.arn

  # Timeout generoso: el agente hace múltiples llamadas a APIs externas
  # Claude API + AbuseIPDB + CloudTrail puede tomar 30-60 segundos
  timeout     = 300   # 5 minutos (máximo de Lambda)
  memory_size = 256   # 256 MB es suficiente para Python + dependencias

  # Variables de entorno: referencias a los secrets (no los valores reales)
  environment {
    variables = {
      AWS_REGION_NAME          = var.aws_region
      SLACK_WEBHOOK_SECRET     = aws_secretsmanager_secret.slack_webhook.name
      ANTHROPIC_SECRET_NAME    = aws_secretsmanager_secret.anthropic_api_key.name
      ABUSEIPDB_SECRET_NAME    = aws_secretsmanager_secret.abuseipdb_api_key.name
      AGENT_MODEL              = "claude-sonnet-4-6"
      HONEYAGENT_MOCK          = "false"
      LOG_LEVEL                = "INFO"
      REPORT_BUCKET            = aws_s3_bucket.cloudtrail_logs.bucket
    }
  }

  depends_on = [
    aws_iam_role_policy_attachment.lambda_basic,
    aws_iam_role_policy.lambda_honeyagent_policy,
    aws_cloudwatch_log_group.lambda_logs,
  ]
}

# ── CloudWatch Log Group para la Lambda ─────────────────────────────────────────
# Crearlo explícitamente permite controlar la retención de logs.
# Sin esto, Lambda crea el grupo con retención indefinida (acumula costos).

resource "aws_cloudwatch_log_group" "lambda_logs" {
  name              = "/aws/lambda/${local.prefix}-agent"
  retention_in_days = 7   # 7 días es suficiente para el lab; reduce costos de CloudWatch
}

# ── Outputs ─────────────────────────────────────────────────────────────────────

output "lambda_function_name" {
  value       = aws_lambda_function.honeyagent.function_name
  description = "Nombre de la función Lambda del agente."
}

output "lambda_function_arn" {
  value       = aws_lambda_function.honeyagent.arn
  description = "ARN de la función Lambda (usado por EventBridge para invocarla)."
}

output "lambda_role_arn" {
  value       = aws_iam_role.lambda_honeyagent.arn
  description = "ARN del IAM Role de la Lambda."
}
