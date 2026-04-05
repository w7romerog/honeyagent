# terraform/main.tf
# Configuración base: provider AWS, datos de la cuenta, y bucket de logs.
#
# State local (sin remote backend) — apropiado para el laboratorio de tesis.
# En producción se usaría S3 + DynamoDB para el state remoto.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "HoneyAgent"
      Environment = "lab"
      ManagedBy   = "terraform"
    }
  }
}

# ── Datos de la cuenta actual ───────────────────────────────────────────────────
# Usamos el account ID para nombrar recursos únicos (ej: bucket names globales).

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id  = data.aws_caller_identity.current.account_id
  region      = data.aws_region.current.name

  # Prefijo común para todos los recursos del proyecto
  prefix      = var.project_name
}

# ── S3 Bucket para logs de CloudTrail ──────────────────────────────────────────
# CloudTrail necesita un bucket para escribir los logs.
# El nombre incluye el account_id para garantizar unicidad global en S3.

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "${local.prefix}-logs-${local.account_id}"
  force_destroy = true   # permite destruir aunque tenga objetos (útil en lab)
}

# Bloquear acceso público al bucket de logs (nadie externo debe leer los logs)
resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Política del bucket: solo CloudTrail puede escribir aquí
resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })

  # La política debe aplicarse después del bloqueo de acceso público
  depends_on = [aws_s3_bucket_public_access_block.cloudtrail_logs]
}

# ── Secrets Manager: credenciales del agente ────────────────────────────────────
# Los secrets se crean vacíos y se completan con los valores reales vía variables.
# Nunca hardcodeados en el código ni en el state de Terraform visible.

resource "aws_secretsmanager_secret" "slack_webhook" {
  name                    = "${local.prefix}/slack/webhook"
  description             = "Slack Incoming Webhook URL para alertas de HoneyAgent"
  recovery_window_in_days = 0   # permite borrar inmediatamente en el lab
}

resource "aws_secretsmanager_secret_version" "slack_webhook" {
  secret_id     = aws_secretsmanager_secret.slack_webhook.id
  secret_string = jsonencode({ webhook_url = var.slack_webhook_url })
}

resource "aws_secretsmanager_secret" "anthropic_api_key" {
  name                    = "${local.prefix}/anthropic/api-key"
  description             = "API key de Anthropic para el agente LLM HoneyAgent"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "anthropic_api_key" {
  secret_id     = aws_secretsmanager_secret.anthropic_api_key.id
  secret_string = jsonencode({ api_key = var.anthropic_api_key })
}

resource "aws_secretsmanager_secret" "abuseipdb_api_key" {
  name                    = "${local.prefix}/abuseipdb/api-key"
  description             = "API key de AbuseIPDB para IP reputation lookup"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "abuseipdb_api_key" {
  secret_id     = aws_secretsmanager_secret.abuseipdb_api_key.id
  secret_string = jsonencode({ api_key = var.abuseipdb_api_key })
}

# ── Outputs ─────────────────────────────────────────────────────────────────────

output "account_id" {
  value       = local.account_id
  description = "ID de la cuenta AWS donde se desplegó HoneyAgent."
}

output "cloudtrail_logs_bucket" {
  value       = aws_s3_bucket.cloudtrail_logs.bucket
  description = "Nombre del bucket S3 donde CloudTrail escribe los logs."
}

output "slack_secret_arn" {
  value       = aws_secretsmanager_secret.slack_webhook.arn
  description = "ARN del secret de Slack en Secrets Manager."
}
