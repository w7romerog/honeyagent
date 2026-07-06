# infra/main.tf
# Configuración base: provider AWS, lectura declarativa de honeypots.yaml, y
# bucket S3 de reportes del agente.
#
# El módulo lee honeypots.yaml directamente con `yamldecode` (sin generador ni
# script intermedio): es la forma más simple de que Terraform "produzca, para
# cada honeypot enabled: true" los recursos correspondientes, tal como lo
# describe el Cap. 4. Los honeypots con enabled: false (s3_bucket,
# secrets_manager, rds_endpoint en el MVP) quedan documentados acá pero no
# generan recursos reales — ver los *.tf.disabled_stub.
#
# State local (sin remote backend) — apropiado para el laboratorio de tesis.

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
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

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  prefix     = var.project_name

  # Config declarativa completa (los 4 tipos, incluidos los deshabilitados)
  honeypots_config = yamldecode(file("${path.module}/../honeypots.yaml"))
  all_honeypots    = local.honeypots_config.honeypots
  agent_config     = local.honeypots_config.agent

  # Único tipo implementado en el MVP: honeypot de identidad (IAM)
  iam_identity_honeypots = {
    for hp in local.all_honeypots : hp.name => hp
    if hp.type == "iam_identity" && hp.enabled
  }

  # honeypots.yaml define el nombre del bucket con el placeholder ${account_id};
  # se resuelve acá porque yamldecode no vuelve a interpolar strings del YAML.
  reports_bucket_name = replace(local.agent_config.reports_bucket, "$${account_id}", local.account_id)
}

# ── Bucket S3 de reportes del agente ────────────────────────────────────────────
# Destino de los reportes .md/.json generados por agent/report_generator.py
# (agent.reports_bucket en honeypots.yaml).

resource "aws_s3_bucket" "reports" {
  bucket        = local.reports_bucket_name
  force_destroy = true   # permite destruir aunque tenga objetos (útil en el lab)
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ── Outputs ─────────────────────────────────────────────────────────────────────

output "account_id" {
  value       = local.account_id
  description = "ID de la cuenta AWS donde se desplegó HoneyAgent."
}

output "reports_bucket" {
  value       = aws_s3_bucket.reports.bucket
  description = "Bucket S3 donde el agente persiste los reportes .md/.json."
}
