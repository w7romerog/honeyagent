# Provider AWS, lectura de honeypots.yaml, bucket de reportes.
# State local (sin remote backend).

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

  honeypots_config = yamldecode(file("${path.module}/../honeypots.yaml"))
  all_honeypots    = local.honeypots_config.honeypots
  agent_config     = local.honeypots_config.agent

  iam_identity_honeypots = {
    for hp in local.all_honeypots : hp.name => hp
    if hp.type == "iam_identity" && hp.enabled
  }

  # yamldecode no reinterpola strings del YAML; se resuelve el placeholder acá.
  reports_bucket_name = replace(local.agent_config.reports_bucket, "$${account_id}", local.account_id)
}

resource "aws_s3_bucket" "reports" {
  bucket        = local.reports_bucket_name
  force_destroy = true
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
