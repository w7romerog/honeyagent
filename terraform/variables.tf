# terraform/variables.tf
# Variables del módulo. Los valores se pasan por variables de entorno:
#   export TF_VAR_aws_region=us-east-1
# Nunca en terraform.tfvars (podría commitearse accidentalmente).

variable "aws_region" {
  description = "Región AWS donde desplegar los recursos."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Prefijo para todos los recursos creados por HoneyAgent."
  type        = string
  default     = "honeyagent"
}

variable "slack_webhook_url" {
  description = "URL del webhook de Slack. Se guarda en Secrets Manager, no en el código."
  type        = string
  sensitive   = true  # Terraform no lo muestra en logs ni en el plan
}

variable "anthropic_api_key" {
  description = "API key de Anthropic para el agente LLM. Se guarda en Secrets Manager."
  type        = string
  sensitive   = true
}

variable "abuseipdb_api_key" {
  description = "API key de AbuseIPDB para reputation lookup. Se guarda en Secrets Manager."
  type        = string
  sensitive   = true
}

variable "alert_cooldown_minutes" {
  description = "Tiempo mínimo entre alertas del mismo origen (evita spam)."
  type        = number
  default     = 15
}
