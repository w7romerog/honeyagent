# infra/variables.tf
# Variables del módulo.

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
