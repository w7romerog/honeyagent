# terraform/honeypots.tf
# Recursos AWS que actúan como honeypots: S3 bucket, IAM user, y Secrets Manager secret.
# Cada recurso está diseñado para ser atractivo para un atacante pero nunca
# debería ser accedido por operaciones legítimas.

# ── Honeypot 1: S3 Bucket con archivos señuelo ─────────────────────────────────
# Simula un bucket con credenciales y backups. Cualquier acceso es sospechoso.

resource "aws_s3_bucket" "fake_credentials" {
  bucket        = "${local.prefix}-fake-credentials-${local.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "fake_credentials" {
  bucket = aws_s3_bucket.fake_credentials.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Habilitar server-side encryption (buena práctica aunque el contenido sea falso)
resource "aws_s3_bucket_server_side_encryption_configuration" "fake_credentials" {
  bucket = aws_s3_bucket.fake_credentials.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Versioning deshabilitado: los archivos señuelo no necesitan historial
resource "aws_s3_bucket_versioning" "fake_credentials" {
  bucket = aws_s3_bucket.fake_credentials.id
  versioning_configuration {
    status = "Disabled"
  }
}

# Objetos señuelo: nombres diseñados para atraer a atacantes
resource "aws_s3_object" "honeypot_credentials_csv" {
  bucket       = aws_s3_bucket.fake_credentials.id
  key          = "credentials/aws_keys_backup.csv"
  content      = "# FAKE FILE - HoneyAgent Trap\nACCESS_KEY,SECRET_KEY\nFAKE_KEY_DO_NOT_USE,FAKE_SECRET_DO_NOT_USE"
  content_type = "text/csv"

  tags = { HoneyAgent = "true", HoneypotFile = "true" }
}

resource "aws_s3_object" "honeypot_db_dump" {
  bucket       = aws_s3_bucket.fake_credentials.id
  key          = "db/prod_dump_2024.sql"
  content      = "-- FAKE DATABASE DUMP - HoneyAgent Trap\n-- This file contains no real data"
  content_type = "application/sql"

  tags = { HoneyAgent = "true", HoneypotFile = "true" }
}

resource "aws_s3_object" "honeypot_tfvars" {
  bucket       = aws_s3_bucket.fake_credentials.id
  key          = "config/terraform.tfvars"
  content      = "# FAKE TERRAFORM VARS - HoneyAgent Trap\naws_access_key = \"FAKE\"\naws_secret_key = \"FAKE\""
  content_type = "text/plain"

  tags = { HoneyAgent = "true", HoneypotFile = "true" }
}

# ── Honeypot 2: IAM User señuelo ────────────────────────────────────────────────
# Usuario que simula ser una cuenta de administrador de respaldo.
# Nunca debería autenticarse. Cualquier actividad = credenciales comprometidas.

resource "aws_iam_user" "honeypot_admin" {
  name = "hp-admin-backup-user"
  path = "/"

  tags = {
    HoneyAgent  = "true"
    Purpose     = "honeypot"
    Description = "DO NOT USE - Honeypot user for HoneyAgent"
  }
}

# Política mínima: solo lectura, para que el honeypot parezca real
# pero no pueda causar daño si las credenciales son usadas
resource "aws_iam_user_policy_attachment" "honeypot_admin_readonly" {
  user       = aws_iam_user.honeypot_admin.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Access key del honeypot: generada y guardada en Secrets Manager
# El atacante podría encontrar esta key en un leak y usarla — eso dispara la alerta
resource "aws_iam_access_key" "honeypot_admin" {
  user = aws_iam_user.honeypot_admin.name
}

# Guardar las credenciales del honeypot en Secrets Manager
# (no en el state de Terraform en texto plano — aunque el state ya es sensible)
resource "aws_secretsmanager_secret" "honeypot_admin_keys" {
  name                    = "${local.prefix}/honeypot/admin-user-keys"
  description             = "Access keys del IAM user honeypot (para referencia interna)"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "honeypot_admin_keys" {
  secret_id = aws_secretsmanager_secret.honeypot_admin_keys.id
  secret_string = jsonencode({
    access_key_id     = aws_iam_access_key.honeypot_admin.id
    secret_access_key = aws_iam_access_key.honeypot_admin.secret
    username          = aws_iam_user.honeypot_admin.name
  })
}

# ── Honeypot 3: Secrets Manager secret señuelo ─────────────────────────────────
# Secret con nombre atractivo. Un GetSecretValue aquí indica que el atacante
# ya comprometió la cuenta y está buscando credenciales de base de datos.

resource "aws_secretsmanager_secret" "fake_db_password" {
  name                    = "prod/database/master"
  description             = "prod/database/master - HoneyAgent Trap"
  recovery_window_in_days = 0

  tags = {
    HoneyAgent = "true"
    Purpose    = "honeypot"
  }
}

resource "aws_secretsmanager_secret_version" "fake_db_password" {
  secret_id     = aws_secretsmanager_secret.fake_db_password.id
  secret_string = jsonencode({
    password = "FAKE_SUPER_SECRET_PASSWORD_HONEYAGENT_TRAP"
    username = "admin"
    host     = "fake-prod-db.cluster-fake.us-east-1.rds.amazonaws.com"
  })
}

# ── Outputs ─────────────────────────────────────────────────────────────────────

output "honeypot_s3_bucket" {
  value       = aws_s3_bucket.fake_credentials.bucket
  description = "Nombre del bucket S3 honeypot."
}

output "honeypot_iam_user" {
  value       = aws_iam_user.honeypot_admin.name
  description = "Nombre del usuario IAM honeypot."
}

output "honeypot_secret_name" {
  value       = aws_secretsmanager_secret.fake_db_password.name
  description = "Nombre del secret honeypot en Secrets Manager."
}
