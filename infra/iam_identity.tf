# Honeypot de identidad (IAM): usuario señuelo de solo lectura, access key de
# larga duración guardada en Secrets Manager para simulate_attack.py.

resource "aws_iam_user" "honeypot" {
  for_each = local.iam_identity_honeypots

  name = each.value.username
  path = "/"

  tags = merge(
    { HoneyAgent = "true", Purpose = "honeypot" },
    lookup(each.value.config, "tags", {}),
  )
}

resource "aws_iam_user_policy_attachment" "honeypot" {
  for_each = local.iam_identity_honeypots

  user       = aws_iam_user.honeypot[each.key].name
  policy_arn = each.value.config.attach_policy_arn
}

resource "aws_iam_access_key" "honeypot" {
  for_each = { for k, v in local.iam_identity_honeypots : k => v if lookup(v.config, "create_access_key", false) }

  user = aws_iam_user.honeypot[each.key].name
}

resource "aws_secretsmanager_secret" "honeypot_keys" {
  for_each = aws_iam_access_key.honeypot

  name                    = "${local.prefix}/honeypot/${each.key}-keys"
  description             = "Access keys del honeypot de identidad '${each.key}' (activo señuelo)"
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "honeypot_keys" {
  for_each = aws_iam_access_key.honeypot

  secret_id = aws_secretsmanager_secret.honeypot_keys[each.key].id
  secret_string = jsonencode({
    access_key_id     = each.value.id
    secret_access_key = each.value.secret
    username          = aws_iam_user.honeypot[each.key].name
  })
}

# ── Outputs ─────────────────────────────────────────────────────────────────────

output "honeypot_iam_users" {
  value       = { for k, v in aws_iam_user.honeypot : k => v.name }
  description = "Usuarios IAM señuelo desplegados (honeypot de identidad)."
}

output "honeypot_credentials_secret_names" {
  value       = { for k, v in aws_secretsmanager_secret.honeypot_keys : k => v.name }
  description = "Nombres de los secrets con las credenciales señuelo, para simulate_attack.py."
}
