# infra/iam_identity.tf
# Honeypot de identidad (IAM) — único tipo implementado de punta a punta en el MVP.
#
# Por cada honeypot type=iam_identity con enabled: true en honeypots.yaml (en el
# MVP, uno solo: hp-billing-readonly):
#   - Usuario IAM señuelo con política de permisos mínima (ninguna acción real
#     tiene efecto: solo lectura).
#   - Credenciales de acceso de larga duración, generadas pero nunca usadas
#     legítimamente — son el "cebo": si aparecen en un CloudTrail, algo salió mal
#     en otro lado (fuga de secretos) y alguien las está probando.
#   - Las credenciales se guardan en Secrets Manager para que
#     scripts/simulate_attack.py pueda leerlas y disparar el escenario simulado.

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

# Credenciales del honeypot: se guardan en Secrets Manager (no en el state en
# texto plano, aunque el state ya es sensible) para que simulate_attack.py las
# lea con las credenciales del operador y dispare el escenario de ataque.
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
