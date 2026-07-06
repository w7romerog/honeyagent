# infra/eventbridge.tf
# Amazon EventBridge: motor de enrutamiento del pipeline de detección
# (detection.routing_engine en honeypots.yaml).
#
# Una regla por honeypot de identidad habilitado: matchea cualquier llamada de
# API de CloudTrail cuya identidad invocadora sea el usuario IAM señuelo, y la
# enruta a la Lambda del agente.

resource "aws_cloudwatch_event_rule" "iam_identity_honeypot" {
  for_each = local.iam_identity_honeypots

  name        = "${local.prefix}-${each.key}-activity"
  description = "Detecta cualquier actividad del honeypot de identidad '${each.key}'"

  event_pattern = jsonencode({
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      userIdentity = {
        userName = [aws_iam_user.honeypot[each.key].name]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "iam_identity_honeypot_lambda" {
  for_each = local.iam_identity_honeypots

  rule      = aws_cloudwatch_event_rule.iam_identity_honeypot[each.key].name
  target_id = "HoneyAgentLambda"
  arn       = aws_lambda_function.honeyagent.arn

  # El placeholder <honeypot> va sin comillas: EventBridge lo sustituye por el
  # objeto JSON completo de $.detail, no por un string (patrón documentado de
  # AWS para input_transformer con sustitución de objetos anidados).
  input_transformer {
    input_paths = {
      honeypot = "$.detail"
    }
    input_template = <<-EOT
    {
      "honeypot_name": "${each.key}",
      "detail": <honeypot>
    }
    EOT
  }
}

resource "aws_lambda_permission" "eventbridge_iam_identity" {
  for_each = local.iam_identity_honeypots

  statement_id  = "AllowEventBridge${title(replace(each.key, "-", ""))}"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.honeyagent.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_identity_honeypot[each.key].arn
}
