# terraform/cloudtrail.tf
# CloudTrail + EventBridge: el sistema nervioso del framework.
#
# Flujo de detección:
#   Acceso a honeypot
#     → CloudTrail registra el evento
#       → EventBridge filtra eventos de honeypots
#         → EventBridge invoca la Lambda del agente
#
# Un trail de CloudTrail es gratis en AWS Free Tier (el primero por cuenta).

# ── CloudTrail ──────────────────────────────────────────────────────────────────

resource "aws_cloudtrail" "honeyagent" {
  name                          = "${local.prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true   # captura eventos de IAM (global)
  is_multi_region_trail         = false  # single-region para el lab (reduce costos)
  enable_log_file_validation    = true   # detecta si alguien modifica los logs

  # Registrar tanto eventos de management (API calls) como de data (S3 GetObject)
  event_selector {
    read_write_type           = "All"
    include_management_events = true

    # Data events de S3: necesarios para detectar GetObject en el bucket honeypot
    data_resource {
      type   = "AWS::S3::Object"
      values = ["${aws_s3_bucket.fake_credentials.arn}/"]
    }
  }

  # Depende del bucket y su política (CloudTrail valida que puede escribir)
  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}

# ── EventBridge Rules ───────────────────────────────────────────────────────────
# Cada rule filtra un tipo de evento de honeypot y dispara la Lambda.
# Usamos el Event Bus default (sin costo adicional).

# Rule 1: Acceso al bucket S3 honeypot
resource "aws_cloudwatch_event_rule" "s3_honeypot" {
  name        = "${local.prefix}-s3-honeypot-access"
  description = "Detecta accesos al bucket S3 honeypot (GetObject, ListBucket, etc.)"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["GetObject", "PutObject", "DeleteObject", "ListBucket", "ListObjects", "ListObjectsV2"]
      requestParameters = {
        bucketName = [aws_s3_bucket.fake_credentials.bucket]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "s3_honeypot_lambda" {
  rule      = aws_cloudwatch_event_rule.s3_honeypot.name
  target_id = "HoneyAgentLambda"
  arn       = aws_lambda_function.honeyagent.arn

  # Enriquecer el evento con metadata del honeypot antes de enviarlo a Lambda
  input_transformer {
    input_paths = {
      eventName   = "$.detail.eventName"
      sourceIP    = "$.detail.sourceIPAddress"
      userArn     = "$.detail.userIdentity.arn"
      userName    = "$.detail.userIdentity.userName"
      eventTime   = "$.detail.eventTime"
      region      = "$.detail.awsRegion"
      resources   = "$.detail.requestParameters"
    }
    input_template = jsonencode({
      honeypot_name = aws_s3_bucket.fake_credentials.bucket
      event_name    = "<eventName>"
      source_ip     = "<sourceIP>"
      aws_user      = "<userArn>"
      aws_username  = "<userName>"
      event_time    = "<eventTime>"
      aws_region    = "<region>"
      severity      = "high"
      resources     = ["<resources>"]
    })
  }
}

# Rule 2: Uso del usuario IAM honeypot (cualquier llamada API con sus credenciales)
resource "aws_cloudwatch_event_rule" "iam_honeypot" {
  name        = "${local.prefix}-iam-honeypot-activity"
  description = "Detecta cualquier actividad del usuario IAM honeypot"

  event_pattern = jsonencode({
    source      = ["aws.iam", "aws.s3", "aws.ec2", "aws.sts"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      userIdentity = {
        userName = [aws_iam_user.honeypot_admin.name]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "iam_honeypot_lambda" {
  rule      = aws_cloudwatch_event_rule.iam_honeypot.name
  target_id = "HoneyAgentLambda"
  arn       = aws_lambda_function.honeyagent.arn

  input_transformer {
    input_paths = {
      eventName = "$.detail.eventName"
      sourceIP  = "$.detail.sourceIPAddress"
      userArn   = "$.detail.userIdentity.arn"
      userName  = "$.detail.userIdentity.userName"
      eventTime = "$.detail.eventTime"
      region    = "$.detail.awsRegion"
    }
    input_template = jsonencode({
      honeypot_name = "hp-admin-backup-user"
      event_name    = "<eventName>"
      source_ip     = "<sourceIP>"
      aws_user      = "<userArn>"
      aws_username  = "<userName>"
      event_time    = "<eventTime>"
      aws_region    = "<region>"
      severity      = "critical"
      resources     = []
    })
  }
}

# Rule 3: Acceso al secret honeypot de Secrets Manager
resource "aws_cloudwatch_event_rule" "secrets_honeypot" {
  name        = "${local.prefix}-secrets-honeypot-access"
  description = "Detecta accesos al secret honeypot de Secrets Manager"

  event_pattern = jsonencode({
    source      = ["aws.secretsmanager"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["secretsmanager.amazonaws.com"]
      eventName   = ["GetSecretValue", "DescribeSecret", "DeleteSecret", "PutSecretValue"]
      requestParameters = {
        secretId = [aws_secretsmanager_secret.fake_db_password.name]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "secrets_honeypot_lambda" {
  rule      = aws_cloudwatch_event_rule.secrets_honeypot.name
  target_id = "HoneyAgentLambda"
  arn       = aws_lambda_function.honeyagent.arn

  input_transformer {
    input_paths = {
      eventName = "$.detail.eventName"
      sourceIP  = "$.detail.sourceIPAddress"
      userArn   = "$.detail.userIdentity.arn"
      userName  = "$.detail.userIdentity.userName"
      eventTime = "$.detail.eventTime"
      region    = "$.detail.awsRegion"
    }
    input_template = jsonencode({
      honeypot_name = "hp-prod-db-password"
      event_name    = "<eventName>"
      source_ip     = "<sourceIP>"
      aws_user      = "<userArn>"
      aws_username  = "<userName>"
      event_time    = "<eventTime>"
      aws_region    = "<region>"
      severity      = "high"
      resources     = []
    })
  }
}

# Rule 4: Tampering de CloudTrail (severidad crítica — intento de evasión)
resource "aws_cloudwatch_event_rule" "cloudtrail_tampering" {
  name        = "${local.prefix}-cloudtrail-tampering"
  description = "Detecta intentos de deshabilitar o borrar CloudTrail"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["cloudtrail.amazonaws.com"]
      eventName   = ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]
    }
  })
}

resource "aws_cloudwatch_event_target" "cloudtrail_tampering_lambda" {
  rule      = aws_cloudwatch_event_rule.cloudtrail_tampering.name
  target_id = "HoneyAgentLambda"
  arn       = aws_lambda_function.honeyagent.arn

  input_transformer {
    input_paths = {
      eventName = "$.detail.eventName"
      sourceIP  = "$.detail.sourceIPAddress"
      userArn   = "$.detail.userIdentity.arn"
      userName  = "$.detail.userIdentity.userName"
      eventTime = "$.detail.eventTime"
      region    = "$.detail.awsRegion"
    }
    input_template = jsonencode({
      honeypot_name = "hp-cloudtrail-tampering"
      event_name    = "<eventName>"
      source_ip     = "<sourceIP>"
      aws_user      = "<userArn>"
      aws_username  = "<userName>"
      event_time    = "<eventTime>"
      aws_region    = "<region>"
      severity      = "critical"
      resources     = []
    })
  }
}

# Permiso para que EventBridge invoque la Lambda
resource "aws_lambda_permission" "eventbridge_s3" {
  statement_id  = "AllowEventBridgeS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.honeyagent.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.s3_honeypot.arn
}

resource "aws_lambda_permission" "eventbridge_iam" {
  statement_id  = "AllowEventBridgeIAM"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.honeyagent.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_honeypot.arn
}

resource "aws_lambda_permission" "eventbridge_secrets" {
  statement_id  = "AllowEventBridgeSecrets"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.honeyagent.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.secrets_honeypot.arn
}

resource "aws_lambda_permission" "eventbridge_cloudtrail" {
  statement_id  = "AllowEventBridgeCloudTrail"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.honeyagent.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.cloudtrail_tampering.arn
}
