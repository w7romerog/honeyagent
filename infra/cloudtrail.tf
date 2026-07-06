# infra/cloudtrail.tf
# Habilita CloudTrail para registrar eventos de administración (management
# events). Es la fuente de auditoría del pipeline de detección
# (detection.audit_source en honeypots.yaml).
#
# No se configuran data_resource de S3: el honeypot S3 está deshabilitado en
# el MVP, así que alcanza con management events (incluye toda la actividad de
# IAM/STS del honeypot de identidad).
#
# Un trail de CloudTrail es gratis en AWS Free Tier (el primero por cuenta).

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket        = "${local.prefix}-cloudtrail-logs-${local.account_id}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail_logs" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail_logs.arn
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail_logs.arn}/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.cloudtrail_logs]
}

resource "aws_cloudtrail" "honeyagent" {
  name                          = "${local.prefix}-trail"
  s3_bucket_name                = aws_s3_bucket.cloudtrail_logs.id
  include_global_service_events = true   # captura eventos de IAM/STS (globales)
  is_multi_region_trail         = false  # single-region para el lab (reduce costos)
  enable_log_file_validation    = true   # detecta si alguien modifica los logs

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs]
}
