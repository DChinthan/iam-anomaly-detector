# One log group per aggregated region, matching aws/cloudwatch_client.py's
# AWS_REGIONS multi-region ingestion loop.
resource "aws_cloudwatch_log_group" "cloudtrail" {
  for_each          = toset(var.aws_regions)
  name              = "${var.cloudtrail_log_group_name}-${each.value}"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

resource "aws_cloudwatch_log_group" "scorer_lambda" {
  name              = "/aws/lambda/${local.name_prefix}-scorer"
  retention_in_days = var.log_retention_days
  tags              = local.common_tags
}

# Alarm on the scoring Lambda's error rate so a broken deploy pages someone
# instead of silently stopping anomaly detection.
resource "aws_cloudwatch_metric_alarm" "scorer_errors" {
  alarm_name          = "${local.name_prefix}-scorer-errors"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  dimensions = {
    FunctionName = aws_lambda_function.scorer.function_name
  }
  treat_missing_data = "notBreaching"
  tags               = local.common_tags
}
