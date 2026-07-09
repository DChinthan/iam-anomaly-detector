# Scoring Lambda, deployed as a container image (TensorFlow + scikit-learn
# exceed the 250 MB zip-package limit). Build/push infra/lambda/scorer with
# the Dockerfile alongside it, then pass the resulting ECR URI as
# var.scorer_image_uri.
resource "aws_lambda_function" "scorer" {
  function_name = "${local.name_prefix}-scorer"
  role          = aws_iam_role.scorer_lambda.arn
  package_type  = "Image"
  image_uri     = var.scorer_image_uri != "" ? var.scorer_image_uri : "PLACEHOLDER_BUILD_AND_PUSH_IMAGE_FIRST"
  timeout       = 120
  memory_size   = 1024

  environment {
    variables = {
      DYNAMODB_TABLE       = aws_dynamodb_table.anomaly_results.name
      AWS_REGIONS          = join(",", var.aws_regions)
      AWS_MOCK             = "false"
      ANTHROPIC_SECRET_ARN = var.anthropic_api_key_secret_arn
    }
  }

  tags = local.common_tags

  lifecycle {
    # Terraform shouldn't fight CI/CD over which image tag is deployed.
    ignore_changes = [image_uri]
  }
}

# Runs the scoring pipeline on a schedule, independent of the always-on
# streaming consumer (streaming/stream_processor.py) — useful as a
# batch safety net or for accounts not yet wired to Kafka/Kinesis.
resource "aws_cloudwatch_event_rule" "scorer_schedule" {
  name                = "${local.name_prefix}-scorer-schedule"
  schedule_expression = var.schedule_expression
  tags                = local.common_tags
}

resource "aws_cloudwatch_event_target" "scorer_schedule" {
  rule = aws_cloudwatch_event_rule.scorer_schedule.name
  arn  = aws_lambda_function.scorer.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.scorer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.scorer_schedule.arn
}
