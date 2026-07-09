# Least-privilege execution role for the scoring Lambda — the app's own
# access model, tying back to the RBAC work on the dashboard side.
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scorer_lambda" {
  name               = "${local.name_prefix}-scorer-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
  tags               = local.common_tags
}

data "aws_iam_policy_document" "scorer_permissions" {
  statement {
    sid       = "WriteLogs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.scorer_lambda.arn}:*"]
  }

  statement {
    sid = "ReadCloudTrailLogs"
    actions = [
      "logs:StartQuery",
      "logs:GetQueryResults",
      "logs:StopQuery",
      "logs:FilterLogEvents",
    ]
    resources = [for lg in aws_cloudwatch_log_group.cloudtrail : "${lg.arn}:*"]
  }

  statement {
    sid = "ReadWriteResultsTable"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:GetItem",
      "dynamodb:Query",
      "dynamodb:Scan",
      "dynamodb:BatchWriteItem",
    ]
    resources = [
      aws_dynamodb_table.anomaly_results.arn,
      "${aws_dynamodb_table.anomaly_results.arn}/index/*",
    ]
  }

  dynamic "statement" {
    for_each = var.anthropic_api_key_secret_arn == "" ? [] : [1]
    content {
      sid       = "ReadAnthropicKey"
      actions   = ["secretsmanager:GetSecretValue"]
      resources = [var.anthropic_api_key_secret_arn]
    }
  }
}

resource "aws_iam_role_policy" "scorer_permissions" {
  name   = "${local.name_prefix}-scorer-permissions"
  role   = aws_iam_role.scorer_lambda.id
  policy = data.aws_iam_policy_document.scorer_permissions.json
}
