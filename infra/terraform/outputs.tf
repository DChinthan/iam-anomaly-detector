output "scorer_lambda_name" {
  value = aws_lambda_function.scorer.function_name
}

output "scorer_lambda_role_arn" {
  value = aws_iam_role.scorer_lambda.arn
}

output "cloudtrail_log_groups" {
  value = { for r, lg in aws_cloudwatch_log_group.cloudtrail : r => lg.name }
}
