# Mirrors aws/dynamodb_store.py: partition key user_id, sort key analysis_timestamp.
resource "aws_dynamodb_table" "anomaly_results" {
  name         = "${local.name_prefix}-results"
  billing_mode = var.dynamodb_billing_mode
  hash_key     = "user_id"
  range_key    = "analysis_timestamp"

  attribute {
    name = "user_id"
    type = "S"
  }

  attribute {
    name = "analysis_timestamp"
    type = "S"
  }

  # Lets get_flagged() query instead of scan in production.
  global_secondary_index {
    name            = "flagged-index"
    hash_key        = "flagged"
    range_key       = "analysis_timestamp"
    projection_type = "ALL"
  }

  attribute {
    name = "flagged"
    type = "S" # DynamoDB GSI keys can't be BOOL; store as "true"/"false" string
  }

  point_in_time_recovery {
    enabled = var.environment == "prod"
  }

  tags = local.common_tags
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.anomaly_results.name
}
