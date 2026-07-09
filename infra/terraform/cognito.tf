# Production auth path for the Streamlit dashboard. dashboard/auth.py's
# hardcoded DASHBOARD_USERS env var is a dev-grade stand-in for this —
# swap it for a Cognito-backed OIDC flow (e.g. via streamlit-authenticator
# or an ALB + Cognito authenticer in front of the app) when enable_cognito_auth = true.
resource "aws_cognito_user_pool" "dashboard" {
  count = var.enable_cognito_auth ? 1 : 0
  name  = "${local.name_prefix}-dashboard-users"

  password_policy {
    minimum_length    = 12
    require_uppercase = true
    require_numbers   = true
    require_symbols   = true
  }

  schema {
    name                = "role"
    attribute_data_type = "String"
    mutable             = true
    string_attribute_constraints {
      min_length = 1
      max_length = 32
    }
  }

  tags = local.common_tags
}

resource "aws_cognito_user_pool_client" "dashboard" {
  count           = var.enable_cognito_auth ? 1 : 0
  name            = "${local.name_prefix}-dashboard-client"
  user_pool_id    = aws_cognito_user_pool.dashboard[0].id
  generate_secret = true

  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
  ]
}

output "cognito_user_pool_id" {
  value = var.enable_cognito_auth ? aws_cognito_user_pool.dashboard[0].id : null
}
