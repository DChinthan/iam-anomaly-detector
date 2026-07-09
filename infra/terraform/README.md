# Terraform module — IAM Anomaly Detector

Provisions the production AWS footprint for the pipeline: a DynamoDB results
table, per-region CloudWatch log groups, a container-image Lambda that runs
the scoring pipeline on a schedule, its least-privilege IAM role, and
(optionally) a Cognito user pool for the dashboard's production auth path.

This is IaC scaffolding, not a `terraform apply`-and-forget black box —
review `variables.tf` and adjust for your account before applying.

## Deploy

```bash
# 1. Build and push the scoring Lambda's container image
cd ../../                      # project root
aws ecr create-repository --repository-name iam-anomaly-scorer
docker build -f infra/lambda/scorer/Dockerfile -t iam-anomaly-scorer .
docker tag iam-anomaly-scorer:latest <account_id>.dkr.ecr.<region>.amazonaws.com/iam-anomaly-scorer:latest
aws ecr get-login-password | docker login --username AWS --password-stdin <account_id>.dkr.ecr.<region>.amazonaws.com
docker push <account_id>.dkr.ecr.<region>.amazonaws.com/iam-anomaly-scorer:latest

# 2. Plan and apply
cd infra/terraform
terraform init
terraform plan  -var="scorer_image_uri=<account_id>.dkr.ecr.<region>.amazonaws.com/iam-anomaly-scorer:latest"
terraform apply -var="scorer_image_uri=<account_id>.dkr.ecr.<region>.amazonaws.com/iam-anomaly-scorer:latest"
```

## What it creates

| Resource | Purpose |
|---|---|
| `aws_dynamodb_table.anomaly_results` | Same schema as `aws/dynamodb_store.py` — `user_id` PK, `analysis_timestamp` SK |
| `aws_cloudwatch_log_group.cloudtrail` (per region) | Matches `AWS_REGIONS` multi-region ingestion in `aws/cloudwatch_client.py` |
| `aws_lambda_function.scorer` | Container-image Lambda running `infra/lambda/scorer/handler.py` on a schedule |
| `aws_iam_role.scorer_lambda` | Least-privilege: CloudWatch read, DynamoDB read/write, Secrets Manager read (only if a Claude key ARN is set) |
| `aws_cognito_user_pool.dashboard` (optional, `enable_cognito_auth=true`) | Production auth path referenced by `dashboard/auth.py`'s docstring |

## Notes / known gaps

- `flagged` is stored as a native bool by `DynamoDBStore`; the `flagged-index` GSI here types it as a string. Align one or the other before relying on the GSI in production.
- The scoring Lambda handles the scheduled **batch** path; the always-on **streaming** path (`streaming/stream_processor.py`) is meant to run as a long-lived consumer (ECS/Fargate task or EC2), not Lambda — Lambda's max 15-minute runtime doesn't fit a persistent Kafka consumer.
- No VPC/networking module included — add one if the Lambda needs to reach a VPC-only RDS/MSK cluster.
