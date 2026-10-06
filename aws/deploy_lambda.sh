#!/usr/bin/env bash
# Deploy SentinelGraph AWS Trigger within AWS Free Tier (<$0.01 / within $90 credit budget)
set -e

FUNCTION_NAME="SentinelGraph-Trigger"
ROLE_NAME="SentinelGraph-Lambda-Execution-Role"
BACKEND_URL="${1:-http://127.0.0.1:8000/alerts}"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"

echo "================================================================="
echo "Deploying AWS Lambda Trigger for SentinelGraph ($REGION)"
echo "Target Webhook: $BACKEND_URL"
echo "Cost: \$0.00 (Free Tier 1M requests/mo, 100% within \$90 credit budget)"
echo "================================================================="

cd "$(dirname "$0")"
zip -j lambda_trigger.zip lambda_trigger.py

# Check if role exists or create minimal execution role
if ! aws iam get-role --role-name "$ROLE_NAME" >/dev/null 2>&1; then
  echo "Creating IAM Role: $ROLE_NAME..."
  aws iam create-role \
    --role-name "$ROLE_NAME" \
    --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
  aws iam attach-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
  echo "Waiting 10s for IAM propagation..."
  sleep 10
fi

ROLE_ARN=$(aws iam get-role --role-name "$ROLE_NAME" --query "Role.Arn" --output text)

# Check if function exists
if aws lambda get-function --function-name "$FUNCTION_NAME" --region "$REGION" >/dev/null 2>&1; then
  echo "Updating existing function code & configuration..."
  aws lambda update-function-code \
    --function-name "$FUNCTION_NAME" \
    --zip-file fileb://lambda_trigger.zip \
    --region "$REGION" >/dev/null
  aws lambda update-function-configuration \
    --function-name "$FUNCTION_NAME" \
    --environment "Variables={BACKEND_URL=$BACKEND_URL}" \
    --region "$REGION" >/dev/null
else
  echo "Creating new AWS Lambda function..."
  aws lambda create-function \
    --function-name "$FUNCTION_NAME" \
    --runtime python3.12 \
    --handler lambda_trigger.lambda_handler \
    --role "$ROLE_ARN" \
    --zip-file fileb://lambda_trigger.zip \
    --environment "Variables={BACKEND_URL=$BACKEND_URL}" \
    --timeout 15 \
    --region "$REGION" >/dev/null
fi

rm -f lambda_trigger.zip
echo "================================================================="
echo "AWS Lambda Trigger successfully deployed!"
echo "To invoke manually:"
echo "  aws lambda invoke --function-name $FUNCTION_NAME --region $REGION response.json"
echo "================================================================="
