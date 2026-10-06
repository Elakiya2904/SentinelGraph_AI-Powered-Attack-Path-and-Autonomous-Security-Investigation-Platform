# Deploy SentinelGraph AWS Trigger within AWS Free Tier (<$0.01 / within $90 credit budget)
param(
    [string]$BackendUrl = "http://127.0.0.1:8000/alerts",
    [string]$Region = "us-east-1"
)

$ErrorActionPreference = "Stop"
$FunctionName = "SentinelGraph-Trigger"
$RoleName = "SentinelGraph-Lambda-Execution-Role"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Deploying AWS Lambda Trigger for SentinelGraph ($Region)" -ForegroundColor Cyan
Write-Host "Target Webhook: $BackendUrl" -ForegroundColor White
Write-Host "Cost: `$0.00 (Free Tier 1M requests/mo, 100% within `$90 credit budget)" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$zipPath = Join-Path $scriptDir "lambda_trigger.zip"
$pyPath = Join-Path $scriptDir "lambda_trigger.py"

if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path $pyPath -DestinationPath $zipPath -Force

# Verify AWS CLI is available
try {
    $null = aws --version
} catch {
    Write-Error "AWS CLI is not installed or not in PATH. Please install AWS CLI or configure credentials."
    exit 1
}

# Ensure Execution Role exists
$roleArn = $null
try {
    $roleJson = aws iam get-role --role-name $RoleName --output json 2>$null | ConvertFrom-Json
    $roleArn = $roleJson.Role.Arn
} catch {
    Write-Host "Creating IAM Role: $RoleName..." -ForegroundColor Yellow
    $assumePolicy = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    $roleJson = aws iam create-role --role-name $RoleName --assume-role-policy-document $assumePolicy --output json | ConvertFrom-Json
    $roleArn = $roleJson.Role.Arn
    $null = aws iam attach-role-policy --role-name $RoleName --policy-arn "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    Write-Host "Waiting 10s for IAM propagation..." -ForegroundColor Yellow
    Start-Sleep -Seconds 10
}

# Deploy or update Lambda
$exists = $false
try {
    $null = aws lambda get-function --function-name $FunctionName --region $Region 2>$null
    $exists = $true
} catch {
    $exists = $false
}

if ($exists) {
    Write-Host "Updating existing function..." -ForegroundColor Yellow
    $null = aws lambda update-function-code --function-name $FunctionName --zip-file "fileb://$zipPath" --region $Region
    $null = aws lambda update-function-configuration --function-name $FunctionName --environment "Variables={BACKEND_URL=$BackendUrl}" --region $Region
} else {
    Write-Host "Creating new AWS Lambda function..." -ForegroundColor Yellow
    $null = aws lambda create-function --function-name $FunctionName --runtime python3.12 --handler lambda_trigger.lambda_handler --role $roleArn --zip-file "fileb://$zipPath" --environment "Variables={BACKEND_URL=$BackendUrl}" --timeout 15 --region $Region
}

if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

Write-Host "`n=================================================================" -ForegroundColor Green
Write-Host "AWS Lambda Trigger successfully deployed!" -ForegroundColor Green
Write-Host "To test invoke from terminal:" -ForegroundColor White
Write-Host "  aws lambda invoke --function-name $FunctionName --region $Region response.json" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Green
