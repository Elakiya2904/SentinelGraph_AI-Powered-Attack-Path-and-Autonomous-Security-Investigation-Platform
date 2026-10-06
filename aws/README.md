# AWS GuardDuty & Lambda Integration for SentinelGraph

This integration connects AWS Cloud Security telemetry (Amazon GuardDuty, CloudTrail, EventBridge) directly into SentinelGraph's graph-based investigation pipeline.

---

## 💰 Budget & Cost Breakdown ($90 Credits Protection)

This architecture is specifically designed to run **100% within the AWS Free Tier**, consuming essentially **$0.00** of your $90 AWS credits:

| AWS Service | Free Tier Allowance | SentinelGraph Demo Usage | Estimated Spend |
| :--- | :--- | :--- | :--- |
| **AWS Lambda** | 1,000,000 free requests/month | ~100 demo invocations | **$0.00** |
| **Amazon EventBridge** | 14,000,000 free events/month | ~100 demo events | **$0.00** |
| **Amazon CloudWatch** | 5 GB free ingestion/month | < 1 MB log lines | **$0.00** |
| **Amazon GuardDuty** | 30-day Free Trial for new accounts | Standard finding forwarding | **$0.00 – $0.02** |
| **Lambda Function URL** | Built-in free HTTPS endpoint | No API Gateway fee needed | **$0.00** |
| **TOTAL** | — | — | **<$0.05 (leaves >$89.95 of credits)** |

---

## 🚀 Fast 1-Command Deployment

If you have the AWS CLI configured on your machine:

### On Linux / macOS / WSL:
```bash
# Deploys Lambda function to us-east-1 and sets target webhook
./aws/deploy_lambda.sh http://YOUR_BACKEND_IP:8000/alerts
```

### On Windows PowerShell:
```powershell
.\aws\deploy_lambda.ps1 -BackendUrl "http://YOUR_BACKEND_IP:8000/alerts"
```

---

## 🖥️ Manual AWS Console Setup (No CLI needed)

1. Go to **AWS Lambda Console** → Click **Create function**.
2. Select **Author from scratch**, Function name: `SentinelGraph-Trigger`, Runtime: `Python 3.12`.
3. In the code editor, paste the contents of `aws/lambda_trigger.py` and click **Deploy**.
4. Go to **Configuration** → **Environment variables** → Add:
   - `BACKEND_URL`: `http://<your-host>:8000/alerts` (or public ngrok / domain URL).
5. Click **Test** → Create a test event with `{}` → Click **Test** to dispatch the alert to SentinelGraph!

---

## ⚡ Live Demo Testing (3 Ways)

### 1. From the SentinelGraph Web UI:
Click the **"☁️ Trigger AWS Alert"** button in the dashboard topbar. This sends an authentic AWS GuardDuty finding (`UnauthorizedAccess:EC2/SSHBruteForce`) with CloudTrail telemetry.

### 2. From Terminal / PowerShell:
```powershell
.\demo.ps1 aws
```
or bash:
```bash
./demo.sh aws
```

### 3. Direct Python Script:
```bash
BACKEND_URL=http://127.0.0.1:8000/alerts python aws/lambda_trigger.py
```

SentinelGraph will immediately correlate the EC2 instance `i-0a89bc44d12` to perimeter node `vpn-bastion`, verify the CloudTrail log evidence, identify reachability to the Production Database, and propose containment authorization.
