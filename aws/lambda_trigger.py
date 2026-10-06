import json
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone

BACKEND_URL = os.environ.get("BACKEND_URL", "http://127.0.0.1:8000/alerts")


def build_payload(event: dict | None = None) -> dict:
    event = event or {}
    detail = event.get("detail", {})
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source_host": "vpn-bastion",
        "rule": detail.get("type", "aws_guardduty_unauthorized_access"),
        "severity": int(detail.get("severity", 9)),
        "raw_log_reference": "aws:cloudtrail:failed-login:arn:aws:ec2:us-east-1:123456789012:instance/i-0a89bc44d12",
        "detector": "aws-guard-duty",
        "source": "aws-production",
        "raw_payload": {
            "account_id": event.get("account", "123456789012"),
            "region": event.get("region", "us-east-1"),
            "resource": "arn:aws:ec2:us-east-1:123456789012:instance/i-0a89bc44d12",
            "finding_type": "UnauthorizedAccess:EC2/SSHBruteForce",
            "source_ip": "13.58.13.54",
            "target_port": 22,
            "attempt_count": 3,
            "user": "admin",
        },
    }


def lambda_handler(event, context):
    payload = build_payload(event if isinstance(event, dict) else None)

    request = urllib.request.Request(
        BACKEND_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read().decode("utf-8")
            return {
                "statusCode": response.status,
                "headers": {"Content-Type": "application/json"},
                "body": body,
            }
    except urllib.error.HTTPError as exc:
        error_body = exc.read().decode("utf-8", errors="replace")
        return {
            "statusCode": exc.code,
            "headers": {"Content-Type": "application/json"},
            "body": error_body,
        }
    except Exception as exc:  # pragma: no cover - Lambda error path
        return {
            "statusCode": 500,
            "headers": {"Content-Type": "application/json"},
            "body": json.dumps({"error": str(exc)}),
        }


if __name__ == "__main__":
    print(json.dumps(lambda_handler({}, None), indent=2))
