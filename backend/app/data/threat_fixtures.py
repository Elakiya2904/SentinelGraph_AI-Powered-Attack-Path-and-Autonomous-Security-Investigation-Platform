from __future__ import annotations

from datetime import datetime, timezone

def _fallback_logs():
    now = datetime.now(timezone.utc).isoformat()
    return [
        {
            "id": "log-001",
            "timestamp": now,
            "host": "victim",
            "line": f"{now} AUTH_FAIL src=198.51.100.42 user=root service=ssh reason=invalid_credentials",
        },
        {
            "id": "log-002",
            "timestamp": now,
            "host": "victim",
            "line": f"{now} AUTH_FAIL src=198.51.100.42 user=admin service=ssh reason=invalid_credentials",
        },
        {
            "id": "log-003",
            "timestamp": now,
            "host": "victim",
            "line": f"{now} AUTH_FAIL src=198.51.100.42 user=devops service=ssh reason=invalid_credentials",
        },
        {
            "id": "log-004",
            "timestamp": now,
            "host": "victim",
            "line": f"{now} AUTH_SUCCESS src=198.51.100.42 user=devops service=ssh action=login",
        },
    ]

LAB_LOGS = _fallback_logs()

CVE_FIXTURES = {
    "CVE-2024-3400": {
        "id": "CVE-2024-3400",
        "severity": 9.8,
        "epss": 0.91,
        "cisa_kev": True,
        "summary": "Palo Alto Networks PAN-OS GlobalProtect command injection vulnerability enabling unauthenticated remote code execution.",
        "evidence_id": "cve-CVE-2024-3400",
    },
    "CVE-2021-44228": {
        "id": "CVE-2021-44228",
        "severity": 10.0,
        "epss": 0.94,
        "cisa_kev": True,
        "summary": "Apache Log4j2 JNDI remote code execution vulnerability (Log4Shell) enabling arbitrary code execution on backend cluster.",
        "evidence_id": "cve-CVE-2021-44228",
    },
    "CVE-2023-23397": {
        "id": "CVE-2023-23397",
        "severity": 9.8,
        "epss": 0.72,
        "cisa_kev": True,
        "summary": "Microsoft Outlook NTLM credential-theft privilege escalation vulnerability enabling unauthorized domain lateral movement.",
        "evidence_id": "cve-CVE-2023-23397",
    },
    "CVE-2024-3094": {
        "id": "CVE-2024-3094",
        "severity": 10.0,
        "epss": 0.62,
        "cisa_kev": False,
        "summary": "XZ Utils / liblzma malicious backdoor in upstream distribution allowing unauthorized remote SSH authentication bypass.",
        "evidence_id": "cve-CVE-2024-3094",
    },
}

ATTACK_TECHNIQUES = {
    "brute force": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "evidence_id": "attack-t1110",
        "summary": "Repeated authentication attempts against exposed service credentials.",
    },
    "ssh_brute_force_failed_login": {
        "id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "evidence_id": "attack-t1110",
        "summary": "Repeated failed authentication attempts against SSH bastion service.",
    },
    "ssh_success_after_failures": {
        "id": "T1110.001",
        "name": "Password Guessing",
        "tactic": "Credential Access",
        "evidence_id": "attack-t1110",
        "summary": "Successful authentication achieved following repeated credential brute force attempts.",
    },
    "web_sqli_injection_attempt": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application (SQLi)",
        "tactic": "Initial Access",
        "evidence_id": "attack-t1190-sqli",
        "summary": "SQL injection payload (' OR 1=1) targeting public-facing web portal input parameters.",
    },
    "web_path_traversal_attempt": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application (Directory Traversal)",
        "tactic": "Initial Access",
        "evidence_id": "attack-t1190-traversal",
        "summary": "Path traversal sequence (../) targeting server filesystem boundaries.",
    },
    "web_exploit_attempt": {
        "id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "evidence_id": "attack-t1190",
        "summary": "Exploitation attempt against public-facing web portal service.",
    },
    "web_request_observed": {
        "id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "evidence_id": "attack-t1046",
        "summary": "Perimeter HTTP service request observed by edge sensor.",
    },
    "aws_guardduty_unauthorized_access": {
        "id": "T1110",
        "name": "Brute Force (Cloud Ingress)",
        "tactic": "Credential Access",
        "evidence_id": "attack-t1110-aws",
        "summary": "AWS GuardDuty detected credential brute-force attempts against EC2 perimeter instance via CloudTrail logs.",
    },
}
