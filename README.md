# Ghost Utility Drift Attestor

Ghost Utility Drift Attestor is a sealed, in-account AWS utility that produces a monthly **Change-Only Security Attestation** report. It runs entirely inside your AWS account, performs **read-only** posture checks, and writes **PDF + JSON** reports to your S3 bucket. No vendor SaaS, no external calls, and no data leaves your account.

## What it does
- Collects a small, focused set of **IAM**, **Exposure**, and **Logging** signals.
- Compares the latest snapshot to the previous snapshot in **your S3** and reports **only the changes**.
- Produces a human-readable **PDF** and a machine-readable **JSON** report.
- Applies customer-owned **exceptions/suppressions** stored in S3.
- Runs monthly on an EventBridge schedule inside ECS Fargate.

## What it does NOT do (non-claims)
- No remediation, auto-fixes, or ticketing.
- No full compliance checks.
- No guarantees of security, compliance, or recoverability.
- No data exfiltration or vendor callbacks.

## Assumptions (explicit)
- You provide an **S3 bucket name** and prefix for outputs **or** you allow Terraform to create the bucket.
- You provide **VPC subnet IDs + security group IDs** for Fargate **or** you allow Terraform to discover the default VPC/subnets.
- The AWS region is configurable.
- Runtime: **Python 3.12** in a small container.
- PDF generation uses **ReportLab** (no headless browser dependencies).

## v1 Checks (tight scope)
### IAM Drift (delta-only, Top 10)
- New or changed IAM policies attached to users/roles/groups.
- New trust policy changes on roles (AssumeRole principals changed).
- New access keys created (presence + age).
- Highlights any effective “admin-ish” grants (wildcard actions/resources, AdministratorAccess attachment).

### Exposure Drift (delta-only, Top 10)
- Security groups: new inbound rules from **0.0.0.0/0** or **::/0** on risky ports (22, 3389, 80, 443, 3306, 5432, 6379).
- S3: PublicAccessBlock changes; bucket policy public statements (best-effort heuristic, clearly labeled).

### Logging Drift (delta-only, Top 10)
- CloudTrail: enabled trails, multi-region setting, log file validation flag (report changes).
- If Config is enabled: report recorder/status change (best-effort, clearly labeled).

## Severity model (deterministic)
- **Critical**: new admin-ish grant; new public DB port exposure; CloudTrail disabled.
- **High**: new public SSH/RDP; new wildcard policy attachment; public S3 policy heuristic hit.
- **Medium**: new public 80/443; CloudTrail validation turned off; Config disabled.
- **Low**: informational changes.

## Report outputs
- JSON: `s3://{bucket}/{prefix}/reports/YYYY-MM/report.json`
- PDF: `s3://{bucket}/{prefix}/reports/YYYY-MM/report.pdf`
- State: `s3://{bucket}/{prefix}/state/latest.json`
- Exceptions: `s3://{bucket}/{prefix}/config/exceptions.json` (optional)

## Exceptions / suppressions
Create `exceptions.json` in S3 at `config/exceptions.json` with entries like:

```json
{
  "suppressions": [
    {
      "id": "iam:admin-attachment:role/AppRole:AdministratorAccess",
      "reason": "Approved admin role"
    },
    {
      "match": "sg-123",
      "reason": "Temporary firewall change"
    }
  ]
}
```

- `id` matches a change ID exactly.
- `match` suppresses any change whose description or evidence contains the substring.

Suppressed changes are **removed from the main report** and listed in the Appendix.

## Local development
```bash
pip install -r requirements.txt
pytest
python -m attestor.main --fixtures
```

The fixture run produces JSON matching `tests/fixtures/expected_report.json` and generates a PDF locally.

## 5-minute deploy (Terraform)
```bash
cd infra/terraform
terraform init
terraform apply \
  -var="region=us-east-1" \
  -var="bucket_name=your-bucket" \
  -var="prefix=ghost-utility" \
  -var="create_bucket=false" \
  -var='subnet_ids=["subnet-abc","subnet-def"]' \
  -var='security_group_ids=["sg-123"]'
```

### Verify it’s running
- Check CloudWatch Logs for the ECS task output.
- Confirm new objects under `s3://{bucket}/{prefix}/reports/YYYY-MM/`.

### Uninstall
```bash
cd infra/terraform
terraform destroy
```

## How to run tests
```bash
pytest
```

## How to deploy
See **5-minute deploy (Terraform)** above.
