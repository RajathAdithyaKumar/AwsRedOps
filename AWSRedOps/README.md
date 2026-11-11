# AWSRedOps

**AWS IAM · IAM Identity Center · EC2 · S3 · Lambda**

A Python 3.12+ CLI for **authorized**, read-oriented security assessment of AWS identities, access configurations, and core infrastructure. A single `-a/--activity` selector drives every command. The project is designed for security engineering, tabletop preparation, preventative reviews, and explicitly approved validation in accounts you control.

> **Scope and safety:** This is not an end-to-end offensive intrusion framework. It deliberately excludes third-party device-code phishing and token capture, automated administrator backdoors, and converting arbitrary STS credentials into an authenticated console session. Identity Center login uses the AWS CLI's supported local flow. `browser-sso` opens the user's own access portal for interactive sign-in. S3 upload is dry-run by default, destination-allowlisted, and capped in size.

## Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Activities](#activities)
- [Credential cache and profiles](#credential-cache-and-profiles)
- [Authentication](#authentication)
- [Enumeration](#enumeration)
- [Privilege-risk audit](#privilege-risk-audit)
- [Guarded S3 upload](#guarded-s3-upload)
- [Output, logging, and error handling](#output-logging-and-error-handling)
- [Permission planning](#permission-planning)
- [Architecture and extension points](#architecture-and-extension-points)
- [Testing](#testing)
- [Security considerations](#security-considerations)

## Requirements

- Python **3.12 or newer** (Python 3.13 also tested).
- AWS SDK credentials or an IAM Identity Center profile with appropriate read permissions.
- `boto3` / `botocore` for AWS API access; `requests` for public AWS endpoint connectivity diagnostics; `playwright` for interactive browser portal opening.
- Optional: AWS CLI v2 for `login-sso` and a Chromium installation for `browser-sso`.

## Installation

```bash
python3.12 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -e .
# Optional for browser-sso
python -m playwright install chromium

awsredops -a connectivity --json
awsredops -h
# Or without installing the console entry point:
python AWSRedOps.py -a credential-list --json
```

## Quick start

Authenticate with an ordinary AWS profile/SDK chain, then inspect effective identity:

```bash
awsredops -a whoami --source-profile audit --region us-east-1 --json
awsredops -a auth --source-profile audit --json
awsredops -a list-iam --source-profile audit --output ./reports/iam.json
awsredops -a gather-all --source-profile audit --regions us-east-1,us-west-2 \
  --output ./reports/inventory.json --json
awsredops -a check-privesc --source-profile audit --json
```

Run in an AWS account specifically approved for your assessment. Standard AWS policy enforcement, SCPs, permission boundaries, and regional constraints continue to apply.

## Activities

| `-a` value | Function | Writes to AWS? |
|---|---|---|
| `credential-save` | Save AWS SigV4 or an explicitly supplied OIDC token record locally | No |
| `credential-list` | List local record metadata without secrets | No |
| `credential-show` | Show a record with secrets redacted by default | No |
| `credential-delete` | Delete a named local record | No |
| `auth` | Validate provided or profile AWS credentials with `sts:GetCallerIdentity` | No |
| `whoami` | Parse STS caller ARN (IAM user, assumed role, etc.) | No |
| `login-sso` | Run `aws sso login` for the operator's configured Identity Center profile | Local AWS CLI login |
| `assume-role` | Exchange existing, authorized credentials using `sts:AssumeRole` | Creates a scoped STS session |
| `browser-sso` | Launch the user's official AWS access portal in Playwright | Interactive sign-in only |
| `list-iam` | Users, roles, groups; inline and attached managed policy mapping | No |
| `list-sso` | Identity Center instances, permission sets, provisioned accounts, and user/group assignments | No |
| `gather-all` | EC2, Lambda across regions; S3 buckets and bucket region | No |
| `check-privesc` | Simulate IAM permission combinations to flag potentially excessive privileges | No |
| `push-file` | Explicitly allowlisted S3 upload; default dry run | Only with `--apply` |
| `connectivity` | Check TLS/HTTP connectivity to public AWS sign-in and STS URLs | No |

The requested attack-oriented names `phish-start`, `phish-capture`, and `add-user` are **not implemented**. They are intentionally not aliases. There is no implicit credential exfiltration, IAM user creation, policy attachment, or AWS console token federation capability.

## Credential cache and profiles

The default cache is `~/.awsredops/.aws_creds` (JSON), or a custom file via `AWSREDOPS_STORE=/private/path`. Files are atomically written with `0600` permissions. The default directory is expected to have `0700` permissions. Data is **not encrypted at rest**; if your environment requires stronger protection, prefer the default AWS provider chain, IAM Identity Center, or a secrets manager. On a multi-user system, never put raw credentials into shell history or logs.

```bash
# Save a named, explicit key set. Use a safe input method rather than shared-terminal flags.
awsredops -a credential-save --name test-audit --access-key-id AKIAEXAMPLE \
  --secret-access-key EXAMPLEONLY --region us-west-2

awsredops -a credential-list --json
awsredops -a credential-show --name test-audit
awsredops -a whoami --cred-name test-audit
awsredops -a credential-delete --name test-audit
```

`--reveal` reveals local secrets intentionally; don't use it on shared terminals or in CI logs. You can also save tokens you already legitimately own:

```bash
awsredops -a credential-save --credential-type oidc --name my-oidc \
  --access-token "$MY_OWN_OIDC_ACCESS_TOKEN" --refresh-token "$MY_OWN_OIDC_REFRESH_TOKEN" \
  --start-url https://example.awsapps.com/start
```

OIDC token records are **not** treated as AWS access keys and are never silently replayed. Use a configured AWS SSO profile when you need SigV4 credentials. The tool does not initiate device code authorization for third parties or poll for another person's tokens.

`--profile <NAME>` is **an export target** for the AWS shared credentials file (`~/.aws/credentials`), not an input profile; use `--source-profile <NAME>` for input. Only explicit credential saving and role assumption write an export profile. `--profile default` is deliberately disallowed to prevent accidental replacement of the default profile.

## Authentication

### Direct AWS validation (`auth`)

```bash
awsredops -a auth --access-key-id "$AUDIT_ACCESS_KEY_ID" \
  --secret-access-key "$AUDIT_SECRET_ACCESS_KEY" \
  --session-token "$AUDIT_SESSION_TOKEN" --region us-east-1 --json
```

The AWS SDK credential provider chain remains supported when raw flags and `--cred-name` are absent. If static credentials do not have a session token, omit `--session-token`.

### IAM Identity Center (`login-sso`)

Configure the AWS CLI v2 profile with `aws configure sso` and sign in locally:

```bash
aws configure sso --profile my-sso-audit
awsredops -a login-sso --source-profile my-sso-audit
awsredops -a whoami --source-profile my-sso-audit --json
awsredops -a browser-sso --start-url https://example.awsapps.com/start
```

`login-sso` invokes the AWS CLI's interactive sign-in, not a token-capture proxy. `browser-sso` needs `python -m playwright install chromium` and a visible desktop session. Custom IAM Identity Center portal domains can be opened in a normal browser; this CLI restricts its automated browser to the standard `*.awsapps.com` hostname.

### STS role assumption (`assume-role`)

```bash
awsredops -a assume-role --source-profile audit \
  --role-arn arn:aws:iam::123456789012:role/SecurityAuditRole \
  --external-id authorized-audit-reference \
  --role-session-name Audit2026 --duration 3600 \
  --save-name scoped-audit --profile scoped-audit

awsredops -a whoami --cred-name scoped-audit
```

`assume-role` never prints secret keys or STS tokens in its normal result. Use `--save-name` or `--profile` to explicitly persist a session. Role trust policies, session duration limits, and conditions are enforced by AWS.

## Enumeration

### IAM principals and policies

```bash
awsredops -a list-iam --source-profile audit --json
awsredops -a list-iam --source-profile audit --policy-documents \
  --output ./reports/iam-policy-documents.json
```

Maps users, roles, groups, and their attached managed and inline policies; `--policy-documents` also retrieves managed policy default versions and inline documents. List APIs are paginated. Individual policy read failures appear in the `errors` collection and do not terminate unrelated enumeration.

### IAM Identity Center (SSO)

```bash
awsredops -a list-sso --source-profile identity-center-admin \
  --region us-east-1 --max-assignments 2500 --json
```

Reads Identity Center instances, permission sets, AWS accounts provisioned for each set, account assignments, and principal display names when permitted. Assignments are limited by `--max-assignments`. A user-assigned session alone will commonly lack the `sso-admin` and `identitystore` administrative read permissions needed here; output reports partial results and per-call permission errors.

### Core AWS services (`gather-all`)

```bash
# Constrained regions
awsredops -a gather-all --source-profile audit --regions eu-west-1,eu-central-1 \
  --output ./reports/eu-inventory.json

# All currently enabled EC2 regions (can incur many API requests)
awsredops -a gather-all --source-profile audit --all-regions \
  --output ./reports/global-inventory.json
```

The inventory contains EC2 instance IDs, types, states, networks and instance profile ARNs; Lambda function names, runtimes and roles; and S3 bucket names/regions. It does **not** retrieve instance user-data, Lambda environment variable values, or bucket object contents. `--region` determines the regional API baseline; `--regions` and `--all-regions` are mutually exclusive.

## Privilege-risk audit

```bash
awsredops -a check-privesc --source-profile security-review --json
awsredops -a check-privesc --source-profile security-review \
  --principal-arn arn:aws:iam::123456789012:role/ReviewTarget
```

The auditor uses AWS `iam:SimulatePrincipalPolicy` to flag policy-level combinations including `iam:PassRole` + `ec2:RunInstances`, `iam:PassRole` + `lambda:CreateFunction`, and high-risk IAM policy administration actions. No escalation is attempted. The checks are **heuristic**: resource scoping, conditions, missing context, SCPs, permissions boundaries, trust relationships, and organizational policy may change live authorization. In particular, `ResourceArns=['*']` simulation is not a substitute for checking concrete resource ARNs.

## Guarded S3 upload

```bash
# First: preview exact file, SHA-256 hash, key and bucket, without an AWS write
awsredops -a push-file --source-profile audit --file ./fixtures/canary.txt \
  --bucket sanctioned-audit-bucket --allow-bucket sanctioned-audit-bucket \
  --key test-runs/canary.txt --json

# Then: explicitly permit that same destination
awsredops -a push-file --source-profile audit --file ./fixtures/canary.txt \
  --bucket sanctioned-audit-bucket --allow-bucket sanctioned-audit-bucket \
  --key test-runs/canary.txt --apply --json
```

The operation requires an explicit bucket allowlist match, rejects symlinked source files, enforces a configurable file-size cap (default 10 MiB; max 100 MiB), and labels the uploaded object with an `awsredops=authorized-assessment` metadata key. Use only synthetic assessment files and preapproved buckets. It does not download S3 content or implement bulk data movement.

## Output, logging, and error handling

Use `--json` for a structured envelope `{ "activity": ..., "success": ..., "result": ... }`. Without it, normal output includes a short activity banner followed by formatted results. `--output path.json` exports the structured result to a private `0600` file and refuses a symlink at the destination.

`-d/--debug` enables selected boto3 endpoint and urllib3 request diagnostics with **best-effort** masking and suppression of signing/parsing traces. Debug output may still contain sensitive metadata: never forward it to an untrusted logging system. Errors such as `AccessDenied`, `ExpiredToken`, throttling and missing AWS credentials have contextual descriptions; list operations preserve partial results with an `errors` array.

Typical exit codes are `0` successful execution, `2` expected or AWS error, `1` unexpected failure, and `130` interruption. A successful inventory may contain partial errors; check its `errors` array instead of relying exclusively on the process exit code.

## Permission planning

Prefer a dedicated account or role with narrow, temporary permissions. Use AWS policy scoping and CloudTrail to record audit activity. The following actions may be needed depending on modules and AWS's permission dependencies:

| Activity | Representative IAM permission(s) |
|---|---|
| `auth`, `whoami` | `sts:GetCallerIdentity` |
| `assume-role` | `sts:AssumeRole`, target trust policy |
| `list-iam` | `iam:ListUsers`, `iam:ListRoles`, `iam:ListGroups`, `iam:ListAttached*Policies`, `iam:List*Policies`, optionally `iam:Get*Policy*` |
| `list-sso` | `sso:ListInstances`, `sso:ListPermissionSets`, `sso:DescribePermissionSet`, `sso:ListAccountAssignments`, `sso:ListAccountsForProvisionedPermissionSet`, `identitystore:DescribeUser`, `identitystore:DescribeGroup` |
| `gather-all` | `ec2:DescribeRegions`, `ec2:DescribeInstances`, `lambda:ListFunctions`, `s3:ListAllMyBuckets`, `s3:GetBucketLocation` |
| `check-privesc` | `iam:SimulatePrincipalPolicy`; `iam:GetRole` for assumed-role identity normalization |
| `push-file --apply` | `s3:PutObject` scoped to the allowlisted bucket/key |

This table is illustrative, not a drop-in IAM policy: verify actions, ARNs, condition keys, org controls, and AWS regional/service availability in your own environment.

## Architecture and extension points

```text
AWSRedOps/
├── AWSRedOps.py               # direct script entry
├── pyproject.toml             # package and console_script
├── requirements.txt
├── README.md
├── awsredops/
│   ├── __init__.py
│   ├── __main__.py             # python -m awsredops
│   ├── cli.py                  # argparse + activity registry + errors
│   ├── errors.py               # actionable AWS API errors
│   ├── utils.py                # paginator, ARN parser, JSON export
│   ├── store.py                # private atomic credential cache
│   ├── session.py              # boto3 resolution + shared profile export
│   ├── auth.py                 # STS identity and role assumption
│   ├── browser.py              # own-user Playwright portal login
│   ├── diagnostics.py          # requests public connectivity test
│   ├── iam.py                  # IAM enumeration
│   ├── sso.py                  # Identity Center enumeration
│   ├── inventory.py            # EC2/Lambda/S3 inventory
│   ├── risk.py                 # IAM policy risk simulation
│   └── s3ops.py                # allowlisted S3 test upload
└── tests/
    └── test_core.py           # credential cache, STS, S3 guard, simulator
```

The activity registry permits new modules without changing the entry point:

```python
from awsredops.cli import activity

@activity("example-readonly-check")
def example_readonly_check(args, store):
    # Uses the SDK's configured/authorized credential source.
    return {"status": "add a new passive audit module here"}
```

Place the activity in `cli.py` (or import a registering module before parsing). Prefer paginators, explicit region handling, resource caps, partial-error reporting, and no side effects by default. The package includes a Python 3.12 (PEP 701) f-string form where expression keys use the same quote style as their surrounding string.

## Testing

```bash
python -m pip install -e '.[test]'
python -m pytest -q
python -m compileall -q awsredops
```

Unit tests are fully local and use mocks for AWS calls. They do not contact AWS or validate actual AWS permissions, network reachability, AWS SSO configuration, or installed Chromium binaries. Run separate, approved integration tests in a non-production test account to validate service access and real profiles.

## Security considerations

- Scope every execution to accounts and roles where you have written assessment authorization. Log intended regions, account IDs and allowed S3 destinations.
- The cache is **plaintext** despite private filesystem permissions. Prefer short-lived IAM Identity Center or STS credentials and restrict access to the host.
- Avoid raw tokens on the command line: shells and process monitors may capture them. Avoid `--reveal` or `-d` in telemetry-captured environments.
- Review `--output` exports before sharing them; IAM policy documents and infrastructure metadata can be sensitive.
- Do not mistake a policy simulator finding for verified exploitability. Validate conditions, attached boundaries, SCPs and resource ARN context.
- Where high-assurance cryptographic storage, enterprise audit logs, or change-approval workflows are required, integrate a dedicated secrets manager and approval system rather than relying on this sample's local cache.

### AWS service references

- [STS GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html)
- [Boto3 IAM](https://docs.aws.amazon.com/boto3/latest/reference/services/iam.html)
- [Boto3 IAM policy simulation](https://docs.aws.amazon.com/boto3/latest/reference/services/iam/client/simulate_principal_policy.html)
- [Boto3 SSO Admin](https://docs.aws.amazon.com/boto3/latest/reference/services/sso-admin.html)
- [AWS IAM Identity Center authentication](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sso.html)
- [Boto3 paginators](https://boto3.amazonaws.com/v1/documentation/api/latest/guide/paginators.html)

## License

MIT. This code is provided as an authorization-scoped assessment toolkit; security controls and integration testing are the responsibility of the deployment environment.
