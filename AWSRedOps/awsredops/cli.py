"""Single -a/--activity CLI entrypoint with a modular activity registry."""
from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Any, Callable

from botocore.exceptions import BotoCoreError, ClientError

from .auth import Authentication, aws_cli_sso_login
from .browser import open_sso_portal
from .diagnostics import connectivity
from .errors import OpsError, explain_aws_error
from .iam import IAMInventory
from .inventory import InfrastructureInventory
from .risk import PrivilegeRiskAudit
from .s3ops import GuardedS3Uploader
from .session import persist_profile, session_from_args
from .sso import SSOInventory
from .store import CredentialStore
from .utils import dumps, safe_export

Activity = Callable[[argparse.Namespace, CredentialStore], dict[str, Any]]
ACTIVITIES: dict[str, Activity] = {}


def activity(name: str) -> Callable[[Activity], Activity]:
    def decorator(func: Activity) -> Activity:
        ACTIVITIES[name] = func
        return func
    return decorator


def require(value: Any, flag: str) -> Any:
    if not value:
        raise OpsError(f"{flag} is required for this activity")
    return value


def make_session(args: argparse.Namespace, store: CredentialStore) -> Any:
    return session_from_args(args, store)


@activity("connectivity")
def check_connectivity(args: argparse.Namespace, store: CredentialStore) -> dict[str, Any]:
    return {"endpoints": connectivity()}


@activity("credential-save")
def save_credential(args: argparse.Namespace, store: CredentialStore) -> dict[str, Any]:
    name = require(args.name, "--name")
    if args.credential_type == "oidc":
        record = {"type": "oidc", "access_token": require(args.access_token, "--access-token"),
                  "refresh_token": args.refresh_token, "region": args.region or "us-east-1", "start_url": args.start_url}
        if args.profile:
            raise OpsError("--profile only exports AWS SigV4 credentials, not OIDC tokens")
    else:
        record = {"type": "aws", "access_key_id": require(args.access_key_id, "--access-key-id"),
                  "secret_access_key": require(args.secret_access_key, "--secret-access-key"),
                  "session_token": args.session_token, "region": args.region or "us-east-1"}
        if args.profile:
            persist_profile(args.profile, record)
    store.save(name, record)
    return {"saved_as": name, "type": record["type"], "path": str(store.path), "profile_name": args.profile}


@activity("credential-list")
def list_credential(args: argparse.Namespace, store: CredentialStore) -> dict[str, Any]:
    return {"credentials": store.names(), "path": str(store.path)}


@activity("credential-show")
def show_credential(args: argparse.Namespace, store: CredentialStore) -> dict[str, Any]:
    return store.show(require(args.name, "--name"), reveal=args.reveal)


@activity("credential-delete")
def delete_credential(args: argparse.Namespace, store: CredentialStore) -> dict[str, Any]:
    name = require(args.name, "--name")
    return {"name": name, "deleted": store.delete(name)}


@activity("auth")
def validate(args: argparse.Namespace, store: CredentialStore) -> dict[str, Any]:
    session = make_session(args, store)
    result = Authentication(session, store).validate()
    if args.save_name:
        if not (args.access_key_id and args.secret_access_key):
            raise OpsError("--save-name on auth requires explicit --access-key-id and --secret-access-key")
        store.save(args.save_name, {"type": "aws", "access_key_id": args.access_key_id, "secret_access_key": args.secret_access_key, "session_token": args.session_token, "region": args.region or session.region_name or "us-east-1"})
        result["saved_as"] = args.save_name
    return result


@activity("whoami")
def whoami(args: argparse.Namespace, store: CredentialStore) -> dict[str, Any]:
    return Authentication(make_session(args, store), store).whoami()


@activity("login-sso")
def login_sso(args: argparse.Namespace, store: CredentialStore) -> dict[str, Any]:
    return aws_cli_sso_login(require(args.source_profile, "--source-profile"))


@activity("assume-role")
def assume_role(args: argparse.Namespace, store: CredentialStore) -> dict[str, Any]:
    auth = Authentication(make_session(args, store), store)
    outcome = auth.assume_role(require(args.role_arn, "--role-arn"), args.role_session_name, args.external_id, args.duration)
    return auth.persist_assumed(outcome, args.save_name, args.profile)


@activity("browser-sso")
def browser_sso(args: argparse.Namespace, store: CredentialStore) -> dict[str, Any]:
    return open_sso_portal(require(args.start_url, "--start-url"), headless=args.headless)


@activity("list-iam")
def list_iam(args: argparse.Namespace, store: CredentialStore) -> dict[str, Any]:
    return IAMInventory(make_session(args, store)).collect(include_documents=args.policy_documents)


@activity("list-sso")
def list_sso(args: argparse.Namespace, store: CredentialStore) -> dict[str, Any]:
    session = make_session(args, store)
    return SSOInventory(session, args.region or session.region_name or "us-east-1").collect(max_assignments=args.max_assignments)


@activity("gather-all")
def gather_all(args: argparse.Namespace, store: CredentialStore) -> dict[str, Any]:
    session = make_session(args, store)
    region = args.region or session.region_name or "us-east-1"
    inventory = InfrastructureInventory(session, region)
    selected = [s.strip() for s in args.regions.split(",") if s.strip()] if args.regions else None
    return inventory.collect(inventory.regions(selected, args.all_regions))


@activity("check-privesc")
def check_privesc(args: argparse.Namespace, store: CredentialStore) -> dict[str, Any]:
    return PrivilegeRiskAudit(make_session(args, store)).collect(args.principal_arn)


@activity("push-file")
def push_file(args: argparse.Namespace, store: CredentialStore) -> dict[str, Any]:
    return GuardedS3Uploader(make_session(args, store)).run(
        source=require(args.file, "--file"), bucket=require(args.bucket, "--bucket"),
        key=require(args.key, "--key"), allowed_bucket=require(args.allow_bucket, "--allow-bucket"),
        apply=args.apply, max_mb=args.max_upload_mb,
    )


class RedactingFormatter(logging.Formatter):
    """Best-effort redaction. Avoid production wire logging on shared terminals."""
    CREDENTIAL_PATTERNS = [
        re.compile(r"(?i)((?:secret_access_key|aws_secret_access_key|access_token|refresh_token|session_token|x-amz-security-token|client_secret)['\" ]*[:=]['\" ]*)([^'\"\s,}]+)"),
        re.compile(r"(?i)(authorization['\" ]*[:=]['\" ]*)([^'\"\n]+)"),
        re.compile(r"(?i)((?:authorization|x-amz-security-token)['\"]?\s*:\s*(?:b)?['\"])[^'\"]+(['\"])") ,
        re.compile(r"(AKIA|ASIA)[A-Z0-9]{16}"),
    ]

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        # Botocore's PreparedRequest repr can include sensitive signing headers.
        # Redact the entire mapping before applying individual-value heuristics.
        msg = re.sub(r"(?i)(headers=)\{[^}]*\}", r"\1[REDACTED_HEADERS]", msg)
        for pattern in self.CREDENTIAL_PATTERNS[:2]:
            msg = pattern.sub(r"\1[REDACTED]", msg)
        msg = self.CREDENTIAL_PATTERNS[2].sub(r"\1[REDACTED]\2", msg)
        msg = self.CREDENTIAL_PATTERNS[3].sub("[REDACTED_KEY_ID]", msg)
        return msg


def setup_logging(debug: bool) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(RedactingFormatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)
    root.setLevel(logging.DEBUG if debug else logging.WARNING)
    # Suppress verbose service argument/response bodies; enable only selected wire metadata.
    logging.getLogger("botocore").setLevel(logging.WARNING)
    logging.getLogger("boto3").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    # Avoid dumping signed HTTP request bodies and complete authorization headers.
    logging.getLogger("botocore.auth").setLevel(logging.WARNING)
    logging.getLogger("botocore.parsers").setLevel(logging.WARNING)
    logging.getLogger("botocore.hooks").setLevel(logging.WARNING)
    if debug:
        logging.getLogger("botocore.endpoint").setLevel(logging.DEBUG)
        logging.getLogger("urllib3.connectionpool").setLevel(logging.DEBUG)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="awsredops", description="Permissioned AWS identity and infrastructure audit toolkit")
    p.add_argument("-a", "--activity", required=True, choices=sorted(ACTIVITIES), help="operation to execute")
    p.add_argument("--region", default=None, help="AWS region; defaults to configured region or us-east-1 for regional scans")
    p.add_argument("--source-profile", help="AWS credential source profile; for IAM Identity Center use aws configure sso first")
    p.add_argument("--profile", help="named target profile to write to ~/.aws/credentials (assume-role/credential-save only)")
    p.add_argument("--cred-name", help="AWS SigV4 credential record name from private cache")
    p.add_argument("--access-key-id", help="explicit AWS access key (prefer environment or configured profile to avoid shell history)")
    p.add_argument("--secret-access-key", help="explicit AWS secret key (shell arguments can be visible to other users)")
    p.add_argument("--session-token", help="AWS STS session token")
    p.add_argument("--access-token", help="OIDC access token for local caching, not for AWS SigV4")
    p.add_argument("--refresh-token", help="OIDC refresh token for local caching")
    p.add_argument("--credential-type", choices=["aws", "oidc"], default="aws")
    p.add_argument("--name", help="credential record name for show/save/delete")
    p.add_argument("--save-name", help="credential name for auth/assume-role persistence")
    p.add_argument("--reveal", action="store_true", help="explicitly print secrets in credential-show (unsafe on shared terminals)")
    p.add_argument("--role-arn", help="IAM role ARN to assume")
    p.add_argument("--role-session-name", default="AWSRedOpsAudit", help="sts:AssumeRole session name")
    p.add_argument("--external-id", help="optional assume role ExternalId")
    p.add_argument("--duration", type=int, default=3600, help="role session duration seconds")
    p.add_argument("--start-url", help="official IAM Identity Center https://org.awsapps.com/start portal")
    p.add_argument("--headless", action="store_true", help="headless Playwright mode (mostly for CI smoke testing)")
    p.add_argument("--policy-documents", action="store_true", help="also fetch IAM policy documents")
    p.add_argument("--max-assignments", type=int, default=2500, help="limit Identity Center assignments returned")
    p.add_argument("--regions", help="comma-separated scan regions")
    p.add_argument("--all-regions", action="store_true", help="scan enabled EC2 regions")
    p.add_argument("--principal-arn", help="IAM user/role ARN used for passive IAM simulator")
    p.add_argument("--file", help="source file to upload")
    p.add_argument("--bucket", help="destination S3 bucket")
    p.add_argument("--allow-bucket", help="explicit expected destination S3 bucket (required)")
    p.add_argument("--key", help="S3 object key")
    p.add_argument("--max-upload-mb", type=int, default=10)
    p.add_argument("--apply", action="store_true", help="perform guarded upload; default is dry run")
    p.add_argument("--output", help="optional local JSON results file, mode 0600")
    p.add_argument("--json", action="store_true", help="emit JSON on stdout")
    p.add_argument("-d", "--debug", action="store_true", help="SDK/urllib3 request metadata with best-effort redaction")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    setup_logging(args.debug)
    store = CredentialStore()
    try:
        if args.max_assignments < 1:
            raise OpsError("--max-assignments must be positive")
        payload = ACTIVITIES[args.activity](args, store)
        result = {"activity": args.activity, "success": True, "result": payload}
        if args.output:
            safe_export(Path(args.output), result)
        if args.json:
            print(dumps(result))
        else:
            print(f"AWSRedOps :: {args.activity} :: OK")
            print(dumps(payload))
        return 0
    except (OpsError, ClientError, BotoCoreError, OSError, ValueError) as exc:
        text = str(exc) if isinstance(exc, OpsError) else explain_aws_error(exc)
        print(dumps({"activity": args.activity, "success": False, "error": text}) if args.json else f"Error: {text}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("Cancelled by operator", file=sys.stderr)
        return 130
    except Exception:
        logging.getLogger(__name__).exception("Unexpected failure")
        print("Unexpected error; rerun with -d to view a sanitized stack trace", file=sys.stderr)
        return 1
