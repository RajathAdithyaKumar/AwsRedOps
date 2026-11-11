"""Approved authentication, identity checks, and role assumption."""
from __future__ import annotations

import re
import subprocess
from typing import Any

from .errors import OpsError
from .session import persist_profile
from .store import CredentialStore
from .utils import identity_parts

ROLE_SESSION_RE = re.compile(r"^[\w+=,.@-]{2,64}$")


class Authentication:
    def __init__(self, session: Any, store: CredentialStore):
        self.session = session
        self.store = store

    def whoami(self) -> dict[str, Any]:
        response = self.session.client("sts").get_caller_identity()
        return {"user_id": response["UserId"], "account": response["Account"], "identity": identity_parts(response["Arn"])}

    def validate(self) -> dict[str, Any]:
        return {"validated": True, **self.whoami()}

    def assume_role(self, role_arn: str, session_name: str, external_id: str | None = None, duration: int = 3600) -> dict[str, Any]:
        if not role_arn.startswith("arn:") or ":role/" not in role_arn:
            raise OpsError("--role-arn must be a valid IAM role ARN")
        if not ROLE_SESSION_RE.fullmatch(session_name):
            raise OpsError("--role-session-name must contain 2-64 supported IAM session-name characters")
        if not 900 <= duration <= 43200:
            raise OpsError("--duration must be 900..43200 seconds (the role may enforce a lower maximum)")
        params: dict[str, Any] = {"RoleArn": role_arn, "RoleSessionName": session_name, "DurationSeconds": duration}
        if external_id:
            params["ExternalId"] = external_id
        response = self.session.client("sts").assume_role(**params)
        c = response["Credentials"]
        return {
            "assumed_role_user": response.get("AssumedRoleUser", {}),
            "credentials": {
                "type": "aws", "access_key_id": c["AccessKeyId"], "secret_access_key": c["SecretAccessKey"],
                "session_token": c["SessionToken"], "region": self.session.region_name or "us-east-1",
                "expires_at": c["Expiration"].isoformat(),
            },
        }

    def persist_assumed(self, data: dict[str, Any], save_name: str | None, profile: str | None) -> dict[str, Any]:
        credential = data.pop("credentials")
        if save_name:
            self.store.save(save_name, credential)
            data["saved_as"] = save_name
        if profile:
            data["profile_path"] = str(persist_profile(profile, credential))
            data["profile_name"] = profile
        if not save_name and not profile:
            data["warning"] = "Temporary credentials were NOT printed. Use --save-name and/or --profile to persist explicitly."
        data["expires_at"] = credential["expires_at"]
        return data


def aws_cli_sso_login(profile: str) -> dict[str, Any]:
    """Entrust login to the supported AWS CLI, not a custom device-code capture flow."""
    if not profile or profile.startswith("-"):
        raise OpsError("--source-profile is required for interactive AWS CLI SSO login")
    try:
        process = subprocess.run(["aws", "sso", "login", "--profile", profile], check=False)
    except FileNotFoundError as exc:
        raise OpsError("AWS CLI v2 not found. Install awscli and configure an IAM Identity Center profile with 'aws configure sso'.") from exc
    if process.returncode:
        raise OpsError(f"aws sso login exited with status {process.returncode}")
    return {"profile": profile, "authenticated": True, "source": "aws-cli-managed-identity-center"}
