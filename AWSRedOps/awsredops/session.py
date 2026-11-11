"""Credential resolution and explicit opt-in AWS shared credentials export."""
from __future__ import annotations

import configparser
import os
import tempfile
from pathlib import Path
from typing import Any

import boto3

from .errors import OpsError
from .store import CredentialStore, NAME_RE


def session_from_args(args: Any, store: CredentialStore) -> boto3.Session:
    access = args.access_key_id
    secret = args.secret_access_key
    token = args.session_token
    region = args.region
    if args.cred_name:
        if access or secret or token:
            raise OpsError("Choose --cred-name OR raw AWS credential flags, not both")
        cached = store.load(args.cred_name)
        if cached.get("type") != "aws":
            raise OpsError("An OIDC token is not an AWS SigV4 access key. Use an AWS key set or configured SSO profile.")
        access, secret, token = (cached.get("access_key_id"), cached.get("secret_access_key"), cached.get("session_token"))
        region = region or cached.get("region")
    if bool(access) != bool(secret):
        raise OpsError("Both --access-key-id and --secret-access-key are required together")
    if token and not access:
        raise OpsError("--session-token requires AWS key pair")
    if args.source_profile and access:
        raise OpsError("Choose --source-profile OR explicit credentials")
    if access:
        return boto3.Session(aws_access_key_id=access, aws_secret_access_key=secret, aws_session_token=token, region_name=region)
    if args.source_profile:
        return boto3.Session(profile_name=args.source_profile, region_name=region)
    return boto3.Session(region_name=region)


def persist_profile(name: str, credentials: dict[str, str], path: Path | None = None) -> Path:
    """Save AWS key set to private ~/.aws/credentials. Only on explicit --profile."""
    if not NAME_RE.fullmatch(name) or name == "default":
        raise OpsError("Export profile must be a named non-default profile, using letters/numbers/_.@-")
    dest = path or (Path.home() / ".aws" / "credentials")
    if dest.is_symlink() or dest.parent.is_symlink():
        raise OpsError("Refusing symlinked AWS shared credentials file")
    dest.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if dest.exists() and dest.stat().st_mode & 0o077:
        raise OpsError("AWS credentials file is accessible to other users; chmod 600 before writing")
    # Preserve existing comments and formatting; never replace an existing profile.
    original = dest.read_text(encoding="utf-8") if dest.exists() else ""
    config = configparser.RawConfigParser()
    if original:
        try:
            config.read_string(original)
        except configparser.Error as exc:
            raise OpsError(f"Cannot parse existing AWS credentials file: {exc}") from exc
    if config.has_section(name):
        raise OpsError(f"Profile {name!r} already exists in {dest}; choose a new target name")
    section = [f"[{name}]", f"aws_access_key_id = {credentials['access_key_id']}",
               f"aws_secret_access_key = {credentials['secret_access_key']}"]
    if credentials.get("session_token"):
        section.append(f"aws_session_token = {credentials['session_token']}")
    if credentials.get("region"):
        section.append(f"region = {credentials['region']}")
    contents = original.rstrip("\n") + ("\n\n" if original.strip() else "") + "\n".join(section) + "\n"
    fd, temp = tempfile.mkstemp(prefix=".credentials-", dir=dest.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fp:
            fp.write(contents)
            fp.flush()
            os.fsync(fp.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, dest)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)
    return dest
