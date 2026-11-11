import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from awsredops.auth import Authentication
from awsredops.cli import main
from awsredops.errors import OpsError
from awsredops.risk import PrivilegeRiskAudit
from awsredops.s3ops import GuardedS3Uploader
from awsredops.store import CredentialStore
from awsredops.utils import identity_parts


def test_store_roundtrip_redaction(tmp_path):
    store = CredentialStore(tmp_path / ".private" / ".aws_creds")
    store.save("demo", {"type": "aws", "access_key_id": "AKIAXXXXX", "secret_access_key": "secret", "session_token": "token", "region": "us-west-2"})
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o600
    assert store.load("demo")["secret_access_key"] == "secret"
    assert store.show("demo")["secret_access_key"] == "[REDACTED]"
    assert store.show("demo", reveal=True)["session_token"] == "token"
    assert store.names()[0]["name"] == "demo"
    assert store.delete("demo")
    assert not store.delete("demo")


def test_store_bad_name_and_permissions(tmp_path):
    store = CredentialStore(tmp_path / "records")
    with pytest.raises(OpsError):
        store.save("../evil", {"type": "aws"})
    store.save("fine", {"type": "aws", "access_key_id": "test"})
    os.chmod(store.path, 0o644)
    with pytest.raises(OpsError, match="permissions"):
        store.load("fine")


def test_identity_formats():
    principal = identity_parts("arn:aws:sts::123456789012:assumed-role/AuditRole/my-session")
    assert principal["role_name"] == "AuditRole"
    assert principal["session_name"] == "my-session"
    assert identity_parts("arn:aws:iam::123456789012:user/path/alice")["identity"] == "path/alice"


def test_assume_role_without_leaking_credentials():
    fake_session = MagicMock()
    fake_session.region_name = "us-east-1"
    fake_session.client.return_value.assume_role.return_value = {
        "Credentials": {"AccessKeyId": "temporary", "SecretAccessKey": "secret", "SessionToken": "token", "Expiration": SimpleNamespace(isoformat=lambda: "2026-10-11T00:00:00Z")},
        "AssumedRoleUser": {"Arn": "arn:aws:sts::123:assumed-role/Role/Session"},
    }
    auth = Authentication(fake_session, MagicMock())
    result = auth.assume_role("arn:aws:iam::123:role/Role", "AuditSession")
    report = auth.persist_assumed(result, None, None)
    assert "secret" not in str(report)
    assert "NOT printed" in report["warning"]


def test_guarded_upload_needs_explicit_permission(tmp_path):
    file = tmp_path / "sample.txt"
    file.write_text("authorized sample", encoding="utf-8")
    client = MagicMock()
    session = MagicMock()
    session.client.return_value = client
    uploader = GuardedS3Uploader(session)
    with pytest.raises(OpsError):
        uploader.run(str(file), "bucket-a", "audit/sample.txt", "other-bucket", False)
    dry = uploader.run(str(file), "bucket-a", "audit/sample.txt", "bucket-a", False)
    assert dry["dry_run"] is True
    client.upload_file.assert_not_called()
    applied = uploader.run(str(file), "bucket-a", "audit/sample.txt", "bucket-a", True)
    assert applied["uploaded"] is True
    client.upload_file.assert_called_once()


def test_risk_rules_are_read_only():
    results = [{"EvalActionName": "iam:PassRole", "EvalDecision": "allowed"}, {"EvalActionName": "ec2:RunInstances", "EvalDecision": "allowed"}]
    pager = MagicMock()
    pager.paginate.return_value = [{"EvaluationResults": results}]
    iam = MagicMock()
    iam.get_paginator.return_value = pager
    session = MagicMock()
    session.client.side_effect = lambda service: iam if service == "iam" else MagicMock()
    audit = PrivilegeRiskAudit(session)
    report = audit.collect("arn:aws:iam::123456789012:role/AuditRole")
    assert report["findings"][0]["rule"] == "role_pass_and_compute"
    iam.create_user.assert_not_called()
    iam.attach_user_policy.assert_not_called()


def test_cli_credential_management(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("AWSREDOPS_STORE", str(tmp_path / ".store" / ".aws_creds"))
    status = main(["-a", "credential-save", "--name", "example", "--access-key-id", "A123", "--secret-access-key", "xyz"])
    assert status == 0
    assert "xyz" not in capsys.readouterr().out
    status = main(["-a", "credential-show", "--name", "example", "--json"])
    assert status == 0
    report = json.loads(capsys.readouterr().out)
    assert report["result"]["secret_access_key"] == "[REDACTED]"


def test_debug_mask_hides_headers_and_keys():
    import logging
    from awsredops.cli import RedactingFormatter

    formatter = RedactingFormatter("%(message)s")
    rec = logging.LogRecord("botocore.endpoint", logging.DEBUG, __file__, 1, "Sending request headers={'Authorization': b'AWS4-HMAC-SHA256 Credential=AKIA1234567890123456/abcd, Signature=secret', 'X-Amz-Security-Token': b'SUPERSECRET'}", (), None)
    rendered = formatter.format(rec)
    assert "SUPERSECRET" not in rendered
    assert "Signature=secret" not in rendered
    assert "[REDACTED_HEADERS]" in rendered


def test_credentials_profile_export_is_private(tmp_path):
    from awsredops.session import persist_profile

    dest = tmp_path / ".aws" / "credentials"
    persist_profile("scoped", {"access_key_id": "A", "secret_access_key": "B", "session_token": "C", "region": "us-west-2"}, path=dest)
    assert stat.S_IMODE(dest.stat().st_mode) == 0o600
    assert "[scoped]" in dest.read_text()
    assert "aws_session_token = C" in dest.read_text()
    with pytest.raises(OpsError):
        persist_profile("default", {"access_key_id": "A", "secret_access_key": "B"}, path=dest)


def test_credentials_profile_export_preserves_original(tmp_path):
    from awsredops.session import persist_profile

    dest = tmp_path / "credentials"
    dest.write_text("# preserved\n[existing]\naws_access_key_id = keep\n", encoding="utf-8")
    os.chmod(dest, 0o600)
    persist_profile("new-audit", {"access_key_id": "A", "secret_access_key": "B"}, path=dest)
    assert dest.read_text().startswith("# preserved\n[existing]\n")
    with pytest.raises(OpsError, match="already exists"):
        persist_profile("new-audit", {"access_key_id": "A", "secret_access_key": "B"}, path=dest)
