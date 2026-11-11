"""Serialization, pagination, identity parsing, and safe atomic JSON output."""
from __future__ import annotations

import datetime as dt
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterator


def json_default(obj: Any) -> str:
    if isinstance(obj, (dt.date, dt.datetime)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return f"<binary:{len(obj)} bytes>"
    return str(obj)


def dumps(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, default=json_default)


def safe_export(destination: Path, payload: Any) -> None:
    """Write scan exports privately, without following a final symlink."""
    destination = destination.expanduser()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.is_symlink():
        raise ValueError(f"Refusing symlink export: {destination}")
    fd, temp = tempfile.mkstemp(prefix=".awsredops-", dir=str(destination.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(dumps(payload) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp, 0o600)
        os.replace(temp, destination)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def pages(client: Any, operation: str, member: str, **kwargs: Any) -> Iterator[Any]:
    """Use boto3 paginator for the requested list operation."""
    paginator = client.get_paginator(operation)
    for page in paginator.paginate(**kwargs):
        yield from page.get(member, [])


def identity_parts(arn: str) -> dict[str, str]:
    """Parse both IAM and STS caller ARN formats."""
    segments = arn.split(":", 5)
    if len(segments) != 6:
        return {"arn": arn, "type": "unknown"}
    resource = segments[5]
    kind, _, identity = resource.partition("/")
    result = {"arn": arn, "partition": segments[1], "service": segments[2], "account_id": segments[4], "type": kind, "identity": identity}
    if kind == "assumed-role":
        role, _, session = identity.partition("/")
        result.update({"role_name": role, "session_name": session})
    return result


def without_metadata(response: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in response.items() if key != "ResponseMetadata"}
