"""Guarded, auditable upload of explicitly selected local files to an allowlisted bucket."""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from .errors import OpsError


class GuardedS3Uploader:
    def __init__(self, session: Any):
        self.s3 = session.client("s3")

    def run(self, source: str, bucket: str, key: str, allowed_bucket: str, apply: bool, max_mb: int = 10) -> dict[str, Any]:
        file = Path(source).expanduser()
        if not file.is_file() or file.is_symlink():
            raise OpsError("--file must be a regular, non-symlink local file")
        if not bucket or bucket != allowed_bucket:
            raise OpsError("Destination bucket must match an explicit --allow-bucket value")
        if not key or key.startswith("/") or ".." in Path(key).parts:
            raise OpsError("--key must be a nonempty relative S3 object key")
        if max_mb < 1 or max_mb > 100:
            raise OpsError("--max-upload-mb must be 1..100")
        size = file.stat().st_size
        if size > max_mb * 1024 * 1024:
            raise OpsError(f"File exceeds upload safety limit of {max_mb} MiB")
        digest = hashlib.sha256()
        with file.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        report = {"operation": "s3_put_object", "file": str(file), "size_bytes": size, "sha256": digest.hexdigest(), "bucket": bucket, "key": key, "dry_run": not apply}
        if apply:
            self.s3.upload_file(str(file), bucket, key, ExtraArgs={"Metadata": {"awsredops": "authorized-assessment"}})
            report["uploaded"] = True
        return report
