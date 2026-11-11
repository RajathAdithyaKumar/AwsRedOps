"""Private, atomic local credential cache; values at rest are NOT encrypted."""
from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from typing import Any

from .errors import OpsError

DEFAULT_STORE = Path.home() / ".awsredops" / ".aws_creds"
NAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{1,80}$")
SECRET_FIELDS = {"secret_access_key", "session_token", "access_token", "refresh_token", "client_secret"}


class CredentialStore:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path or os.environ.get("AWSREDOPS_STORE", DEFAULT_STORE)).expanduser()

    @staticmethod
    def _check_name(name: str) -> None:
        if not NAME_RE.fullmatch(name):
            raise OpsError("Credential name must be 1-80 characters: letters, digits, _ . @ -")

    def _verify(self) -> None:
        if self.path.is_symlink() or self.path.parent.is_symlink():
            raise OpsError("Refusing symlinked credential store or store directory")
        if self.path.exists() and (self.path.stat().st_mode & 0o077):
            raise OpsError(f"Insecure credential file permissions: {self.path}. Set chmod 600 before reading.")

    def _read(self) -> dict[str, Any]:
        self._verify()
        if not self.path.exists():
            return {"schema": 1, "credentials": {}}
        try:
            envelope = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise OpsError("Cannot read encrypted credential cache") from exc
        if not isinstance(envelope, dict):
            raise OpsError("Invalid credential cache schema")
        if envelope.get("schema") == 1 and isinstance(envelope.get("credentials"), dict):
            # Upgrade the previous plaintext cache in place, before returning secrets.
            self._write(envelope)
            return envelope
        if envelope.get("schema") != 2 or envelope.get("cipher") != "AES-256-GCM":
            raise OpsError("Invalid or unsupported encrypted credential cache schema")
        try:
            import base64
            import hashlib
            import keyring
            from cryptography.exceptions import InvalidTag
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as exc:
            raise OpsError("Encrypted cache requires keyring and cryptography; install requirements.txt") from exc
        backend_name = type(keyring.get_keyring()).__module__
        if not backend_name.startswith((
            "keyring.backends.macOS", "keyring.backends.Windows",
            "keyring.backends.SecretService", "keyring.backends.libsecret",
            "keyring.backends.kwallet",
        )):
            raise OpsError("A native OS keychain is required; refusing an unavailable or non-native keyring backend")
        identity = str(self.path.resolve(strict=False))
        username = f"aes256-gcm:{hashlib.sha256(identity.encode('utf-8')).hexdigest()}"
        try:
            encoded_key = keyring.get_password("AWSRedOps credential cache", username)
        except Exception as exc:
            raise OpsError("Cannot access the OS keychain; unlock or configure it") from exc
        if not encoded_key:
            raise OpsError("Encryption key missing from the OS keychain; refusing to discard cached credentials")
        try:
            key = base64.b64decode(encoded_key, validate=True)
            nonce = base64.b64decode(envelope["nonce"], validate=True)
            ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
            if len(key) != 32 or len(nonce) != 12:
                raise ValueError("invalid AES key or nonce length")
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, f"AWSRedOps-v2:{identity}".encode("utf-8"))
            parsed = json.loads(plaintext)
        except (ValueError, KeyError, TypeError, InvalidTag, json.JSONDecodeError) as exc:
            raise OpsError("Encrypted credential cache cannot be decrypted or is corrupted") from exc
        if not isinstance(parsed, dict) or parsed.get("schema") != 1 or not isinstance(parsed.get("credentials"), dict):
            raise OpsError("Invalid decrypted credential cache schema")
        return parsed

    def _write(self, payload: dict[str, Any]) -> None:
        self._verify()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.parent == DEFAULT_STORE.parent and (self.path.parent.stat().st_mode & 0o077):
            raise OpsError("Default credential store directory must have mode 0700; fix its permissions")
        try:
            import base64
            import hashlib
            import keyring
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as exc:
            raise OpsError("Encrypted cache requires keyring and cryptography; install requirements.txt") from exc
        backend_name = type(keyring.get_keyring()).__module__
        if not backend_name.startswith((
            "keyring.backends.macOS", "keyring.backends.Windows",
            "keyring.backends.SecretService", "keyring.backends.libsecret",
            "keyring.backends.kwallet",
        )):
            raise OpsError("A native OS keychain is required; refusing an unavailable or non-native keyring backend")
        identity = str(self.path.resolve(strict=False))
        username = f"aes256-gcm:{hashlib.sha256(identity.encode('utf-8')).hexdigest()}"
        try:
            encoded_key = keyring.get_password("AWSRedOps credential cache", username)
        except Exception as exc:
            raise OpsError("Cannot access the OS keychain; unlock or configure it") from exc
        if encoded_key:
            try:
                key = base64.b64decode(encoded_key, validate=True)
            except (ValueError, TypeError) as exc:
                raise OpsError("Invalid credential encryption key in the OS keychain") from exc
            if len(key) != 32:
                raise OpsError("Invalid credential encryption key length in the OS keychain")
        else:
            if self.path.exists():
                try:
                    existing = json.loads(self.path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as exc:
                    raise OpsError("Cannot verify existing cache before allocating encryption key") from exc
                if not isinstance(existing, dict) or existing.get("schema") != 1:
                    raise OpsError("Existing encrypted cache has no key; refusing to overwrite it")
            key = os.urandom(32)
            try:
                keyring.set_password("AWSRedOps credential cache", username, base64.b64encode(key).decode("ascii"))
            except Exception as exc:
                raise OpsError("Cannot save encryption key to the OS keychain") from exc
        nonce = os.urandom(12)
        plaintext = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, f"AWSRedOps-v2:{identity}".encode("utf-8"))
        envelope = {
            "schema": 2,
            "cipher": "AES-256-GCM",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }
        descriptor, temp_path = tempfile.mkstemp(prefix=".aws_creds-", dir=self.path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as fp:
                json.dump(envelope, fp, sort_keys=True, indent=2)
                fp.write("\n")
                fp.flush()
                os.fsync(fp.fileno())
            os.chmod(temp_path, 0o600)
            os.replace(temp_path, self.path)
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def save(self, name: str, value: dict[str, Any]) -> None:
        self._check_name(name)
        if value.get("type") not in {"aws", "oidc"}:
            raise OpsError("Credential record must be type 'aws' or 'oidc'")
        data = self._read()
        data["credentials"][name] = value
        self._write(data)

    def load(self, name: str) -> dict[str, Any]:
        self._check_name(name)
        try:
            return dict(self._read()["credentials"][name])
        except KeyError as exc:
            raise OpsError(f"No credential named {name!r}") from exc

    def names(self) -> list[dict[str, str]]:
        return [{"name": name, "type": record.get("type", "unknown"), "region": record.get("region", "")} for name, record in sorted(self._read()["credentials"].items())]

    def show(self, name: str, reveal: bool = False) -> dict[str, Any]:
        record = self.load(name)
        # Always redact cache output, including when legacy --reveal is requested.
        for field in SECRET_FIELDS | {"access_key_id"}:
            if field in record and record[field]:
                record[field] = "[REDACTED]"
        return {"name": name, **record}

    def delete(self, name: str) -> bool:
        self._check_name(name)
        data = self._read()
        if name not in data["credentials"]:
            return False
        del data["credentials"][name]
        self._write(data)
        return True
