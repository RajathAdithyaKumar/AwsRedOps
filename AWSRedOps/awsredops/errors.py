"""Exceptions and safe AWS error reporting."""

from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError, PartialCredentialsError


class OpsError(Exception):
    """Expected, user-facing failure (no stack trace unless debug enabled)."""


def explain_aws_error(exc: Exception, service: str = "AWS") -> str:
    if isinstance(exc, ClientError):
        info = exc.response.get("Error", {})
        code = info.get("Code", "Unknown")
        message = info.get("Message", "No details provided")
        if code in {"AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "UnauthorizedException"}:
            return f"{service}: permission denied ({code}). Check scoped IAM permission, SCPs, and permission boundaries. {message}"
        if code in {"ExpiredToken", "ExpiredTokenException", "InvalidClientTokenId", "UnrecognizedClientException"}:
            return f"{service}: credentials invalid or expired ({code}). {message}"
        if code in {"Throttling", "ThrottlingException", "TooManyRequestsException"}:
            return f"{service}: throttled ({code}); retry with lower frequency. {message}"
        return f"{service}: {code}: {message}"
    if isinstance(exc, (NoCredentialsError, PartialCredentialsError)):
        return "AWS credentials not found or incomplete. Provide --cred-name, --access-key-id/--secret-access-key, or use the AWS default credential chain."
    if isinstance(exc, BotoCoreError):
        return f"{service}: SDK error: {type(exc).__name__}: {exc}"
    return f"{service}: {type(exc).__name__}: {exc}"
