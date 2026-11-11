"""Public endpoint connectivity tests without credentials or side effects."""
from __future__ import annotations

import requests

ENDPOINTS = {
    "aws_signin": "https://signin.aws.amazon.com/",
    "aws_sts": "https://sts.amazonaws.com/",
}


def connectivity(timeout: float = 6.0) -> dict[str, dict[str, object]]:
    report: dict[str, dict[str, object]] = {}
    with requests.Session() as session:
        session.trust_env = True  # supports corporate HTTP(S) proxy configuration
        for label, url in ENDPOINTS.items():
            try:
                # A 4xx at an unauthenticated AWS API can still mean the endpoint is reachable.
                response = session.head(url, timeout=timeout, allow_redirects=False)
                report[label] = {"url": url, "reachable": True, "http_status": response.status_code}
                response.close()
            except requests.RequestException as exc:
                report[label] = {"url": url, "reachable": False, "error": type(exc).__name__}
    return report
