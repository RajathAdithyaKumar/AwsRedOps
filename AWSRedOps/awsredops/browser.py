"""Open AWS IAM Identity Center portal for local, interactive sign-in."""
from __future__ import annotations

from urllib.parse import urlsplit

from .errors import OpsError


def open_sso_portal(start_url: str, headless: bool = False) -> dict[str, str]:
    """Does not accept, convert, replay, or expose programmatic session credentials."""
    parsed = urlsplit(start_url)
    # Standard IAM Identity Center portal URL; custom portal domains should be opened manually.
    if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".awsapps.com"):
        raise OpsError("--start-url must use the official https://<org>.awsapps.com/start portal")
    if parsed.port not in (None, 443) or parsed.username or parsed.password:
        raise OpsError("Only HTTPS default port and URLs without embedded credentials are permitted")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise OpsError("Playwright not installed. pip install -r requirements.txt; python -m playwright install chromium") from exc
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=headless)
            page = browser.new_page()
            page.goto(start_url, wait_until="domcontentloaded", timeout=30000)
            print("Complete sign-in yourself in the opened browser. Press Enter here to close it.")
            input()
            browser.close()
    except Exception as exc:
        raise OpsError(f"Could not open local portal browser: {exc}. Run 'python -m playwright install chromium'.") from exc
    return {"portal": start_url, "status": "browser-closed"}
