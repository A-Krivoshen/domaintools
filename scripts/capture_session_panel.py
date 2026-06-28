#!/usr/bin/env python3
"""Capture Quick Actions panel screenshots for session info QA."""
from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path(__file__).resolve().parents[1] / "static"
URL = "http://127.0.0.1:8001/dns?q=example.com&types=A&lang=ru"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1440, "height": 900})
        page.goto(URL, wait_until="networkidle")
        page.click("[data-quick-actions-dock] [data-qa-dock-toggle]")
        page.wait_for_timeout(500)

        trigger = page.locator("[data-quick-actions-dock] [data-qa-session-info-toggle]").first
        trigger.scroll_into_view_if_needed()
        page.wait_for_timeout(300)

        panel = page.locator("[data-quick-actions-dock]").first
        panel.screenshot(path=str(OUT / "session-panel-collapsed.png"))

        trigger.click()
        page.wait_for_selector(
            "[data-quick-actions-dock] [data-qa-session-info-data]:not([hidden])",
            timeout=5000,
        )
        page.wait_for_timeout(400)
        panel.screenshot(path=str(OUT / "session-panel-expanded.png"))

        browser.close()
    print("saved:", OUT / "session-panel-collapsed.png", OUT / "session-panel-expanded.png")


if __name__ == "__main__":
    main()