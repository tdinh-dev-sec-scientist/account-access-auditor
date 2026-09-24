"""Render the README's screenshots of the HTML report.

    python -m lab.run_benchmark            # produces results/aws_audit_report.html
    python scripts/render_screenshots.py

Optional tooling, deliberately outside CI: it needs Playwright and a Chromium
build, which the test suite does not. Everything CI checks is text.

    pip install playwright && playwright install chromium

The screenshots are taken from ``results/aws_audit_report.html`` -- the artifact
the benchmark writes -- so they cannot drift from the report the tool actually
produces without someone regenerating both.

Set ``CHROMIUM_PATH`` to use a Chromium already on the machine.
"""

from __future__ import annotations

import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SOURCE = os.path.join(REPO_ROOT, "results", "aws_audit_report.html")
IMAGES = os.path.join(REPO_ROOT, "docs", "images")

VIEWPORT = {"width": 1180, "height": 900}
SCALE = 1.5  # sharp on a high-density display without doubling the file size

# (filename, colour scheme, the section to frame). "overview" is the header and
# the result together; "findings" is the filter row plus the first finding, so
# the evidence block is visible.
SHOTS = [
    ("report-light.png", "light", "overview"),
    ("report-dark.png", "dark", "overview"),
    ("report-findings.png", "light", "findings"),
]


def _clip(page, region: str) -> dict[str, float]:
    """A pixel box around the part of the report the shot is meant to show."""
    sections = page.locator("main > section")
    if region == "overview":
        first, last = sections.nth(0), sections.nth(1)
    else:
        first = last = sections.last

    top = first.bounding_box()
    bottom = last.bounding_box()
    height = bottom["y"] + bottom["height"] - top["y"]
    if region == "findings":
        # The findings section is the whole rest of the page; frame the filter
        # row and the first finding rather than all twenty-five.
        height = min(height, 980)
    return {
        "x": top["x"] - 16,
        "y": top["y"] - 16,
        "width": top["width"] + 32,
        "height": height + 32,
    }


def main() -> int:
    if not os.path.exists(SOURCE):
        print(f"{os.path.relpath(SOURCE, REPO_ROOT)} is missing. Run `python -m lab.run_benchmark` first.")
        return 1

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Playwright is not installed. See this file's docstring.")
        return 1

    os.makedirs(IMAGES, exist_ok=True)
    launch = {"executable_path": os.environ["CHROMIUM_PATH"]} if os.environ.get("CHROMIUM_PATH") else {}

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(**launch)
        for name, scheme, region in SHOTS:
            page = browser.new_page(viewport=VIEWPORT, device_scale_factor=SCALE, color_scheme=scheme)
            page.goto("file://" + SOURCE)
            page.wait_for_timeout(300)
            destination = os.path.join(IMAGES, name)
            # full_page so a clip below the fold (the findings) is still in range.
            page.screenshot(path=destination, clip=_clip(page, region), full_page=True)
            page.close()
            print(f"Wrote docs/images/{name}")
        browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
