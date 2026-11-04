"""Record the README's console walkthrough GIF.

    python -m lab.run_benchmark
    python scripts/build_site.py
    python scripts/render_console_gif.py

Optional tooling, deliberately outside CI: it needs Playwright, a Chromium
build, and ffmpeg, which the test suite does not.

    pip install playwright && playwright install chromium

The walkthrough follows the "Try the console" steps in the README against the
locally built ``site/`` directory, so the GIF shows the same saved fixtures the
public demo serves. Set ``CHROMIUM_PATH`` to use a Chromium already on the
machine.
"""

from __future__ import annotations

import functools
import http.server
import os
import shutil
import subprocess
import sys
import tempfile
import threading

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE = os.path.join(REPO_ROOT, "site")
OUTPUT = os.path.join(REPO_ROOT, "docs", "images", "console-walkthrough.gif")

VIEWPORT = {"width": 1280, "height": 760}
GIF_WIDTH = 960
SETTLE_MS = 350


def _serve(directory: str) -> tuple[http.server.ThreadingHTTPServer, str]:
    handler = functools.partial(_QuietHandler, directory=directory)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}/console/"


class _QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002 - signature is fixed by the base class
        pass


def _record(url: str, frames_dir: str) -> list[tuple[str, float]]:
    from playwright.sync_api import sync_playwright

    frames: list[tuple[str, float]] = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=os.environ.get("CHROMIUM_PATH") or None)
        page = browser.new_page(viewport=VIEWPORT, device_scale_factor=1, color_scheme="dark")
        page.goto(url, wait_until="networkidle")

        def shot(seconds: float) -> None:
            page.wait_for_timeout(SETTLE_MS)
            path = os.path.join(frames_dir, f"frame{len(frames):02d}.png")
            page.screenshot(path=path)
            frames.append((path, seconds))

        shot(2.5)  # overview of the misconfigured fixture
        page.select_option("#scope-select", "no-trail")
        shot(2.2)
        page.select_option("#scope-select", "misconfigured")
        page.click('[data-view="findings"]')
        shot(2.2)
        page.select_option("#severity-filter", "CRITICAL")
        shot(2.0)
        page.locator(".finding-title-button").first.click()
        shot(3.2)  # finding evidence and remediation
        page.click("#dialog-close")
        page.click('[data-view="security-scans"]')
        shot(2.5)
        page.click("#assistant-launcher")
        page.click('[data-assistant-question="How many critical findings?"]')
        page.wait_for_timeout(600)
        shot(3.2)  # Rin answers from the saved report
        page.click("#assistant-close")
        page.click("#theme-toggle")
        page.click('[data-view="overview"]')
        shot(2.5)
        browser.close()
    return frames


def _encode(frames: list[tuple[str, float]], frames_dir: str) -> None:
    playlist = os.path.join(frames_dir, "frames.txt")
    with open(playlist, "w", encoding="utf-8") as handle:
        for path, seconds in frames:
            handle.write(f"file '{path}'\nduration {seconds}\n")
        handle.write(f"file '{frames[-1][0]}'\n")  # the concat demuxer drops the last duration otherwise
    palette = (
        f"fps=10,scale={GIF_WIDTH}:-1:flags=lanczos,split[a][b];"
        "[a]palettegen=max_colors=128:stats_mode=diff[p];"
        "[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle"
    )
    subprocess.run(
        ["ffmpeg", "-loglevel", "error", "-y", "-f", "concat", "-safe", "0", "-i", playlist]
        + ["-vf", palette, "-loop", "0", OUTPUT],
        check=True,
    )


def main() -> int:
    if not os.path.isfile(os.path.join(SITE, "console", "index.html")):
        print("site/ is missing; run python scripts/build_site.py first.", file=sys.stderr)
        return 1
    if shutil.which("ffmpeg") is None:
        print("ffmpeg is required to encode the GIF.", file=sys.stderr)
        return 1
    server, url = _serve(SITE)
    try:
        with tempfile.TemporaryDirectory(prefix="console-gif-") as frames_dir:
            _encode(_record(url, frames_dir), frames_dir)
    finally:
        server.shutdown()
    print(f"wrote {os.path.relpath(OUTPUT, REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
