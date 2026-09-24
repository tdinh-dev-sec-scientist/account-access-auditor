"""Render the demo's terminal output to an SVG for the README.

    python scripts/render_terminal_svg.py

An SVG rather than a screenshot: it is text, so it diffs, it stays sharp at any
zoom, it is a few kilobytes, and it is regenerated from an actual run rather
than pasted in by hand. Running it is the only way to change it, which is the
point -- a terminal sample in a README is a claim about what the tool prints.

Needs moto (it drives ``lab.demo``); it makes no network call and touches no
AWS account.
"""

from __future__ import annotations

import os
import subprocess
import sys
from xml.sax.saxutils import escape

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT = os.path.join(REPO_ROOT, "docs", "images", "terminal.svg")

# A dark terminal, using the same neutral ink as the HTML report.
BACKGROUND = "#1a1a19"
TEXT = "#e8e7e0"
DIM = "#898781"
CHROME = "#2c2c2a"

FONT = "ui-monospace, SFMono-Regular, Menlo, Consolas, 'DejaVu Sans Mono', monospace"
FONT_SIZE = 13
LINE_HEIGHT = 19
CHAR_WIDTH = FONT_SIZE * 0.6005  # advance width of the monospace stack above
PADDING_X = 18
PADDING_Y = 16
TITLE_BAR = 30

# Lines that are chrome rather than content are dimmed, so the eye lands on the
# findings table instead of on the banner.
DIM_PREFIXES = ("=", "-", "Severity is this project's")


def capture() -> str:
    """Run the demo and return exactly what it printed."""
    result = subprocess.run(
        [sys.executable, "-m", "lab.demo", "--output", ""],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        check=True,
    )
    return result.stdout.rstrip("\n")


def render(text: str) -> str:
    lines = text.split("\n")
    columns = max((len(line) for line in lines), default=80)
    width = int(columns * CHAR_WIDTH + PADDING_X * 2)
    height = int(len(lines) * LINE_HEIGHT + PADDING_Y * 2 + TITLE_BAR)

    rows = []
    for index, line in enumerate(lines):
        y = TITLE_BAR + PADDING_Y + index * LINE_HEIGHT + FONT_SIZE
        fill = DIM if line.startswith(DIM_PREFIXES) else TEXT
        rows.append(f'<text x="{PADDING_X}" y="{y}" fill="{fill}" xml:space="preserve">{escape(line)}</text>')

    dots = "".join(
        f'<circle cx="{18 + offset * 18}" cy="15" r="5.5" fill="{CHROME}"/>' for offset in range(3)
    )

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"
     viewBox="0 0 {width} {height}" role="img"
     aria-label="Terminal output of a scan of the emulated lab account">
  <rect width="{width}" height="{height}" rx="8" fill="{BACKGROUND}"/>
  <rect width="{width}" height="{TITLE_BAR}" rx="8" fill="{BACKGROUND}"/>
  <line x1="0" y1="{TITLE_BAR}" x2="{width}" y2="{TITLE_BAR}" stroke="{CHROME}"/>
  {dots}
  <g font-family="{FONT}" font-size="{FONT_SIZE}">
{chr(10).join("    " + row for row in rows)}
  </g>
</svg>
"""


def main() -> int:
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    svg = render(capture())
    with open(OUTPUT, "w", encoding="utf-8") as handle:
        handle.write(svg)
    print(f"Wrote {os.path.relpath(OUTPUT, REPO_ROOT)} ({len(svg)} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
