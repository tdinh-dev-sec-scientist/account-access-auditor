"""Build the published demo site from the artifacts the benchmark produced.

    python -m lab.run_benchmark      # produces the artifacts this reads
    python scripts/build_site.py     # writes site/

The site is three files: a landing page that replays a scan, the full HTML
report, and the machine-readable artifacts the page's numbers came from.

Nothing on the page is typed in. The terminal transcript it replays is captured
from ``auditor.reporters.terminal`` -- the same reporter a real run prints
through -- and every count comes out of ``results/*.json``. So the page cannot
claim a number the tool did not produce, which is the same rule the README's
evidence table follows.

**The replay is a replay, and the page says so.** It is a recording of
``python -m lab.run_benchmark``, not a scan running in the visitor's browser,
because a static page cannot run boto3. Presenting canned output as a live scan
would be exactly the kind of unearned claim this project avoids everywhere else.

Note the split: this landing page uses JavaScript for the animation, while the
audit report it links to still contains none. The report is evidence and gets
archived; the landing page is a shop window. The page also renders its complete
final state in HTML, so it reads correctly with scripts disabled -- the script
only animates what is already there.
"""

from __future__ import annotations

import html
import io
import json
import os
import shutil
import sys
from contextlib import redirect_stdout
from typing import Any

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:  # pragma: no cover
    sys.path.insert(0, REPO_ROOT)

from auditor.reporters import terminal  # noqa: E402
from auditor.reporters.html_reporter import TIER_COLOURS  # noqa: E402
from auditor.severity import Severity, ordered_names  # noqa: E402

RESULTS = os.path.join(REPO_ROOT, "results")
SITE = os.path.join(REPO_ROOT, "site")

REPO_URL = "https://github.com/tdinh-dev-sec-scientist/account-access-auditor"

# The two lab profiles, in the order the selector shows them.
PROFILES = [
    ("misconfigured", "aws_audit_results.json", "Misconfigured account"),
    ("no-trail", "aws_audit_results_no-trail.json", "Account with no CloudTrail"),
]


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _load(name: str) -> dict[str, Any]:
    path = os.path.join(RESULTS, name)
    if not os.path.exists(path):
        raise SystemExit(
            f"{os.path.relpath(path, REPO_ROOT)} is missing. Run `python -m lab.run_benchmark` first."
        )
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


# ------------------------------------------------------- the transcript -----


def transcript(report: dict[str, Any]) -> list[str]:
    """Capture what the terminal reporter prints for this report.

    Going through the real reporter rather than formatting the lines here is
    what keeps the replay honest: if the terminal output changes, so does the
    recording, with no second implementation to keep in step.
    """
    metadata = report.get("metadata") or {}
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        terminal.print_header(
            metadata.get("account_id"),
            metadata.get("region"),
            (report.get("lab") or {}).get("caller_arn"),
            metadata.get("environment"),
        )
        for service in metadata.get("services_scanned") or []:
            terminal.print_scan_line(service)
        terminal.print_summary(report)
    return buffer.getvalue().rstrip("\n").split("\n")


# ------------------------------------------------------------- fragments ----


def tier_legend(counts: dict[str, int]) -> str:
    """All five tiers, always -- the scale legend the severity ramp requires."""
    items = []
    for tier in ordered_names():
        count = counts.get(tier, 0)
        items.append(
            f'<li><span class="swatch" style="background: var(--tier-{tier.lower()})"></span>'
            f'<span class="tier-name">{_e(Severity(tier).label)}</span>'
            f'<span class="tier-count" data-tier="{_e(tier)}">{count}</span></li>'
        )
    return '<ul class="tiers">' + "".join(items) + "</ul>"


def distribution_bar(counts: dict[str, int], total: int) -> str:
    if total <= 0:
        return '<div class="bar"><span class="bar-empty"></span></div>'
    segments = "".join(
        f'<span data-tier="{_e(tier)}" style="width: {100.0 * counts.get(tier, 0) / total:.4f}%;'
        f' background: var(--tier-{tier.lower()})" title="{_e(tier)}: {counts.get(tier, 0)}"></span>'
        for tier in ordered_names()
        if counts.get(tier, 0)
    )
    return f'<div class="bar">{segments}</div>'


def findings_table(findings: list[dict[str, Any]]) -> str:
    rows = []
    for finding in findings:
        control = (finding.get("compliance") or {}).get("control_id") or "—"
        severity = str(finding.get("severity"))
        rows.append(
            f'<tr data-severity="{_e(severity)}">'
            f'<td><span class="chip" data-tier="{_e(severity)}"'
            f' style="background: var(--tier-{severity.lower()})">{_e(severity)}</span></td>'
            f'<td class="mono">{_e(finding.get("rule_id"))}</td>'
            f'<td class="mono dim">{_e(control)}</td>'
            f'<td class="mono">{_e(finding.get("resource"))}</td>'
            f"<td>{_e(finding.get('title'))}</td></tr>"
        )
    return (
        '<table class="findings"><thead><tr><th>Severity</th><th>Rule</th><th>CIS</th>'
        f"<th>Resource</th><th>Finding</th></tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def stat(value: Any, label: str, note: str = "", value_id: str | None = None) -> str:
    """A stat tile. ``value_id`` is the hook the replay updates; the value is
    still rendered, so the tile reads correctly with scripts disabled."""
    note_html = f'<div class="stat-note">{_e(note)}</div>' if note else ""
    ident = f' id="{_e(value_id)}"' if value_id else ""
    return (
        f'<div class="stat"><div class="stat-value"{ident}>{_e(value)}</div>'
        f'<div class="stat-label">{_e(label)}</div>{note_html}</div>'
    )


# ------------------------------------------------------------ stylesheet ----


def stylesheet() -> str:
    """Shares the report's tokens, so the page and the report read as one thing."""
    light = "\n".join(f"  --tier-{t.lower()}: {c[0]};" for t, c in TIER_COLOURS.items())
    dark = "\n".join(f"    --tier-{t.lower()}: {c[1]};" for t, c in TIER_COLOURS.items())
    return f"""
:root {{
  color-scheme: light;
  --surface: #fcfcfb;
  --plane: #f9f9f7;
  --ink: #0b0b0b;
  --ink-2: #52514e;
  --muted: #898781;
  --rule: #e1e0d9;
  --edge: rgba(11,11,11,0.10);
  --term-bg: #1a1a19;
  --term-ink: #e8e7e0;
{light}
}}
@media (prefers-color-scheme: dark) {{
  :root {{
    color-scheme: dark;
    --surface: #1a1a19;
    --plane: #0d0d0d;
    --ink: #ffffff;
    --ink-2: #c3c2b7;
    --muted: #898781;
    --rule: #2c2c2a;
    --edge: rgba(255,255,255,0.10);
    --term-bg: #0d0d0d;
{dark}
  }}
}}

*,*::before,*::after {{ box-sizing: border-box; }}
body {{
  margin: 0; padding: 40px 16px 80px; background: var(--plane); color: var(--ink);
  font: 16px/1.6 system-ui, -apple-system, "Segoe UI", sans-serif;
}}
main {{ max-width: 1080px; margin: 0 auto; }}
section {{ margin: 0 0 40px; }}
h1 {{ font-size: clamp(26px, 4vw, 36px); line-height: 1.15; margin: 0 0 12px; letter-spacing: -0.02em; }}
h2 {{ font-size: 13px; letter-spacing: 0.07em; text-transform: uppercase; color: var(--ink-2);
     margin: 0 0 14px; font-weight: 600; }}
h3 {{ font-size: 17px; margin: 0 0 8px; }}
p {{ margin: 0 0 12px; max-width: 68ch; }}
a {{ color: inherit; text-underline-offset: 3px; }}
.lede {{ font-size: 18px; color: var(--ink-2); }}
.mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 13px; }}
.dim {{ color: var(--muted); }}

.card {{ background: var(--surface); border: 1px solid var(--edge); border-radius: 10px;
         padding: 22px 24px; }}
header {{ margin: 0 0 46px; }}
.badges {{ display: flex; flex-wrap: wrap; gap: 8px; margin: 20px 0 0; padding: 0; list-style: none; }}
.badges li {{ font-size: 12px; font-weight: 600; border: 1px solid var(--edge); border-radius: 999px;
              padding: 4px 12px; color: var(--ink-2); background: var(--surface); }}

/* -- controls ---------------------------------------------------------- */
.controls {{ display: none; flex-wrap: wrap; gap: 10px; align-items: center; margin: 0 0 14px; }}
.has-js .controls {{ display: flex; }}
button {{ font: inherit; font-size: 14px; font-weight: 600; cursor: pointer;
          border-radius: 999px; padding: 8px 18px; border: 1px solid var(--ink);
          background: var(--ink); color: var(--surface); }}
button.ghost {{ background: var(--surface); color: var(--ink-2); border-color: var(--edge); }}
button.ghost[aria-pressed="true"] {{ background: var(--ink); color: var(--surface); border-color: var(--ink); }}
button:disabled {{ opacity: 0.55; cursor: progress; }}
button:focus-visible {{ outline: 2px solid var(--tier-low); outline-offset: 2px; }}

/* -- terminal ---------------------------------------------------------- */
.terminal {{ background: var(--term-bg); border-radius: 10px; padding: 0 0 16px;
             border: 1px solid var(--edge); overflow: hidden; }}
.terminal-bar {{ display: flex; gap: 7px; padding: 12px 14px; border-bottom: 1px solid #2c2c2a; }}
.terminal-bar span {{ width: 11px; height: 11px; border-radius: 50%; background: #2c2c2a; }}
.terminal pre {{ margin: 0; padding: 16px 18px; color: var(--term-ink); overflow: auto;
                 font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
                 font-size: 12.5px; line-height: 1.5; height: 32em; }}
.caret {{ display: inline-block; width: 8px; height: 1em; background: var(--term-ink);
          vertical-align: text-bottom; animation: blink 1s step-end infinite; }}
@keyframes blink {{ 50% {{ opacity: 0; }} }}

/* -- result ------------------------------------------------------------ */
.hero {{ font-size: 56px; font-weight: 600; line-height: 1; letter-spacing: -0.03em; }}
.hero-sub {{ color: var(--ink-2); margin-top: 6px; }}
.bar {{ display: flex; gap: 2px; height: 22px; margin: 20px 0 16px; border-radius: 4px; }}
.bar span {{ display: block; }}
.bar span:first-child {{ border-radius: 4px 0 0 4px; }}
.bar span:last-child {{ border-radius: 0 4px 4px 0; }}
.bar-empty {{ flex: 1; background: var(--rule); border-radius: 4px; }}
.tiers {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 2px;
          list-style: none; margin: 0; padding: 0; }}
.tiers li {{ background: var(--plane); border-radius: 6px; padding: 10px 12px; }}
.swatch {{ display: inline-block; width: 10px; height: 10px; border-radius: 2px; margin-right: 7px; }}
.tier-name {{ font-size: 11px; font-weight: 700; letter-spacing: 0.06em; color: var(--ink-2);
              text-transform: uppercase; }}
.tier-count {{ display: block; font-size: 26px; font-weight: 600; margin-top: 2px;
               font-variant-numeric: tabular-nums; }}

.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 18px; }}
.stat-value {{ font-size: 30px; font-weight: 600; letter-spacing: -0.02em; }}
.stat-label {{ color: var(--ink-2); font-size: 14px; margin-top: 2px; }}
.stat-note {{ color: var(--muted); font-size: 12px; margin-top: 4px; }}

/* -- tables ------------------------------------------------------------ */
.scroll {{ overflow-x: auto; }}
table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
th, td {{ text-align: left; padding: 8px 14px 8px 0; border-bottom: 1px solid var(--rule);
          vertical-align: top; white-space: nowrap; }}
td:last-child, th:last-child {{ white-space: normal; }}
th {{ font-size: 11px; letter-spacing: 0.05em; text-transform: uppercase; color: var(--muted);
      font-weight: 600; }}
tbody tr:last-child td {{ border-bottom: none; }}
.chip {{ display: inline-block; font-size: 10px; font-weight: 700; letter-spacing: 0.06em;
         border-radius: 4px; padding: 2px 7px; color: #fcfcfb; }}
.chip[data-tier="MEDIUM"], .chip[data-tier="HIGH"] {{ color: #0b0b0b; }}

.note {{ font-size: 13px; color: var(--muted); max-width: 72ch; }}
.cta {{ display: flex; flex-wrap: wrap; gap: 10px; margin: 16px 0 0; }}
.cta a {{ font-size: 14px; font-weight: 600; text-decoration: none; border-radius: 999px;
          padding: 9px 18px; border: 1px solid var(--edge); background: var(--surface); }}
.cta a.primary {{ background: var(--ink); color: var(--surface); border-color: var(--ink); }}
pre.cmd {{ background: var(--surface); border: 1px solid var(--edge); border-radius: 8px;
           padding: 14px 16px; overflow-x: auto; font-size: 13px; margin: 0 0 12px; }}
footer {{ max-width: 1080px; margin: 48px auto 0; color: var(--muted); font-size: 13px; }}

@media (prefers-reduced-motion: reduce) {{ .caret {{ animation: none; }} }}
"""


# ------------------------------------------------------------------ page ----

# Small enough to read in full, which is the point: a visitor who wonders
# whether the numbers are real can read the page's source and the JSON blob it
# animates, and then go check that blob against results/ in the repository.
SCRIPT = """
document.documentElement.classList.add('has-js');

const DATA = JSON.parse(document.getElementById('run-data').textContent);
const still = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

const out = document.getElementById('transcript');
const runButton = document.getElementById('run');
const profileButtons = Array.from(document.querySelectorAll('[data-profile]'));
const tbody = document.querySelector('.findings tbody');

let token = 0;  // invalidates an in-flight replay when another one starts

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, still ? 0 : ms));

function setText(id, value) {
  const node = document.getElementById(id);
  if (node) node.textContent = value;
}

function paintResult(run) {
  setText('total', run.total);
  setText('resources', run.resources);
  setText('api-calls', run.apiCalls);
  setText('duration', run.duration + 's');
  setText('expected', run.expected);
  setText('tp', run.tp);
  setText('fn', run.fn);
  setText('fp', run.fp);

  document.querySelectorAll('.tier-count').forEach((node) => {
    node.textContent = run.counts[node.dataset.tier] || 0;
  });

  const bar = document.querySelector('.bar');
  bar.textContent = '';
  const tiers = Object.keys(run.counts).filter((tier) => run.counts[tier] > 0);
  if (!tiers.length) {
    const empty = document.createElement('span');
    empty.className = 'bar-empty';
    bar.appendChild(empty);
    return;
  }
  tiers.forEach((tier) => {
    const segment = document.createElement('span');
    segment.style.width = (100 * run.counts[tier]) / run.total + '%';
    segment.style.background = 'var(--tier-' + tier.toLowerCase() + ')';
    segment.title = tier + ': ' + run.counts[tier];
    bar.appendChild(segment);
  });
}

function paintFindings(run) {
  tbody.textContent = '';
  run.findings.forEach((finding) => {
    const row = document.createElement('tr');
    const chip = document.createElement('span');
    chip.className = 'chip';
    chip.dataset.tier = finding.severity;
    chip.style.background = 'var(--tier-' + finding.severity.toLowerCase() + ')';
    chip.textContent = finding.severity;

    const cells = [chip, finding.rule, finding.control, finding.resource, finding.title];
    cells.forEach((value, index) => {
      const cell = document.createElement('td');
      if (index === 0) cell.appendChild(value);
      else cell.textContent = value;
      if (index === 1 || index === 3) cell.className = 'mono';
      if (index === 2) cell.className = 'mono dim';
      row.appendChild(cell);
    });
    tbody.appendChild(row);
  });
}

async function replay(key) {
  const mine = ++token;
  const run = DATA[key];

  profileButtons.forEach((button) => {
    button.setAttribute('aria-pressed', String(button.dataset.profile === key));
  });
  runButton.disabled = true;
  runButton.textContent = 'Scanning…';
  out.textContent = '';

  for (const line of run.transcript) {
    if (mine !== token) return;            // a newer replay took over
    out.textContent += line + '\\n';
    out.scrollTop = out.scrollHeight;
    // The pauses mirror the shape of a real run: collection is the slow part,
    // and printing the findings is not.
    await sleep(line.startsWith('Scanning') ? 260 : 26);
  }
  if (mine !== token) return;

  paintResult(run);
  paintFindings(run);
  runButton.disabled = false;
  runButton.textContent = 'Run scan again';
}

runButton.addEventListener('click', () => {
  replay(document.querySelector('[data-profile][aria-pressed="true"]').dataset.profile);
});
profileButtons.forEach((button) => {
  button.addEventListener('click', () => replay(button.dataset.profile));
});
"""


def page(runs: dict[str, dict[str, Any]], primary: str, metrics: dict[str, Any]) -> str:
    run = runs[primary]
    counts = run["counts"]

    selector = "".join(
        f'<button type="button" class="ghost" data-profile="{_e(key)}"'
        f' aria-pressed="{"true" if key == primary else "false"}">{_e(runs[key]["label"])}</button>'
        for key, _, _ in PROFILES
    )

    blob = json.dumps(runs, indent=None, separators=(",", ":")).replace("</", "<\\/")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AWS Account &amp; Access Configuration Auditor</title>
<meta name="description" content="A read-only auditor for AWS IAM, S3 and CloudTrail
 configuration, demonstrated against a deliberately misconfigured account.">
<style>{stylesheet()}</style>
</head>
<body>
<main>

<header>
  <h1>AWS Account &amp; Access Configuration Auditor</h1>
  <p class="lede">A read-only tool that inspects an AWS account's IAM, S3 and CloudTrail
  configuration and reports what it observes &mdash; prioritised, evidenced, and mapped to
  CIS controls.</p>
  <ul class="badges">
    <li>{_e(metrics["security_rules"]["value"])} rules</li>
    <li>{_e(metrics["tests"]["value"])} tests</li>
    <li>{_e(metrics["fixture_cases"]["value"])} offline fixture cases</li>
    <li>{_e(metrics["coverage"]["detection_percent"])}% detection coverage</li>
    <li>CIS AWS Foundations v3.0.0</li>
    <li>Read-only, enforced at runtime</li>
  </ul>
</header>

<section>
  <h2>Watch it scan</h2>
  <p>Below is a recording of <code class="mono">python -m lab.run_benchmark</code> against the
  lab account this repository ships: an AWS account deliberately misconfigured in every way the
  14 rules exist to find. The account is emulated in-process by
  <a href="https://github.com/getmoto/moto">moto</a>, so the run needs no credentials and no
  network &mdash; but everything on the auditor's side of the endpoint is real boto3, real
  botocore signing and parsing, real paginators, real AWS error codes.</p>

  <div class="controls">
    <button type="button" id="run">Run scan</button>
    {selector}
  </div>

  <div class="terminal">
    <div class="terminal-bar"><span></span><span></span><span></span></div>
    <pre id="transcript">{_e(chr(10).join(run["transcript"]))}</pre>
  </div>
  <p class="note">This is a replay, not a scan running in your browser &mdash; a static page
  cannot make AWS API calls. Every line above is what the tool's own terminal reporter printed,
  captured from the run that produced
  <a href="aws_audit_results.json">aws_audit_results.json</a> beside this page.</p>
</section>

<section class="card">
  <h2>Result</h2>
  <div class="hero" id="total">{run["total"]}</div>
  <div class="hero-sub">findings across <span id="resources">{run["resources"]}</span> resources,
  from <span id="api-calls">{run["apiCalls"]}</span> read-only API calls in
  <span id="duration">{run["duration"]}s</span></div>
  {distribution_bar(counts, run["total"])}
  {tier_legend(counts)}
</section>

<section class="card">
  <h2>Did it find what it was supposed to?</h2>
  <p>A scanner that reports findings is not the same as a scanner that reports the
  <em>right</em> findings. Each planted misconfiguration is written down in advance &mdash; rule,
  resource and severity &mdash; and the benchmark scores the run against that list. A missed
  expectation fails the build.</p>
  <div class="stats">
    {stat(run["expected"], "Planted misconfigurations", "written down before the scan", "expected")}
    {stat(run["tp"], "Detected", "correct rule, resource and tier", "tp")}
    {stat(run["fn"], "Missed", "a scanner defect if above zero", "fn")}
    {stat(run["fp"], "Unexpected", "findings nobody planted", "fp")}
  </div>
</section>

<section>
  <h2>The findings</h2>
  <div class="scroll card">{findings_table(run["findings"])}</div>
  <p class="note">Each finding in the full report also carries its evidence, why it matters,
  how to remediate it, and a stable fingerprint for de-duplication across scans.</p>
  <div class="cta">
    <a class="primary" href="report.html">Open the full HTML report</a>
    <a href="{REPO_URL}">Source on GitHub</a>
    <a href="aws_audit_results.json">The raw JSON</a>
  </div>
</section>

<section class="card">
  <h2>Run it yourself</h2>
  <p>The same scan, on your machine, with no AWS account and no credentials:</p>
  <pre class="cmd">docker build -t account-access-auditor .
docker run --rm -v "$PWD/reports:/out" account-access-auditor</pre>
  <p>Or re-derive every number on this page &mdash; test suite, coverage, self-audit,
  policy-drift check and the scored benchmark &mdash; in one command:</p>
  <pre class="cmd">docker run --rm account-access-auditor verify</pre>
</section>

</main>
<footer>
  <p>Severity is this project's own prioritisation model. It is not a CVSS score, an AWS risk
  rating, or a formal industry classification.</p>
  <p>The audited account is emulated, not a live AWS account, and the report says so in its own
  metadata. The tool reports observed configuration: it does not attempt to prove
  exploitability, and it resolves neither service control policies, permissions boundaries, nor
  session policies.</p>
</footer>

<script type="application/json" id="run-data">{blob}</script>
<script>{SCRIPT}</script>
</body>
</html>
"""


# ------------------------------------------------------------------ main ----


def build_run(key: str, filename: str, label: str, scoring: dict[str, Any]) -> dict[str, Any]:
    report = _load(filename)
    summary = report["summary"]
    return {
        "label": label,
        "transcript": transcript(report),
        "total": summary["total_findings"],
        "counts": summary["by_severity"],
        "resources": summary["affected_resource_count"],
        "apiCalls": summary["api_call_count"],
        "duration": summary["duration_seconds"],
        "expected": scoring["expected_count"],
        "tp": scoring["true_positives"],
        "fn": scoring["false_negatives"],
        "fp": scoring["false_positives"],
        "findings": [
            {
                "severity": finding["severity"],
                "rule": finding["rule_id"],
                "control": (finding.get("compliance") or {}).get("control_id") or "—",
                "resource": finding["resource"],
                "title": finding["title"],
            }
            for finding in report["findings"]
        ],
    }


def main() -> int:
    scoring = {item["profile"]: item for item in _load("expected_vs_actual.json")["profiles"]}
    metrics = _load("metrics.json")["metrics"]

    runs = {key: build_run(key, filename, label, scoring[key]) for key, filename, label in PROFILES}
    primary = PROFILES[0][0]

    os.makedirs(SITE, exist_ok=True)
    with open(os.path.join(SITE, "index.html"), "w", encoding="utf-8") as handle:
        handle.write(page(runs, primary, metrics))

    # The report and the artifacts its numbers came from, beside the page, so a
    # reader can check the page against them without cloning anything.
    shutil.copy(os.path.join(RESULTS, "aws_audit_report.html"), os.path.join(SITE, "report.html"))
    for name in ("aws_audit_results.json", "aws_audit_results.csv", "expected_vs_actual.json"):
        shutil.copy(os.path.join(RESULTS, name), os.path.join(SITE, name))

    # Pages would otherwise hand the directory to Jekyll.
    with open(os.path.join(SITE, ".nojekyll"), "w", encoding="utf-8") as handle:
        handle.write("")

    for name in sorted(os.listdir(SITE)):
        size = os.path.getsize(os.path.join(SITE, name))
        print(f"  site/{name:<28} {size:>8,} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
