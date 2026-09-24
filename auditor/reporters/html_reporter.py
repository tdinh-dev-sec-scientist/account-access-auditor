"""HTML reporter: the report a reviewer reads, and the one that gets archived.

Three properties drive every decision in this module, and each has a test behind
it in ``tests/test_reporters.py``:

**The report contains no JavaScript.** Not "no third-party JavaScript" -- none at
all. Severity and service filtering is done with radio inputs and CSS ``:has()``,
so the file renders fully under ``script-src 'none'``, which the embedded CSP
meta tag declares. A findings report is handed to auditors, attached to tickets,
and opened years later; it should not be a program.

**The report loads nothing from the network.** No CDN stylesheet, no web font, no
tracking pixel. Everything is inline, so the file is self-contained, works
offline and air-gapped, and cannot phone home about which account was scanned.

**Every value from the audited account is escaped.** This is the one that matters
most: bucket names, IAM user names, policy documents, and CloudTrail error
strings are attacker-influenced input. A bucket named ``<img onerror=...>`` is a
legal bucket name, and rendering it unescaped would turn a security report into
the delivery vehicle. Interpolation goes through ``_e()`` without exception;
numbers that reach CSS (segment widths) are formatted from integer counts, never
from account strings.

Colour: the five severity tiers are an ordered *semantic heat* ramp -- the one
multi-hue exception the visualisation guidance allows, on the condition that a
scale legend is always present. It is: the tier row is zero-filled, so all five
tiers appear with their name and count on every report, including the tiers that
did not fire. No mark anywhere carries meaning by hue alone.
"""

from __future__ import annotations

import html
import json
import logging
import os
from typing import Any

from ..severity import Severity, ordered_names

log = logging.getLogger(__name__)

# Severity ramp. CRITICAL/HIGH/MEDIUM are the reserved status steps (fixed in
# both themes by design); LOW and INFO step down into blue and neutral grey,
# because "low" and "informational" should not wear an alarm colour.
TIER_COLOURS: dict[str, tuple[str, str]] = {
    # tier:       (light,     dark)
    "CRITICAL": ("#d03b3b", "#d03b3b"),
    "HIGH": ("#ec835a", "#ec835a"),
    "MEDIUM": ("#fab219", "#fab219"),
    "LOW": ("#2a78d6", "#3987e5"),
    "INFO": ("#898781", "#898781"),
}

# HIGH and MEDIUM sit closer together than the normal-vision separation floor
# wants, and on the light surface HIGH and MEDIUM fall below 3:1 against it.
# Both are discharged the same way rather than by re-stepping the ramp: every
# tier is always written out as text beside its swatch, and the by-severity and
# by-rule tables carry every number the bar encodes. Nothing is gated behind
# telling two oranges apart.

CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'"

EVIDENCE_INLINE_LIMIT = 160


def _e(value: Any) -> str:
    """Escape anything on its way into the document. No exceptions."""
    return html.escape("" if value is None else str(value), quote=True)


def _wide_class(wide: bool) -> str:
    return ' class="wide"' if wide else ""


def _slug(value: str) -> str:
    """A CSS/id-safe token. Only ever fed closed vocabularies (tiers, services)."""
    return "".join(character if character.isalnum() else "-" for character in str(value).lower())


# ----------------------------------------------------------------- styling --


def _stylesheet() -> str:
    """One stylesheet, generated so the tier colours have a single source."""
    light = "\n".join(f"    --tier-{_slug(t)}: {c[0]};" for t, c in TIER_COLOURS.items())
    dark = "\n".join(f"    --tier-{_slug(t)}: {c[1]};" for t, c in TIER_COLOURS.items())

    # Filtering: a radio per tier plus "all". `:has()` on the root lets a
    # checked radio hide the rows that do not match, with no script involved.
    tier_filters = "\n".join(
        f'  body:has(#f-sev-{_slug(t)}:checked) .finding:not([data-severity="{t}"]) {{ display: none; }}'
        for t in ordered_names()
    )

    return f"""
:root {{
    color-scheme: light;
    --surface: #fcfcfb;
    --plane: #f9f9f7;
    --ink: #0b0b0b;
    --ink-2: #52514e;
    --muted: #898781;
    --rule: #e1e0d9;
    --edge: rgba(11, 11, 11, 0.10);
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
    --edge: rgba(255, 255, 255, 0.10);
{dark}
  }}
}}

*, *::before, *::after {{ box-sizing: border-box; }}

body {{
    margin: 0;
    padding: 32px 16px 64px;
    background: var(--plane);
    color: var(--ink);
    font: 15px/1.55 system-ui, -apple-system, "Segoe UI", sans-serif;
}}
main {{ max-width: 1040px; margin: 0 auto; }}

h1 {{ font-size: 21px; margin: 0 0 4px; letter-spacing: -0.01em; }}
h2 {{ font-size: 15px; margin: 0 0 12px; letter-spacing: 0.04em; text-transform: uppercase;
      color: var(--ink-2); font-weight: 600; }}
h3 {{ font-size: 15px; margin: 0; font-weight: 600; }}
p {{ margin: 0 0 10px; }}
a {{ color: inherit; }}

.card {{
    background: var(--surface);
    border: 1px solid var(--edge);
    border-radius: 8px;
    padding: 20px 22px;
    margin: 0 0 18px;
}}

/* -- header ------------------------------------------------------------- */

.masthead {{ display: flex; flex-wrap: wrap; gap: 14px; align-items: baseline;
             justify-content: space-between; margin-bottom: 4px; }}
.badge {{
    font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;
    border: 1px solid var(--edge); border-radius: 999px; padding: 3px 10px; color: var(--ink-2);
    white-space: nowrap;
}}
.env {{ color: var(--ink-2); font-size: 13px; margin: 6px 0 0; }}

dl.facts {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(190px, 1fr));
            gap: 12px 24px; margin: 18px 0 0; }}
dl.facts div {{ min-width: 0; }}
dl.facts div.wide {{ grid-column: 1 / -1; }}
dl.facts dt {{ font-size: 11px; letter-spacing: 0.06em; text-transform: uppercase;
               color: var(--muted); margin-bottom: 2px; }}
dl.facts dd {{ margin: 0; font-size: 14px; overflow-wrap: anywhere; }}

/* -- hero + tier legend -------------------------------------------------- */

.hero {{ font-size: 52px; line-height: 1; font-weight: 600; letter-spacing: -0.02em; }}
.hero-label {{ color: var(--ink-2); font-size: 14px; margin-top: 6px; }}

.bar {{ display: flex; gap: 2px; height: 22px; margin: 22px 0 18px; border-radius: 4px; }}
.bar span {{ display: block; }}
.bar span:first-child {{ border-radius: 4px 0 0 4px; }}
.bar span:last-child {{ border-radius: 0 4px 4px 0; }}
.bar-empty {{ background: var(--rule); flex: 1; border-radius: 4px; }}

.tiers {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
          gap: 2px; list-style: none; margin: 0; padding: 0; }}
.tiers li {{ padding: 10px 12px; border-radius: 6px; background: var(--plane); }}
.tiers .swatch {{ display: inline-block; width: 10px; height: 10px; border-radius: 2px;
                  margin-right: 7px; vertical-align: baseline; }}
.tiers .name {{ font-size: 11px; font-weight: 700; letter-spacing: 0.07em; color: var(--ink-2); }}
.tiers .count {{ display: block; font-size: 26px; font-weight: 600; margin-top: 2px; }}
.tiers li[data-zero="true"] .count {{ color: var(--muted); font-weight: 500; }}

/* -- tables -------------------------------------------------------------- */

table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
caption {{ text-align: left; font-size: 11px; letter-spacing: 0.06em; text-transform: uppercase;
           color: var(--muted); padding-bottom: 8px; }}
th, td {{ text-align: left; padding: 7px 10px 7px 0; border-bottom: 1px solid var(--rule);
          vertical-align: top; }}
th {{ font-size: 11px; letter-spacing: 0.05em; text-transform: uppercase; color: var(--muted);
      font-weight: 600; }}
td.n, th.n {{ text-align: right; font-variant-numeric: tabular-nums; padding-right: 0; }}
tbody tr:last-child td {{ border-bottom: none; }}
.split {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 26px; }}

/* -- filters ------------------------------------------------------------- */

.filters {{ display: flex; flex-wrap: wrap; gap: 6px; align-items: center; margin: 0 0 16px; }}
.filters input {{ position: absolute; opacity: 0; pointer-events: none; }}
.filters label {{
    font-size: 12px; font-weight: 600; letter-spacing: 0.03em;
    border: 1px solid var(--edge); border-radius: 999px; padding: 5px 12px;
    cursor: pointer; color: var(--ink-2); background: var(--surface);
}}
.filters label:hover {{ border-color: var(--muted); }}
.filters input:checked + label {{ background: var(--ink); color: var(--surface);
                                  border-color: var(--ink); }}
.filters input:focus-visible + label {{ outline: 2px solid var(--tier-low); outline-offset: 2px; }}
.filters .sep {{ width: 1px; height: 20px; background: var(--rule); margin: 0 6px; }}

{tier_filters}

/* -- findings ------------------------------------------------------------ */

.finding {{ border-top: 1px solid var(--rule); padding: 18px 0 16px; }}
.finding:first-of-type {{ border-top: none; padding-top: 0; }}
.finding-head {{ display: flex; flex-wrap: wrap; gap: 8px 10px; align-items: center; }}
.chip {{
    font-size: 11px; font-weight: 700; letter-spacing: 0.06em; border-radius: 4px;
    padding: 2px 7px; color: #fcfcfb; white-space: nowrap;
}}
.chip[data-tier="MEDIUM"], .chip[data-tier="HIGH"] {{ color: #0b0b0b; }}
.meta {{ font-size: 12px; color: var(--muted); font-variant-numeric: tabular-nums; }}
.resource {{ font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 13px;
             overflow-wrap: anywhere; }}
.finding h3 {{ margin: 9px 0 0; font-size: 16px; letter-spacing: -0.005em; }}
.finding p {{ margin: 8px 0 0; }}
.finding .why, .finding .fix {{ font-size: 14px; color: var(--ink-2); }}
.finding .fix strong, .finding .why strong {{ color: var(--ink); font-weight: 600; }}

dl.evidence {{ margin: 12px 0 0; padding: 12px 14px; background: var(--plane);
               border-radius: 6px; font-size: 13px; }}
dl.evidence div {{ display: flex; gap: 10px; padding: 2px 0; }}
dl.evidence dt {{ color: var(--muted); flex: 0 0 auto; width: 170px; overflow-wrap: anywhere; }}
dl.evidence dd {{ margin: 0; flex: 1 1 auto; overflow-wrap: anywhere;
                  font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }}
dl.evidence pre {{ margin: 0; white-space: pre-wrap; overflow-wrap: anywhere; font-size: 12px; }}

.empty {{ color: var(--ink-2); margin: 0; }}
.errors {{ border-left: 3px solid var(--tier-high); }}
footer {{ max-width: 1040px; margin: 0 auto; color: var(--muted); font-size: 12px; }}
footer p {{ margin: 0 0 8px; }}

/* -- print --------------------------------------------------------------- */

@media print {{
    body {{ background: #ffffff; padding: 0; }}
    .filters {{ display: none; }}
    .card {{ break-inside: avoid; border-color: #cccccc; }}
    .finding {{ break-inside: avoid; }}
    /* A filter must never remove a finding from the printed record. */
    .finding {{ display: block !important; }}
}}
"""


# ------------------------------------------------------------------ pieces --


def _facts(report: dict[str, Any]) -> list[tuple[str, str, bool]]:
    """(label, value, spans_the_full_row) for the header's provenance block."""
    metadata = report.get("metadata") or {}
    summary = report.get("summary") or {}
    scanned = summary.get("resources_scanned") or {}

    duration = summary.get("duration_seconds")
    calls = summary.get("api_call_count")
    api = "not recorded"
    if calls is not None:
        api = f"{calls}" + (f" in {duration}s" if duration is not None else "")

    return [
        ("Account", metadata.get("account_id") or "unknown", False),
        ("Region", metadata.get("region") or "default", False),
        ("Generated", metadata.get("generated_at") or "unknown", False),
        ("Run ID", metadata.get("run_id") or "-", False),
        ("Services scanned", ", ".join(metadata.get("services_scanned") or []) or "none", False),
        ("Rules evaluated", str(len(metadata.get("rules_evaluated") or [])), False),
        ("Benchmark", metadata.get("compliance_framework") or "-", False),
        ("Read-only API calls", api, False),
        ("Tool version", metadata.get("tool_version") or "-", False),
        # Long and variable-length, so it gets the whole row rather than
        # punching a ragged hole in the grid.
        (
            "Resources read",
            ", ".join(f"{k}={v}" for k, v in sorted(scanned.items())) or "none recorded",
            True,
        ),
    ]


def _distribution_bar(counts: dict[str, int], total: int) -> str:
    """One stacked bar. Widths come from integer counts, never from account data."""
    if total <= 0:
        return '<div class="bar"><span class="bar-empty"></span></div>'

    segments = []
    for tier in ordered_names():
        count = counts.get(tier, 0)
        if not count:
            continue  # a zero tier gets no segment; the legend still lists it
        width = 100.0 * count / total
        segments.append(
            f'<span style="width: {width:.4f}%; background: var(--tier-{_slug(tier)});"'
            f' title="{_e(tier)}: {count}"></span>'
        )
    return '<div class="bar" role="presentation">' + "".join(segments) + "</div>"


def _tier_legend(counts: dict[str, int]) -> str:
    """The scale legend for the severity ramp. Always all five tiers."""
    items = []
    for tier in ordered_names():
        count = counts.get(tier, 0)
        items.append(
            f'<li data-zero="{"true" if not count else "false"}">'
            f'<span class="swatch" style="background: var(--tier-{_slug(tier)});"></span>'
            f'<span class="name">{_e(Severity(tier).label)}</span>'
            f'<span class="count">{count}</span></li>'
        )
    return '<ul class="tiers">' + "".join(items) + "</ul>"


def _table(caption: str, heading: str, rows: list[tuple[str, ...]], columns: list[str]) -> str:
    """A small two- or three-column tally table, or an explicit empty state."""
    if not rows:
        return (
            f"<table><caption>{_e(caption)}</caption><tbody><tr>"
            f'<td class="empty">none</td></tr></tbody></table>'
        )
    head = f"<th>{_e(heading)}</th>" + "".join(f'<th class="n">{_e(column)}</th>' for column in columns)
    body = "".join(
        "<tr><td>"
        + _e(row[0])
        + "</td>"
        + "".join(f'<td class="n">{_e(cell)}</td>' for cell in row[1:])
        + "</tr>"
        for row in rows
    )
    return (
        f"<table><caption>{_e(caption)}</caption><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"
    )


def _tally_table(caption: str, heading: str, tally: dict[str, int]) -> str:
    rows = [
        (key, str(int(value))) for key, value in sorted(tally.items(), key=lambda item: (-item[1], item[0]))
    ]
    return _table(caption, heading, rows, ["Findings"])


def _severity_table(counts: dict[str, int], total: int) -> str:
    """The table view that relieves the ramp's sub-floor colour pairs.

    Always all five tiers, so a reader never has to infer a zero from a missing
    row, and never has to tell two oranges apart to read a count.
    """
    rows = []
    for tier in ordered_names():
        count = counts.get(tier, 0)
        share = f"{(100.0 * count / total):.1f}%" if total else "-"
        rows.append((Severity(tier).label, str(count), share))
    return _table("By severity", "Severity", rows, ["Findings", "Share"])


def _collection_errors(errors: list[dict[str, Any]]) -> str:
    """Rendered before the findings, because an unread resource is a coverage gap."""
    if not errors:
        return (
            '<section class="card"><h2>Collection coverage</h2>'
            '<p class="empty">Every declared read succeeded. No resource was skipped, so the '
            "findings below cover everything the auditor was permitted to inspect.</p></section>"
        )

    rows = "".join(
        f"<tr><td>{_e(error.get('service'))}</td>"
        f'<td class="resource">{_e(error.get("operation"))}</td>'
        f'<td class="resource">{_e(error.get("resource") or "-")}</td>'
        f"<td>{_e(error.get('code'))}</td>"
        f"<td>{_e(error.get('message') or '')}</td></tr>"
        for error in errors
    )
    return (
        '<section class="card errors"><h2>Collection errors '
        f"({len(errors)})</h2>"
        "<p>These resources could not be fully read, so no rule could evaluate them. "
        "<strong>Absence of a finding here is absence of data, not evidence of correct "
        "configuration.</strong></p>"
        "<table><thead><tr><th>Service</th><th>Operation</th><th>Resource</th><th>Code</th>"
        f"<th>Message</th></tr></thead><tbody>{rows}</tbody></table></section>"
    )


def _evidence(evidence: dict[str, Any]) -> str:
    if not evidence:
        return ""
    rows = []
    for key, value in evidence.items():
        if isinstance(value, dict | list):
            rendered = json.dumps(value, indent=2, sort_keys=True, default=str)
            body = f"<pre>{_e(rendered)}</pre>"
        else:
            text = str(value)
            body = f"<pre>{_e(text)}</pre>" if len(text) > EVIDENCE_INLINE_LIMIT else _e(text)
        rows.append(f"<div><dt>{_e(key)}</dt><dd>{body}</dd></div>")
    return '<dl class="evidence">' + "".join(rows) + "</dl>"


def _framework_short(framework: str | None) -> str:
    """ "CIS AWS Foundations Benchmark v3.0.0" -> "CIS"; the full name is the tooltip."""
    if not framework:
        return "control"
    return str(framework).split()[0]


def _finding(finding: dict[str, Any]) -> str:
    severity = str(finding.get("severity", "INFO"))
    compliance = finding.get("compliance") or {}
    control = compliance.get("control_id")
    control_bit = (
        f'<span class="meta" title="{_e(compliance.get("framework") or "")}">'
        f"{_e(_framework_short(compliance.get('framework')))} {_e(control)}</span>"
        if control
        else '<span class="meta">no mapped control</span>'
    )

    parts = [
        f'<article class="finding" data-severity="{_e(severity)}"'
        f' data-service="{_e(finding.get("service"))}">',
        '<div class="finding-head">',
        f'<span class="chip" data-tier="{_e(severity)}"'
        f' style="background: var(--tier-{_slug(severity)});">{_e(severity)}</span>',
        f'<span class="meta">{_e(finding.get("rule_id"))}</span>',
        f'<span class="meta">{_e(finding.get("service"))}</span>',
        control_bit,
        "</div>",
        f"<h3>{_e(finding.get('title'))}</h3>",
        f'<p class="resource">{_e(finding.get("resource"))}</p>',
        f"<p>{_e(finding.get('description'))}</p>",
    ]
    if finding.get("rationale"):
        parts.append(f'<p class="why"><strong>Why it matters.</strong> {_e(finding["rationale"])}</p>')
    parts.append(_evidence(finding.get("evidence") or {}))
    if finding.get("remediation"):
        parts.append(f'<p class="fix"><strong>Remediation.</strong> {_e(finding["remediation"])}</p>')
    parts.append(
        f'<p class="meta">fingerprint {_e(finding.get("fingerprint"))}'
        f" · detected {_e(finding.get('detected_at'))}</p>"
    )
    parts.append("</article>")
    return "".join(parts)


def _filters(findings: list[dict[str, Any]], counts: dict[str, int]) -> str:
    """Radio inputs only. The CSS in ``_stylesheet`` does the hiding."""
    if not findings:
        return ""
    controls = [
        '<div class="filters">',
        '<input type="radio" name="sev" id="f-sev-all" checked>',
        f'<label for="f-sev-all">All {len(findings)}</label>',
        '<span class="sep" role="presentation"></span>',
    ]
    for tier in ordered_names():
        count = counts.get(tier, 0)
        if not count:
            continue
        controls.append(f'<input type="radio" name="sev" id="f-sev-{_slug(tier)}">')
        controls.append(f'<label for="f-sev-{_slug(tier)}">{_e(tier)} {count}</label>')
    controls.append("</div>")
    return "".join(controls)


# ------------------------------------------------------------------ render --


def render(report: dict[str, Any]) -> str:
    """The whole report as one self-contained HTML document."""
    metadata = report.get("metadata") or {}
    summary = report.get("summary") or {}
    findings: list[dict[str, Any]] = report.get("findings") or []
    counts: dict[str, int] = summary.get("by_severity") or {}
    total = int(summary.get("total_findings") or 0)

    account = metadata.get("account_id") or "unknown account"
    title = f"AWS access configuration audit - {account}"

    facts = "".join(
        f"<div{_wide_class(wide)}><dt>{_e(label)}</dt><dd>{_e(value)}</dd></div>"
        for label, value, wide in _facts(report)
    )

    environment = metadata.get("environment")
    env_line = f'<p class="env">{_e(environment)}</p>' if environment else ""

    if findings:
        body = "".join(_finding(finding) for finding in findings)
        heading = f"Findings ({total})"
    else:
        body = (
            '<p class="empty">No findings at or above the configured severity threshold. '
            "Read the collection coverage section above before reading this as a clean "
            "account.</p>"
        )
        heading = "Findings"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{CSP}">
<meta name="robots" content="noindex, nofollow">
<meta name="generator" content="account-access-auditor {_e(metadata.get("tool_version") or "")}">
<title>{_e(title)}</title>
<style>{_stylesheet()}</style>
</head>
<body>
<main>

<section class="card">
  <div class="masthead">
    <div>
      <h1>AWS Account &amp; Access Configuration Audit</h1>
      <p class="env">Observed configuration of IAM, S3, and CloudTrail. Read-only scan.</p>
      {env_line}
    </div>
    <span class="badge">Read-only</span>
  </div>
  <dl class="facts">{facts}</dl>
</section>

<section class="card">
  <h2>Result</h2>
  <div class="hero">{total}</div>
  <div class="hero-label">findings across {int(summary.get("affected_resource_count") or 0)} resources</div>
  {_distribution_bar(counts, total)}
  {_tier_legend(counts)}
</section>

{_collection_errors(report.get("collection_errors") or [])}

<section class="card">
  <h2>Breakdown</h2>
  <div class="split">
    {_severity_table(counts, total)}
    {_tally_table("By service", "Service", summary.get("by_service") or {})}
    {_tally_table("By rule", "Rule", summary.get("by_rule") or {})}
    {_tally_table("By resource type", "Resource type", summary.get("by_resource_type") or {})}
  </div>
</section>

<section class="card">
  <h2>{_e(heading)}</h2>
  {_filters(findings, counts)}
  {body}
</section>

</main>
<footer>
  <p>{_e(metadata.get("severity_disclaimer") or "")}</p>
  <p>This report describes observed configuration. It does not attempt to prove
  exploitability, and it does not resolve service control policies, permissions
  boundaries, or session policies.</p>
  <p>Generated by account-access-auditor {_e(metadata.get("tool_version") or "")}. This document
  contains no scripts and loads nothing from the network.</p>
</footer>
</body>
</html>
"""


def write(report: dict[str, Any], path: str) -> str:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(render(report))
    log.info("Wrote HTML report: %s", path)
    return path
