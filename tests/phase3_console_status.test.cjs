const assert = require("node:assert/strict");
const test = require("node:test");

const status = require("../scripts/console/status.js");

function render(presentation) {
  const nodes = new Map(
    ["source-label", "source-detail", "state-explainer"].map((id) => [id, { textContent: "" }]),
  );
  const document = { getElementById: (id) => nodes.get(id) };
  status.render(document, presentation);
  return Object.fromEntries([...nodes].map(([id, node]) => [id, node.textContent]));
}

test("API outage renders saved fixture mode with an explicit unavailable notice", () => {
  assert.deepEqual(render(status.apiUnavailable()), {
    "source-label": "Saved fixture data",
    "source-detail": "Live API unavailable · showing checked-in Moto reports · no credentials or cross-origin requests",
    "state-explainer": "The live API is unavailable. This page is showing checked-in fixtures; fixture data is not a live scan.",
  });
});

test("the budget kill switch renders static mode and keeps the stored snapshot visible", () => {
  assert.deepEqual(render(status.staticMode()), {
    "source-label": "Static mode active",
    "source-detail": "Budget kill switch is on · showing checked-in fixtures · last-good public snapshot remains available from the API",
    "state-explainer": "Live console mode is paused by the budget kill switch. This page is showing checked-in fixtures; public last-good scan data remains stored.",
  });
});

test("a publication failure keeps and labels the last complete snapshot", () => {
  assert.deepEqual(render(status.liveSnapshot({
    freshness: { publication_paused: true, stale: false, latest_attempt_status: null },
    completedAt: "Nov 3, 2026, 11:00 AM",
    executionStatus: "FAIL",
    gateStatus: "NOT_CONFIGURED",
  })), {
    "source-label": "Publication paused",
    "source-detail": "The last complete public snapshot remains available · publication needs review",
    "state-explainer": "Publication is paused. The console is keeping the last complete public snapshot from Nov 3, 2026, 11:00 AM.",
  });
});

test("partial and failed latest attempts stay visible as UNKNOWN or ERROR", () => {
  for (const attempt of ["UNKNOWN", "ERROR"]) {
    const rendered = render(status.liveSnapshot({
      freshness: { publication_paused: false, stale: false, latest_attempt_status: attempt },
      completedAt: "Nov 3, 2026, 11:00 AM",
      executionStatus: "FAIL",
      gateStatus: "NOT_CONFIGURED",
    }));
    assert.equal(rendered["source-label"], attempt === "UNKNOWN" ? "Incomplete scan" : "Latest scan failed");
    assert.match(rendered["source-detail"], new RegExp(`latest attempt ${attempt}`));
    assert.equal(
      rendered["state-explainer"],
      attempt === "UNKNOWN"
        ? "Incomplete scan. Service-level impact was not recorded. The console is keeping the last complete snapshot from Nov 3, 2026, 11:00 AM."
        : "Latest scan failed. Service-level impact was not recorded. The console is keeping the last complete snapshot from Nov 3, 2026, 11:00 AM.",
    );
  }
});

test("partial and failed attempts name affected services and the prior snapshot", () => {
  const partial = render(status.liveSnapshot({
    freshness: {
      publication_paused: false,
      stale: false,
      latest_attempt_status: "UNKNOWN",
      affected_services: [{ service: "s3", status: "UNKNOWN" }],
    },
    completedAt: "Nov 3, 2026, 11:00 AM",
    executionStatus: "FAIL",
    gateStatus: "NOT_CONFIGURED",
  }));
  assert.equal(partial["source-label"], "Incomplete scan");
  assert.match(partial["source-detail"], /S3: UNKNOWN/);
  assert.match(partial["state-explainer"], /incomplete scan/i);
  assert.match(partial["state-explainer"], /S3.*UNKNOWN/);
  assert.match(partial["state-explainer"], /last complete snapshot/i);

  const failed = render(status.liveSnapshot({
    freshness: {
      publication_paused: false,
      stale: false,
      latest_attempt_status: "ERROR",
      affected_services: [{ service: "iam", status: "ERROR" }],
    },
    completedAt: "Nov 3, 2026, 11:00 AM",
    executionStatus: "FAIL",
    gateStatus: "NOT_CONFIGURED",
  }));
  assert.equal(failed["source-label"], "Latest scan failed");
  assert.match(failed["source-detail"], /IAM: ERROR/);
  assert.match(failed["state-explainer"], /latest scan failed/i);
  assert.match(failed["state-explainer"], /IAM.*ERROR/);
});

test("stale data is labeled and never presented as clean", () => {
  const rendered = render(status.liveSnapshot({
    freshness: { publication_paused: false, stale: true, latest_attempt_status: null },
    completedAt: "Nov 3, 2026, 11:00 AM",
    executionStatus: "PASS",
    gateStatus: "PASS",
  }));
  assert.equal(rendered["source-label"], "Live redacted AWS data");
  assert.match(rendered["source-detail"], /snapshot stale/);
  assert.match(rendered["state-explainer"], /stale data is not a clean result/);
});

test("a fresh live snapshot reports its actual execution and gate states", () => {
  assert.deepEqual(render(status.liveSnapshot({
    freshness: { publication_paused: false, stale: false, latest_attempt_status: null },
    completedAt: "Nov 3, 2026, 11:00 AM",
    executionStatus: "FAIL",
    gateStatus: "NOT_CONFIGURED",
  })), {
    "source-label": "Live redacted AWS data",
    "source-detail": "Dedicated demo scope · read only · snapshot current",
    "state-explainer": "Live read-only snapshot · execution FAIL · security gate NOT_CONFIGURED.",
  });
});

test("Rin outage shows a prepared fixture answer and says live answers are paused", () => {
  const bubble = { textContent: "" };
  status.renderRinFallback(bubble, "Start with the saved S3 public-access finding.");
  assert.equal(
    bubble.textContent,
    "Live answers are paused. This prepared answer uses the saved Misconfigured Moto fixture.\n\nStart with the saved S3 public-access finding.",
  );
  status.renderRinFallback(bubble, "x".repeat(5000));
  assert.match(bubble.textContent, /No prepared fixture answer is available/);
  status.renderRinFallback(bubble, "The project status is pending.", "platform-knowledge");
  assert.match(bubble.textContent, /approved platform knowledge set/);
});
