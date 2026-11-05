(function installPhase3ConsoleStatus(root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.Phase3ConsoleStatus = api;
})(typeof globalThis === "undefined" ? this : globalThis, function createPhase3ConsoleStatus() {
  "use strict";

  const FALLBACK_RIN_ANSWER = "No prepared fixture answer is available. The scan evidence remains visible in the console.";

  function render(document, presentation) {
    renderSource(document, presentation.sourceLabel, presentation.sourceDetail);
    renderExplainer(document, presentation.stateExplainer);
  }

  function renderSource(document, label, detail) {
    document.getElementById("source-label").textContent = label;
    document.getElementById("source-detail").textContent = detail;
  }

  function renderExplainer(document, text) {
    document.getElementById("state-explainer").textContent = text;
  }

  function fixture() {
    return {
      sourceLabel: "Saved fixture data",
      sourceDetail: "Moto emulated account · no live AWS calls",
      stateExplainer: "Execution status does not mean findings are absent. The saved fixture scan gate is NOT_CONFIGURED.",
    };
  }

  function apiUnavailable() {
    return {
      sourceLabel: "Saved fixture data",
      sourceDetail: "Live API unavailable · showing checked-in Moto reports · no credentials or cross-origin requests",
      stateExplainer: "The live API is unavailable. This page is showing checked-in fixtures; fixture data is not a live scan.",
    };
  }

  function signInRequired() {
    return {
      sourceLabel: "Sign in for live data",
      sourceDetail: "Invite-only console · showing checked-in Moto reports until you sign in",
      stateExplainer: "Live scan data and Rin are limited to invited users. This page is showing checked-in fixtures; fixture data is not a live scan.",
    };
  }

  function signInFailed() {
    return {
      sourceLabel: "Sign-in did not complete",
      sourceDetail: "Showing checked-in Moto reports · try signing in again",
      stateExplainer: "Sign-in did not complete, so no live data was requested. This page is showing checked-in fixtures; fixture data is not a live scan.",
    };
  }

  function staticMode() {
    return {
      sourceLabel: "Static mode active",
      sourceDetail: "Budget kill switch is on · showing checked-in fixtures · last-good public snapshot remains available from the API",
      stateExplainer: "Live console mode is paused by the budget kill switch. This page is showing checked-in fixtures; public last-good scan data remains stored.",
    };
  }

  function liveSnapshot({ freshness, completedAt, executionStatus, gateStatus }) {
    const allowedServices = new Set(["iam", "s3", "cloudtrail"]);
    if (
      !freshness
      || typeof freshness.stale !== "boolean"
      || (freshness.publication_paused !== undefined && typeof freshness.publication_paused !== "boolean")
      || (freshness.latest_attempt_status !== undefined
        && freshness.latest_attempt_status !== null
        && !["PASS", "FAIL", "UNKNOWN", "ERROR"].includes(freshness.latest_attempt_status))
      || (freshness.affected_services !== undefined
        && (!Array.isArray(freshness.affected_services)
          || freshness.affected_services.length > 3
          || freshness.affected_services.some((item) => (
            !item
            || typeof item !== "object"
            || !allowedServices.has(item.service)
            || !["UNKNOWN", "ERROR"].includes(item.status)
            || item.status !== freshness.latest_attempt_status
          ))))
    ) {
      throw new Error("invalid snapshot freshness");
    }

    const attempt = freshness.latest_attempt_status || null;
    const affected = (freshness.affected_services || []).map((item) => {
      const label = { iam: "IAM", s3: "S3", cloudtrail: "CloudTrail" }[item.service];
      return `${label}: ${item.status}`;
    });
    const freshnessText = attempt ? `latest attempt ${attempt}` : freshness.stale ? "snapshot stale" : "snapshot current";
    let stateExplainer;
    if (freshness.publication_paused === true) {
      stateExplainer = `Publication is paused. The console is keeping the last complete public snapshot from ${completedAt}.`;
    } else if (attempt === "UNKNOWN") {
      const serviceDetail = affected.length
        ? ` Affected services: ${affected.join(", ")}.`
        : " Service-level impact was not recorded.";
      stateExplainer = `Incomplete scan.${serviceDetail} The console is keeping the last complete snapshot from ${completedAt}.`;
    } else if (attempt === "ERROR") {
      const serviceDetail = affected.length
        ? ` Affected services: ${affected.join(", ")}.`
        : " Service-level impact was not recorded.";
      stateExplainer = `Latest scan failed.${serviceDetail} The console is keeping the last complete snapshot from ${completedAt}.`;
    } else if (freshness.stale) {
      stateExplainer = `This live snapshot is stale. Last complete scan: ${completedAt}. Findings remain visible; stale data is not a clean result.`;
    } else {
      stateExplainer = `Live read-only snapshot · execution ${executionStatus} · security gate ${gateStatus}.`;
    }

    return {
      sourceLabel: freshness.publication_paused === true
        ? "Publication paused"
        : attempt === "UNKNOWN"
          ? "Incomplete scan"
          : attempt === "ERROR"
            ? "Latest scan failed"
            : "Live redacted AWS data",
      sourceDetail: freshness.publication_paused === true
        ? "The last complete public snapshot remains available · publication needs review"
        : affected.length
          ? `Dedicated demo scope · read only · ${affected.join(" · ")} · last complete snapshot shown`
          : `Dedicated demo scope · read only · ${freshnessText}`,
      stateExplainer,
    };
  }

  function renderRinFallback(bubble, preparedAnswer, answerSource) {
    const answer = typeof preparedAnswer === "string"
      && preparedAnswer.trim()
      && preparedAnswer.length <= 4000
      ? preparedAnswer.trim()
      : FALLBACK_RIN_ANSWER;
    const source = answerSource === "platform-knowledge"
      ? "the approved platform knowledge set"
      : "the saved Misconfigured Moto fixture";
    bubble.textContent = `Live answers are paused. This prepared answer uses ${source}.\n\n${answer}`;
  }

  return {
    apiUnavailable,
    fixture,
    liveSnapshot,
    render,
    renderExplainer,
    renderRinFallback,
    renderSource,
    signInFailed,
    signInRequired,
    staticMode,
  };
});
