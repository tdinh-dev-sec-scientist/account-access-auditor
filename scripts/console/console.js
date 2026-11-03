(function () {
  "use strict";

  const dataNode = document.getElementById("console-data");
  const root = document.getElementById("view-root");
  const dialog = document.getElementById("evidence-dialog");
  const dialogBody = document.getElementById("dialog-body");
  const dialogTitle = document.getElementById("dialog-title");
  const profiles = JSON.parse(dataNode.textContent).profiles;
  const profileKeys = Object.keys(profiles);
  const titles = {
    overview: "Security Overview",
    "aws-accounts": "AWS Accounts",
    "security-scans": "Security Scans",
    findings: "Findings",
    "drift-history": "Drift History",
    "iac-security": "IaC Security",
    "ci-cd": "CI/CD",
    "supply-chain": "Supply Chain",
    exceptions: "Exceptions",
    "ai-analyst": "AI Analyst",
    settings: "Settings",
  };
  const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const severityNames = new Set(severityOrder);
  const severityClasses = {
    CRITICAL: "critical",
    HIGH: "high",
    MEDIUM: "medium",
    LOW: "low",
    INFO: "info",
  };
  const stateClasses = { PASS: "pass", FAIL: "fail", UNKNOWN: "unknown", ERROR: "error" };
  const stateMarkers = { PASS: "✓", FAIL: "×", UNKNOWN: "?", ERROR: "!", NOT_CONFIGURED: "—" };
  let activeProfile = profiles.misconfigured ? "misconfigured" : profileKeys[0];
  let activeView = "overview";
  let activeTheme = "dark";
  let assistantWelcomed = false;

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function icon(name) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("class", "icon");
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `#icon-${name}`);
    svg.append(use);
    return svg;
  }

  function current() {
    return profiles[activeProfile];
  }

  function isMobileNavigation() {
    return window.matchMedia("(max-width: 900px)").matches;
  }

  function storedNavigationPreference() {
    try {
      const value = window.localStorage.getItem("account-access-auditor-navigation");
      return value === "collapsed" || value === "expanded" ? value : null;
    } catch (_error) {
      return null;
    }
  }

  function updateNavigationState() {
    const appFrame = document.getElementById("app-frame");
    const sidebar = document.getElementById("sidebar");
    const toggle = document.getElementById("menu-toggle");
    const backdrop = document.getElementById("sidebar-backdrop");
    const mobile = isMobileNavigation();

    if (mobile) {
      appFrame.classList.remove("is-collapsed");
      const open = sidebar.classList.contains("is-open");
      sidebar.inert = !open;
      sidebar.setAttribute("aria-hidden", String(!open));
      backdrop.hidden = !open;
      toggle.setAttribute("aria-expanded", String(open));
      toggle.setAttribute("aria-label", open ? "Close navigation" : "Open navigation");
      toggle.title = open ? "Close navigation" : "Open navigation";
    } else {
      sidebar.classList.remove("is-open");
      sidebar.inert = false;
      sidebar.removeAttribute("aria-hidden");
      backdrop.hidden = true;
      const preference = storedNavigationPreference();
      const collapsed = preference ? preference === "collapsed" : window.innerWidth <= 1220;
      appFrame.classList.toggle("is-collapsed", collapsed);
      toggle.setAttribute("aria-expanded", String(!collapsed));
      if (collapsed) {
        toggle.setAttribute("aria-label", "Expand navigation");
        toggle.title = "Expand navigation";
      } else {
        toggle.setAttribute("aria-label", "Collapse navigation");
        toggle.title = "Collapse navigation";
      }
    }

    document.querySelectorAll(".nav-item[data-view]").forEach((item) => {
      const label = item.dataset.label || item.textContent.trim().replace(/\s+/g, " ");
      if (!mobile && appFrame.classList.contains("is-collapsed")) {
        item.setAttribute("aria-label", label);
        item.title = label;
      } else {
        item.removeAttribute("aria-label");
        item.removeAttribute("title");
      }
    });
  }

  function closeMobileNavigation(focusTarget) {
    if (!isMobileNavigation()) return;
    document.getElementById("sidebar").classList.remove("is-open");
    updateNavigationState();
    if (focusTarget === "main") {
      window.scrollTo(0, 0);
      document.getElementById("main-content").focus({ preventScroll: true });
    } else if (focusTarget === "menu") {
      document.getElementById("menu-toggle").focus();
    }
  }

  function savedTheme() {
    try {
      const value = window.localStorage.getItem("account-access-auditor-theme");
      return value === "light" || value === "dark" ? value : "dark";
    } catch (_error) {
      return "dark";
    }
  }

  function applyTheme(theme, persist) {
    activeTheme = theme === "light" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", activeTheme);
    const nextTheme = activeTheme === "dark" ? "light" : "dark";
    const themeButton = document.getElementById("theme-toggle");
    themeButton.setAttribute("aria-label", `Switch to ${nextTheme} mode`);
    themeButton.title = `Switch to ${nextTheme} mode`;
    document.getElementById("theme-icon").setAttribute("href", activeTheme === "dark" ? "#icon-sun" : "#icon-moon");
    document.getElementById("theme-label").textContent = nextTheme === "light" ? "Light" : "Dark";
    if (persist) {
      try {
        window.localStorage.setItem("account-access-auditor-theme", activeTheme);
      } catch (_error) {
        // The theme still applies for this page view when browser storage is disabled.
      }
    }
  }

  function formatDate(value) {
    if (!value) return "Not recorded";
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? String(value) : parsed.toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
  }

  function formatDuration(value) {
    if (typeof value !== "number" || !Number.isFinite(value)) return "Not recorded";
    return `${value.toFixed(value < 10 ? 2 : 1)} sec`;
  }

  function readableStatus(value) {
    const normalized = String(value || "UNKNOWN").toUpperCase();
    if (normalized === "NOT_CONFIGURED") return "Not configured";
    if (normalized === "NOT_VERIFIED") return "Not verified";
    return normalized.replaceAll("_", " ");
  }

  function statusBadge(value, prefix) {
    const normalized = String(value || "UNKNOWN").toUpperCase();
    const stateClass = stateClasses[normalized] || "unknown";
    const notConfigured = normalized === "NOT_CONFIGURED" ? " status-not-configured" : "";
    const badge = element("span", `status-badge status-${stateClass}${notConfigured}`);
    const marker = element("span", "status-marker", stateMarkers[normalized] || "·");
    marker.setAttribute("aria-hidden", "true");
    badge.append(marker, element("span", "status-label", readableStatus(normalized)));
    if (prefix) badge.setAttribute("aria-label", `${prefix}: ${readableStatus(normalized)}`);
    return badge;
  }

  function severityBadge(value) {
    const severity = String(value || "UNKNOWN").toUpperCase();
    const className = severityClasses[severity] || "info";
    return element("span", `severity-badge severity-${className}`, severity);
  }

  function pageHeader(eyebrow, title, description, actions) {
    const header = element("div", "page-header");
    const copy = element("div", "page-header-copy");
    copy.append(element("span", "eyebrow", eyebrow), element("h1", "", title), element("p", "", description));
    header.append(copy);
    if (actions && actions.length) {
      const actionGroup = element("div", "page-actions");
      actions.forEach((action) => actionGroup.append(action));
      header.append(actionGroup);
    }
    return header;
  }

  function panel(title, subtitle) {
    const section = element("section", "panel");
    const head = element("div", "panel-header");
    const copy = element("div");
    copy.append(element("h2", "", title));
    if (subtitle) copy.append(element("p", "", subtitle));
    head.append(copy);
    section.append(head);
    return { section, head };
  }

  function metric(label, value, note, iconName, tone) {
    const card = element("article", "metric-card");
    const top = element("div", "metric-top");
    top.append(element("span", "", label));
    const iconBox = element("span", "metric-icon");
    iconBox.append(icon(iconName));
    top.append(iconBox);
    card.append(top);
    card.append(element("strong", `metric-value${typeof value === "string" && value.length > 5 ? " is-text" : ""}${tone ? ` ${tone}` : ""}`, value));
    card.append(element("span", "metric-note", note));
    return card;
  }

  function emptyState(title, description, iconName, actionLabel, action) {
    const box = element("section", "empty-state");
    const mark = element("span", "empty-mark");
    mark.append(icon(iconName || "scan"));
    box.append(mark, element("h2", "", title), element("p", "", description));
    if (actionLabel && action) {
      const button = element("button", "button", actionLabel);
      button.type = "button";
      button.addEventListener("click", action);
      box.append(button);
    }
    return box;
  }

  function detailItem(label, value, mono) {
    const item = element("div", "detail-item");
    item.append(element("small", "", label), element("strong", mono ? "mono" : "", value === undefined || value === null || value === "" ? "Not recorded" : value));
    return item;
  }

  function sectionRow(title, actionLabel, action) {
    const row = element("div", "section-row");
    row.append(element("h2", "", title));
    if (actionLabel && action) {
      const button = element("button", "text-button", actionLabel);
      button.type = "button";
      button.append(icon("arrow"));
      button.addEventListener("click", action);
      row.append(button);
    }
    return row;
  }

  function makeFindingsTable(findings, compact) {
    const wrap = element("div", "table-scroll");
    const table = element("table", `data-table${compact ? " compact-table" : ""}`);
    const head = document.createElement("thead");
    const headRow = document.createElement("tr");
    const columns = compact
      ? ["Severity", "Finding", "Source", "Resource", "State"]
      : ["Severity", "Finding", "Control", "Source", "Affected resource", "Detected", "State"];
    columns.forEach((name) => headRow.append(element("th", "", name)));
    head.append(headRow);
    table.append(head);
    const body = document.createElement("tbody");

    if (!findings.length) {
      const row = document.createElement("tr");
      const cell = element("td", "table-empty", "No findings match the selected filters.");
      cell.colSpan = columns.length;
      row.append(cell);
      body.append(row);
    } else {
      findings.forEach((finding) => {
        const row = document.createElement("tr");
        row.append(cellWith(severityBadge(finding.severity)));
        const titleCell = document.createElement("td");
        const open = element("button", "finding-title-button", finding.title);
        open.type = "button";
        open.addEventListener("click", () => showFinding(finding));
        titleCell.append(open, element("span", "cell-secondary", finding.ruleId));
        row.append(titleCell);

        if (!compact) row.append(cellWith(element("span", "mono", finding.controlId)));
        row.append(cellWith(element("span", "", finding.service)));
        const resource = element("span", "resource-cell", finding.resource);
        row.append(cellWith(resource));
        if (!compact) row.append(cellWith(element("span", "", formatDate(finding.detectedAt))));
        row.append(cellWith(element("span", "lifecycle-badge", readableStatus(finding.status))));
        body.append(row);
      });
    }
    table.append(body);
    wrap.append(table);
    return wrap;
  }

  function cellWith(child) {
    const cell = document.createElement("td");
    cell.append(child);
    return cell;
  }

  function recentFindings(profile, limit) {
    return profile.findings.slice(0, limit);
  }

  function renderOverview() {
    const profile = current();
    const view = document.createDocumentFragment();
    const findingsAction = element("button", "button button-primary", "Review findings");
    findingsAction.type = "button";
    findingsAction.append(icon("arrow"));
    findingsAction.addEventListener("click", () => setView("findings"));
    const reportLink = element("a", "button", "Open full report");
    reportLink.href = "../report.html";
    reportLink.append(icon("external"));
    view.append(pageHeader("Workspace / Local benchmark", "Security Overview", "Monitor the findings and scan evidence recorded in the selected local fixture.", [findingsAction, reportLink]));

    const cards = element("div", "metric-grid");
    cards.append(
      metric("Open findings", profile.openFindingCount, `${profile.findingCount} total findings in this report`, "findings"),
      metric("Critical findings", profile.severityCounts.CRITICAL || 0, "From the selected Moto fixture", "shield", (profile.severityCounts.CRITICAL || 0) ? "tone-critical" : ""),
      metric("Connected AWS accounts", "Not connected", "No account registry or live AWS integration", "cloud"),
      metric("Latest execution", readableStatus(profile.run.executionStatus), `Gate ${readableStatus(profile.run.gateStatus)} · ${formatDate(profile.run.completedAt)}`, "scan", profile.run.executionStatus === "PASS" ? "tone-success" : "")
    );
    view.append(cards);

    const grid = element("div", "content-grid");
    const severity = panel("Findings by severity", "Recorded distribution for this report · not a risk score");
    const list = element("div", "severity-list");
    severityOrder.forEach((name) => {
      const count = Number(profile.severityCounts[name] || 0);
      const row = element("div", "severity-row");
      const label = element("span", `severity-label severity-${severityClasses[name]}`, name);
      label.prepend(element("span", "severity-dot"));
      const track = document.createElementNS("http://www.w3.org/2000/svg", "svg");
      track.setAttribute("class", "severity-bar-track");
      track.setAttribute("viewBox", "0 0 100 8");
      track.setAttribute("preserveAspectRatio", "none");
      track.setAttribute("role", "img");
      track.setAttribute("aria-label", `${name}: ${count} findings`);
      const background = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      background.setAttribute("class", "severity-track-bg");
      background.setAttribute("x", "0");
      background.setAttribute("y", "0");
      background.setAttribute("width", "100");
      background.setAttribute("height", "8");
      background.setAttribute("rx", "4");
      const total = Number(profile.findingCount) || 0;
      const bar = document.createElementNS("http://www.w3.org/2000/svg", "rect");
      bar.setAttribute("class", `severity-bar severity-${severityClasses[name]}`);
      bar.setAttribute("x", "0");
      bar.setAttribute("y", "0");
      bar.setAttribute("width", String(total ? Math.min(100, (count / total) * 100) : 0));
      bar.setAttribute("height", "8");
      bar.setAttribute("rx", "4");
      track.append(background, bar);
      row.append(label, track, element("strong", "severity-value", count));
      list.append(row);
    });
    severity.section.append(list);
    severity.section.append(element("div", "chart-caption", "Snapshot only · no time-series data is available"));

    const activity = panel("Recent scan activity", "Local fixture runs included with the checked-in artifacts");
    activity.section.append(renderScanList());
    grid.append(severity.section, activity.section);
    view.append(grid);

    view.append(sectionRow("Recent findings", "View all findings", () => setView("findings")));
    const recent = element("section", "panel recent-findings");
    recent.append(makeFindingsTable(recentFindings(profile, 5), true));
    view.append(recent);

    const foot = element("div", "overview-foot-grid");
    foot.append(
      miniPanel("Posture history", "history", "Historical snapshots unavailable", "The saved fixture profiles are scenarios, not a chronological account history."),
      miniPanel("Supply chain", "package", "No artifact assessment data", "No SBOM, vulnerability assessment, or signature result is included in this static replay."),
      miniPanel("AI Analyst", "brain", "Not connected", "No AI service or generated analysis is available in this replay.")
    );
    view.append(foot);
    return view;
  }

  function miniPanel(title, iconName, state, description) {
    const box = element("section", "mini-panel");
    const heading = element("div", "mini-panel-head");
    heading.append(icon(iconName), element("span", "", title));
    box.append(heading, element("p", "", description), element("span", "mini-state", state));
    return box;
  }

  function renderScanList() {
    const list = element("div", "scan-list");
    profileKeys.forEach((key) => {
      const profile = profiles[key];
      const row = element("div", "scan-row");
      const name = element("div", "scan-name");
      const glyph = element("span", "scan-source-icon");
      glyph.append(icon("scan"));
      const copy = element("div");
      copy.append(element("strong", "", profile.label), element("small", "", `${profile.run.runId} · ${profile.region}`));
      name.append(glyph, copy);
      const meta = element("div", "scan-meta");
      meta.append(statusBadge(profile.run.executionStatus, "Execution status"), element("span", "", formatDate(profile.run.completedAt)));
      row.append(name, meta);
      list.append(row);
    });
    return list;
  }

  function renderAccounts() {
    const view = document.createDocumentFragment();
    view.append(pageHeader("Workspace / Scope", "AWS Accounts", "Review the account scope present in the local audit fixtures. No account registry is connected."));
    const notice = element("div", "callout");
    notice.append(icon("lock"), element("span", "", "These are Moto-emulated fixture profiles, not connected customer AWS accounts. Account identifiers are masked in this view; the source report remains available for evidence review."));
    view.append(notice);
    const grid = element("div", "module-grid");
    profileKeys.forEach((key) => {
      const profile = profiles[key];
      const card = element("article", "module-card profile-card");
      const top = element("div", "profile-top");
      const copy = element("div");
      copy.append(element("h2", "", profile.label), element("p", "", profile.environment));
      top.append(copy, statusBadge(profile.run.executionStatus, "Execution status"));
      card.append(top);
      const details = element("div", "detail-grid");
      details.append(
        detailItem("Fixture account", profile.accountIdSuffix ? `Account ending ${profile.accountIdSuffix}` : "Not present"),
        detailItem("Region", profile.region, true),
        detailItem("Open findings", profile.openFindingCount),
        detailItem("Collection errors", profile.collectionErrorCount),
        detailItem("Recorded at", formatDate(profile.generatedAt)),
        detailItem("AWS access", profile.readOnly ? "Read-only artifact · no live access" : "Read-only status not confirmed")
      );
      card.append(details);
      const services = element("div", "service-tags");
      profile.servicesScanned.forEach((service) => services.append(element("span", "service-tag", service)));
      card.append(services);
      grid.append(card);
    });
    view.append(grid);
    view.append(emptyState("No account registry is configured", "This static console cannot enumerate connected accounts, configured regions, or the latest live collection status. The fixture profiles above come only from the saved benchmark reports.", "cloud", "View scan records", () => setView("security-scans")));
    return view;
  }

  function renderScans() {
    const view = document.createDocumentFragment();
    view.append(pageHeader("Workspace / Run records", "Security Scans", "Execution metadata and findings are shown as separate signals for every saved fixture run."));
    const note = element("div", "scan-detail-banner");
    note.append(statusBadge(current().run.executionStatus, "Execution status"));
    note.append(element("p", "", "Execution status describes whether the scanner completed. It does not mean the findings are absent. The security gate is not configured for these benchmark runs."));
    note.append(statusBadge(current().run.gateStatus, "Gate status"));
    view.append(note);
    const tablePanel = element("section", "panel findings-panel");
    const head = element("div", "panel-header");
    const copy = element("div");
    copy.append(element("h2", "", "Saved scan runs"), element("p", "", "Two local Moto reports; not a live scan feed."));
    head.append(copy);
    tablePanel.append(head);
    const tableWrap = element("div", "table-scroll");
    const table = element("table", "data-table scan-table");
    const thead = document.createElement("thead");
    const header = document.createElement("tr");
    ["Run ID", "Scan source", "Fixture", "Completed", "Duration", "Execution", "Gate", "Findings"].forEach((label) => header.append(element("th", "", label)));
    thead.append(header);
    const tbody = document.createElement("tbody");
    profileKeys.forEach((key) => {
      const profile = profiles[key];
      const run = profile.run;
      const row = document.createElement("tr");
      row.append(cellWith(element("span", "mono", run.runId)));
      row.append(cellWith(element("span", "", run.scanSource)));
      row.append(cellWith(element("span", "", profile.label)));
      row.append(cellWith(element("span", "", formatDate(run.completedAt))));
      row.append(cellWith(element("span", "", formatDuration(run.durationSeconds))));
      row.append(cellWith(statusBadge(run.executionStatus)));
      row.append(cellWith(statusBadge(run.gateStatus)));
      row.append(cellWith(element("strong", "", run.findingCount)));
      tbody.append(row);
    });
    table.append(thead, tbody);
    tableWrap.append(table);
    tablePanel.append(tableWrap);
    view.append(tablePanel);

    const profile = current();
    const detail = element("section", "panel");
    detail.append(element("h2", "section-title", "Selected run details"));
    const items = element("div", "detail-grid");
    items.append(
      detailItem("Run ID", profile.run.runId, true),
      detailItem("Scanner version", Object.entries(profile.run.scannerVersions).map(([name, version]) => `${name} ${version}`).join(", ")),
      detailItem("Policy-pack version", profile.run.policyPackVersion || "Not recorded"),
      detailItem("Region", profile.region),
      detailItem("Started", formatDate(profile.run.startedAt)),
      detailItem("Completed", formatDate(profile.run.completedAt)),
      detailItem("Collection errors", profile.run.collectionErrorCount),
      detailItem("Reported API calls", profile.run.apiCallCount === null ? "Not recorded" : profile.run.apiCallCount)
    );
    detail.append(items);
    view.append(detail);
    return view;
  }

  function filteredFindings() {
    const profile = current();
    const query = document.getElementById("global-search").value.trim().toLocaleLowerCase();
    const severity = document.getElementById("severity-filter");
    const status = document.getElementById("state-filter");
    const selectedSeverity = severity ? severity.value : "ALL";
    const selectedStatus = status ? status.value : "ALL";
    return profile.findings.filter((finding) => {
      if (selectedSeverity !== "ALL" && String(finding.severity).toUpperCase() !== selectedSeverity) return false;
      if (selectedStatus !== "ALL" && String(finding.status).toUpperCase() !== selectedStatus) return false;
      if (!query) return true;
      const searchable = [finding.title, finding.ruleId, finding.controlId, finding.service, finding.resource, finding.status]
        .join(" ")
        .toLocaleLowerCase();
      return searchable.includes(query);
    });
  }

  function renderFindings() {
    const profile = current();
    const view = document.createDocumentFragment();
    view.append(pageHeader("Investigation / Evidence", "Findings", "Investigate deterministic findings with source, control mapping, lifecycle status, and evidence."));
    const filters = element("div", "filter-row");
    const severity = element("select");
    severity.id = "severity-filter";
    severity.setAttribute("aria-label", "Filter by severity");
    [["ALL", "All severities"], ["CRITICAL", "Critical"], ["HIGH", "High"], ["MEDIUM", "Medium"], ["LOW", "Low"], ["INFO", "Info"]].forEach(([value, label]) => {
      const option = element("option", "", label);
      option.value = value;
      severity.append(option);
    });
    const state = element("select");
    state.id = "state-filter";
    state.setAttribute("aria-label", "Filter by finding state");
    [["ALL", "All states"], ["OPEN", "Open"], ["RESOLVED", "Resolved"], ["UNKNOWN", "Unknown"]].forEach(([value, label]) => {
      const option = element("option", "", label);
      option.value = value;
      state.append(option);
    });
    const count = element("span", "filter-count", `${profile.findings.length} findings`);
    filters.append(severity, state, count);
    view.append(filters);

    const panel = element("section", "panel findings-panel");
    const tableHeader = element("div", "panel-header");
    const heading = element("div");
    heading.append(element("h2", "", "Finding inventory"), element("p", "", "Values are read from the saved report; original rule IDs and mapped controls remain distinct."));
    tableHeader.append(heading);
    panel.append(tableHeader);
    const tableSlot = element("div", "findings-table-slot");
    panel.append(tableSlot);
    view.append(panel);

    function refresh() {
      const filtered = filteredFindings();
      count.textContent = `${filtered.length} of ${profile.findings.length} findings`;
      tableSlot.replaceChildren(makeFindingsTable(filtered, false));
    }
    severity.addEventListener("change", refresh);
    state.addEventListener("change", refresh);
    refresh();
    return view;
  }

  function renderDrift() {
    const view = document.createDocumentFragment();
    view.append(pageHeader("Workspace / Continuity", "Drift History", "Compare trustworthy assessment snapshots without treating missing data as resolution."));
    const notice = element("div", "callout");
    notice.append(icon("history"), element("span", "", "The saved fixture profiles are different scenarios, not chronological snapshots of one assessment scope. They are not compared for drift, and no finding is marked resolved because it is absent from another profile."));
    view.append(notice);
    view.append(emptyState("Historical snapshots unavailable", "No local history export is included in this static site. Drift transitions require ordered ScanRun records, stable fingerprints, and comparable collection coverage.", "history", "Review available scan runs", () => setView("security-scans")));
    return view;
  }

  function renderIac() {
    const view = document.createDocumentFragment();
    view.append(pageHeader("Developer Security / Pre-deployment", "IaC Security", "Review supported static analysis inputs and the boundary between local checks and authenticated AWS validation."));
    const chips = element("div", "service-tags");
    ["Terraform", "IAM policy JSON", "Kubernetes", "Helm-rendered manifests"].forEach((name) => chips.append(element("span", "service-tag", name)));
    const supported = element("section", "panel");
    supported.append(element("h2", "section-title", "Supported input types"), chips);
    view.append(supported);

    const grid = element("div", "module-grid");
    grid.append(
      infoCard("Checkov", "Standard infrastructure checks for supported Terraform inputs.", "No IaC scan-run artifact is included in this static replay."),
      infoCard("OPA / Conftest", "Organization policy checks use the repository policy pack and preserve upstream result identifiers.", "No IaC scan-run artifact is included in this static replay."),
      infoCard("Gatekeeper", "Kubernetes admission enforcement is a separate cluster boundary, not a browser action.", "No admission event data is included in this static replay."),
      infoCard("IAM Access Analyzer", "Authenticated ValidatePolicy or CheckNoNewAccess results are distinguished from credential-free static checks.", "No authenticated Access Analyzer result is evidenced here.")
    );
    view.append(grid);
    view.append(emptyState("No IaC run data", "The repository contains IaC scanning support, but this static site is built from AWS benchmark artifacts and has no attached IaC ScanRun history. No findings are fabricated for this view.", "code", "Browse AWS findings", () => setView("findings")));
    return view;
  }

  function infoCard(title, description, note) {
    const card = element("article", "module-card");
    card.append(element("h2", "", title), element("p", "", description), element("span", "module-note", note));
    return card;
  }

  function renderCiCd() {
    const view = document.createDocumentFragment();
    view.append(pageHeader("Developer Security / Pull requests", "CI/CD", "Review security feedback from trusted workflow runs and pull requests."));
    const note = element("div", "callout");
    note.append(icon("lock"), element("span", "", "This console is a static artifact viewer. It has no workflow API connection and cannot issue AWS OIDC tokens or alter CI permissions."));
    view.append(note);
    view.append(emptyState("No CI run data", "No repository, workflow, pull request, commit, SARIF upload, or security-gate execution records are included in this static replay. Incomplete or failed scans are not represented as passing.", "pipeline", "Review IaC support", () => setView("iac-security")));
    return view;
  }

  function renderSupplyChain() {
    const view = document.createDocumentFragment();
    view.append(pageHeader("Developer Security / Artifacts", "Supply Chain", "Inspect software bill of materials, vulnerability assessment, and artifact verification evidence."));
    const grid = element("div", "module-grid");
    [
      ["SBOM generation", "No artifact assessment data"],
      ["Vulnerability assessment", "No scan result available"],
      ["Signature verification", "Not verified in this view"],
      ["Provenance", "No provenance record included"],
    ].forEach(([title, state]) => {
      const card = element("article", "module-card");
      card.append(element("h2", "", title), element("span", "module-value is-text", state), element("span", "module-note", "No supply-chain artifact record is attached to this static site."));
      grid.append(card);
    });
    view.append(grid);
    view.append(emptyState("No artifact assessment data", "There are no SBOM, Grype, Cosign, signer identity, digest, or provenance records in this static replay. An empty view does not mean an artifact is safe.", "package"));
    return view;
  }

  function renderExceptions() {
    const view = document.createDocumentFragment();
    view.append(pageHeader("Governance / Deviations", "Exceptions", "Make approved security deviations visible without removing the underlying findings."));
    const notice = element("div", "callout");
    notice.append(icon("shield"), element("span", "", "Exception workflows are not enabled. The interface is read-only; creation, approval, extension, and revocation require an authorized backend and explicit permission model."));
    view.append(notice);
    view.append(emptyState("No exception records included", "No exception registry or approval history is connected to this static console. Existing findings remain visible and unsuppressed.", "shield"));
    return view;
  }

  function renderAiAnalyst() {
    const view = document.createDocumentFragment();
    view.append(pageHeader("Intelligence / Advisory", "AI Analyst", "Evidence-grounded assistance is optional and remains separate from deterministic scanner decisions."));
    const disclaimer = element("div", "callout");
    disclaimer.append(icon("brain"), element("span", "", "AI-generated recommendations are advisory. All changes require validation and human review. AI cannot change severity, suppress findings, decide PASS/FAIL, or make AWS API calls."));
    view.append(disclaimer);
    view.append(emptyState("AI service not connected", "No model provider or AI response is configured in this static replay. Findings are not sent to an external model, and no answer or remediation patch is generated here.", "brain"));
    return view;
  }

  function renderSettings() {
    const view = document.createDocumentFragment();
    view.append(pageHeader("Administration / Platform", "Settings", "Platform settings, identity, and integration status require a defined backend and authorization model."));
    const grid = element("div", "module-grid");
    [
      ["Authentication & roles", "Not configured in static console", "Authentication provider and RBAC model are not defined here."],
      ["Backend API", "Not connected", "This static site makes no network requests."],
      ["Assessment scope", "Local Moto fixtures", "Only checked-in benchmark artifacts are available."],
      ["Credentials", "Not present in client assets", "AWS credentials and API secrets are never embedded in this console."],
    ].forEach(([title, value, note]) => {
      const card = element("article", "module-card");
      card.append(element("h2", "", title), element("span", "module-value is-text", value), element("span", "module-note", note));
      grid.append(card);
    });
    view.append(grid);
    view.append(emptyState("Configuration is read-only", "No settings can be edited through this view. Authentication, authorization, data retention, integrations, and configuration-write permissions need their own backend design.", "settings"));
    return view;
  }

  const renderers = {
    overview: renderOverview,
    "aws-accounts": renderAccounts,
    "security-scans": renderScans,
    findings: renderFindings,
    "drift-history": renderDrift,
    "iac-security": renderIac,
    "ci-cd": renderCiCd,
    "supply-chain": renderSupplyChain,
    exceptions: renderExceptions,
    "ai-analyst": renderAiAnalyst,
    settings: renderSettings,
  };

  function setView(viewName) {
    if (!renderers[viewName]) return;
    activeView = viewName;
    document.querySelectorAll(".nav-item[data-view]").forEach((item) => {
      const active = item.dataset.view === viewName;
      item.classList.toggle("is-active", active);
      if (active) item.setAttribute("aria-current", "page");
      else item.removeAttribute("aria-current");
    });
    document.getElementById("breadcrumb-current").textContent = titles[viewName];
    const timestamp = document.getElementById("snapshot-generated-at");
    timestamp.textContent = formatDate(current().generatedAt);
    if (current().generatedAt) timestamp.setAttribute("datetime", current().generatedAt);
    else timestamp.removeAttribute("datetime");
    root.replaceChildren(renderers[viewName]());
    root.setAttribute("aria-busy", "false");
    if (isMobileNavigation() && document.getElementById("sidebar").classList.contains("is-open")) {
      closeMobileNavigation("main");
    }
  }

  function setScope(key) {
    if (!profiles[key]) return;
    activeProfile = key;
    document.getElementById("scope-select").value = key;
    document.getElementById("nav-finding-count").textContent = String(current().openFindingCount);
    document.getElementById("assistant-messages").replaceChildren();
    assistantWelcomed = false;
    setView(activeView);
  }

  function answerFromFixture(question) {
    const profile = current();
    const severityCounts = profile.severityCounts || {};
    const findings = Array.isArray(profile.findings) ? profile.findings : [];
    const normalized = String(question || "").toLowerCase();
    const orderedFindings = [...findings].sort((left, right) => {
      const leftRank = severityOrder.indexOf(String(left.severity || "INFO").toUpperCase());
      const rightRank = severityOrder.indexOf(String(right.severity || "INFO").toUpperCase());
      return (leftRank < 0 ? severityOrder.length : leftRank) - (rightRank < 0 ? severityOrder.length : rightRank);
    });

    if (/\b(aws|live|connected|connection|account)\b/.test(normalized)) {
      return {
        text: `No live AWS connection here, by design. I read only the saved “${profile.label}” Moto fixture; no AWS or network call is made.`,
      };
    }
    if (/\bcritical\b/.test(normalized)) {
      return { text: `This saved report records ${Number(severityCounts.CRITICAL || 0)} CRITICAL finding(s). I keep the report's severity as-is; open a row to inspect its evidence.` };
    }
    if (/\b(high|medium|low|info)\b/.test(normalized)) {
      const severity = normalized.match(/\b(high|medium|low|info)\b/)[1].toUpperCase();
      return { text: `This saved report records ${Number(severityCounts[severity] || 0)} ${severity} finding(s). The count comes straight from the fixture.` };
    }
    if (/\b(count|how many|total|number)\b/.test(normalized)) {
      return { text: `I count ${Number(profile.findingCount || findings.length)} total finding(s), ${Number(profile.openFindingCount || 0)} still open in this report. No roll-up beyond the fixture.` };
    }
    if (/\b(top|highest|explain|remediat|priority)\b/.test(normalized)) {
      const finding = orderedFindings[0];
      if (!finding) return { text: "The selected local fixture contains no findings to explain." };
      return {
        finding,
        text: `Start here: ${finding.severity} · ${finding.title} (${finding.ruleId})\nResource: ${finding.resource}\n${finding.description}\nSuggested remediation: ${finding.remediation}\nI haven't changed anything; inspect the evidence before acting.`,
      };
    }

    const terms = normalized.split(/[^a-z0-9-]+/).filter((term) => term.length > 2);
    const matched = findings.find((finding) => {
      const searchable = [finding.title, finding.ruleId, finding.controlId, finding.service, finding.resource]
        .join(" ").toLowerCase();
      return terms.length > 0 && terms.some((term) => searchable.includes(term));
    });
    if (matched) {
      return {
        finding: matched,
        text: `Found it: ${matched.severity} · ${matched.title} (${matched.ruleId}) for ${matched.resource}. Open the row for the evidence trail and remediation guidance.`,
      };
    }
    return {
      text: "Try a severity count, a rule or resource ID, the top finding, or the demo's AWS connection state. I keep to this saved report; no hunches, no hidden data.",
    };
  }

  function appendAssistantMessage(message, role) {
    const log = document.getElementById("assistant-messages");
    const bubble = element("div", `assistant-message${role === "user" ? " is-user" : ""}`, message);
    log.append(bubble);
    log.scrollTop = log.scrollHeight;
    return bubble;
  }

  function askLocalAssistant(rawQuestion) {
    const question = String(rawQuestion || "").trim().slice(0, 500);
    if (!question) return;
    appendAssistantMessage(question, "user");
    const answer = answerFromFixture(question);
    const bubble = appendAssistantMessage(answer.text, "assistant");
    if (answer.finding) {
      const openFinding = element("button", "assistant-finding-action", "Open finding in console");
      openFinding.type = "button";
      openFinding.addEventListener("click", () => {
        const assistant = document.getElementById("assistant-dialog");
        if (assistant.open && typeof assistant.close === "function") assistant.close();
        setView("findings");
        const search = document.getElementById("global-search");
        search.value = answer.finding.title;
        search.dispatchEvent(new Event("input", { bubbles: true }));
        search.focus();
      });
      bubble.append(openFinding);
    }
  }

  function openLocalAssistant() {
    const assistant = document.getElementById("assistant-dialog");
    if (dialog.open && typeof dialog.close === "function") dialog.close();
    if (typeof assistant.showModal === "function") assistant.showModal();
    else assistant.setAttribute("open", "");
    if (!assistantWelcomed) {
      appendAssistantMessage(
        "I'm Rin. I keep the evidence close and the guesses out. Ask about this saved Moto report and I'll point you to the finding. No live AWS or AI model is connected here.",
        "assistant"
      );
      assistantWelcomed = true;
    }
    document.getElementById("assistant-input").focus();
  }

  function dialogSection(title, value, className) {
    const section = element("section", "dialog-section");
    section.append(element("h3", "", title));
    section.append(element("p", className || "", value || "Not recorded"));
    return section;
  }

  function showFinding(finding) {
    dialogTitle.textContent = finding.title;
    dialogBody.replaceChildren();
    const badges = element("div", "dialog-meta");
    badges.append(severityBadge(finding.severity), element("span", "lifecycle-badge", readableStatus(finding.status)), element("span", "lifecycle-badge mono", finding.ruleId));
    dialogBody.append(badges);
    dialogBody.append(dialogSection("Description", finding.description));
    const fields = element("div", "detail-grid");
    fields.append(
      detailItem("Affected resource", finding.resource, true),
      detailItem("Resource type", finding.resourceType),
      detailItem("Source service", finding.service),
      detailItem("Canonical control", finding.controlId),
      detailItem("Control title", finding.controlTitle),
      detailItem("Detected", formatDate(finding.detectedAt)),
      detailItem("Fingerprint", finding.fingerprint, true)
    );
    dialogBody.append(fields);
    dialogBody.append(dialogSection("Technical rationale", finding.rationale));
    dialogBody.append(dialogSection("Remediation guidance", finding.remediation));

    const evidenceSection = element("section", "dialog-section");
    const toolbar = element("div", "evidence-toolbar");
    toolbar.append(element("h3", "", "Collected evidence"));
    const copy = element("button", "button", "Copy JSON");
    copy.type = "button";
    copy.append(icon("copy"));
    const copied = element("span", "copy-status", "");
    copied.setAttribute("aria-live", "polite");
    toolbar.append(copy);
    const evidence = element("pre", "evidence-code", JSON.stringify(finding.evidence, null, 2));
    evidenceSection.append(toolbar, evidence, copied);
    dialogBody.append(evidenceSection);
    copy.addEventListener("click", async () => {
      if (!navigator.clipboard || !navigator.clipboard.writeText) {
        copied.textContent = "Clipboard access is unavailable; select the evidence text to copy it.";
        return;
      }
      try {
        await navigator.clipboard.writeText(evidence.textContent);
        copied.textContent = "Evidence copied.";
      } catch (_error) {
        copied.textContent = "Clipboard access was denied; select the evidence text to copy it.";
      }
    });
    if (typeof dialog.showModal === "function") dialog.showModal();
    else dialog.setAttribute("open", "");
  }

  document.querySelectorAll(".nav-item[data-view]").forEach((item) => {
    item.dataset.label = item.textContent.trim().replace(/\s+/g, " ");
    item.addEventListener("click", () => setView(item.dataset.view));
  });
  updateNavigationState();
  document.getElementById("scope-select").addEventListener("change", (event) => setScope(event.target.value));
  document.getElementById("theme-toggle").addEventListener("click", () => {
    applyTheme(activeTheme === "dark" ? "light" : "dark", true);
  });
  document.getElementById("global-search").addEventListener("input", (event) => {
    if (event.target.value.trim() && activeView !== "findings") setView("findings");
    else if (activeView === "findings") setView("findings");
  });
  document.getElementById("menu-toggle").addEventListener("click", (event) => {
    const sidebar = document.getElementById("sidebar");
    if (isMobileNavigation()) {
      const open = !sidebar.classList.contains("is-open");
      sidebar.classList.toggle("is-open", open);
      updateNavigationState();
      if (open) sidebar.querySelector(".nav-item[data-view]")?.focus();
      else event.currentTarget.focus();
      return;
    }

    const collapsed = document.getElementById("app-frame").classList.toggle("is-collapsed");
    try {
      window.localStorage.setItem("account-access-auditor-navigation", collapsed ? "collapsed" : "expanded");
    } catch (_error) {
      // The sidebar remains in the selected state for this page view when storage is disabled.
    }
    updateNavigationState();
  });
  document.getElementById("sidebar-backdrop").addEventListener("click", () => closeMobileNavigation("menu"));
  document.getElementById("dialog-close").addEventListener("click", () => dialog.close());
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
  const assistantDialog = document.getElementById("assistant-dialog");
  const assistantLauncher = document.getElementById("assistant-launcher");
  assistantLauncher.addEventListener("click", openLocalAssistant);
  document.getElementById("assistant-close").addEventListener("click", () => assistantDialog.close());
  assistantDialog.addEventListener("close", () => assistantLauncher.focus());
  assistantDialog.addEventListener("click", (event) => {
    if (event.target === assistantDialog) assistantDialog.close();
  });
  document.getElementById("assistant-form").addEventListener("submit", (event) => {
    event.preventDefault();
    const input = document.getElementById("assistant-input");
    askLocalAssistant(input.value);
    input.value = "";
    input.focus();
  });
  document.querySelectorAll("[data-assistant-question]").forEach((button) => {
    button.addEventListener("click", () => askLocalAssistant(button.dataset.assistantQuestion));
  });
  let mobileNavigation = isMobileNavigation();
  window.addEventListener("resize", () => {
    const nextMobileNavigation = isMobileNavigation();
    if (nextMobileNavigation !== mobileNavigation) {
      document.getElementById("sidebar").classList.remove("is-open");
      mobileNavigation = nextMobileNavigation;
    }
    updateNavigationState();
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && isMobileNavigation() && document.getElementById("sidebar").classList.contains("is-open")) {
      closeMobileNavigation("menu");
    }
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      document.getElementById("global-search").focus();
    }
  });

  document.getElementById("nav-finding-count").textContent = String(current().openFindingCount);
  applyTheme(savedTheme(), false);
  setView("overview");
})();
