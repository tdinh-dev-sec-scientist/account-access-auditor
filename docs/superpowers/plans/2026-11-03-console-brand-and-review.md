# Cloud Security Console Brand and Quality Plan

> **For agentic workers:** Use `superpowers:executing-plans` and `superpowers:test-driven-development` to execute this plan. Each task ends with a checkable result. Do not commit or publish without the user's explicit approval.

**Goal:** Give the read-only security console a distinctive, responsibly researched brand and memorable local assistant, while preserving truthful Phase 2 claims and the AWS read-only boundary.

**Architecture:** Keep the existing static HTML/CSS/JavaScript console and fixture-backed data model. Apply a Sysdig-inspired information hierarchy, compact side navigation, readable system typography, and a named decorative 3D assistant; the assistant remains a deterministic local fixture helper, not a browser AI integration.

**Tech Stack:** Python build script, static HTML, CSS, vanilla JavaScript, pytest; no new runtime dependencies or external data calls.

**Spec:** `AWS_Cloud_Security_Guardrails_Phase_2_Final_Plan.docx`, its approved amendment at `docs/phase2-stage6-amendment.md`, and the supplied Phase 2 UI/UX specification.

## Global Constraints

- Preserve AWS read-only behavior; add no AWS write calls, write permissions, credentials, or infrastructure apply path.
- The DOCX remains the source of truth; the approved Stage 6 amendment changes only its direct-apply acceptance.
- Label all browser console data as saved Moto fixtures; never imply a live scan, connected model, or supported production integration.
- Keep the implementation self-hosted/static, dependency-light, and operable without external font, icon, model, or telemetry requests.
- Do not commit, push, or deploy without the user's explicit approval.

## Review Focus

- Browser storage unavailable: theme and sidebar continue to work for the current session.
- Narrow viewports and keyboard use: no hidden focus targets, clipped labels, or focus loss after closing menus/dialogs.
- Reduced-motion preference: assistant decoration stops moving while retaining its static identity.
- Untrusted report strings and questions: render as text; never create markup or network requests.
- Plan scoring: score Section 13 under its approved amendment separately from broader architecture items that require AWS writes or live external services.

## File Map

- `scripts/console/index.html`: product identity, navigation, assistant identity, disclosures.
- `scripts/console/console.css`: tokens, typography, Sysdig-inspired surfaces, responsive 3D assistant styling.
- `scripts/console/console.js`: local assistant voice and safe fixture-grounded behavior.
- `tests/test_site_build.py`: deterministic build, visible product/assistant identity, disclosure, no-network invariants.
- `docs/implementation-status.md`: only if a score or acceptance statement needs a factual correction; retain all limitations.

## Tasks

### Task 1: Choose and encode a defensible product name

**Files:** `scripts/console/index.html`, `scripts/console/console.js`, `tests/test_site_build.py`.

- [x] Search exact candidate names against current software/security use and official trademark-search guidance; select the clearest low-collision name.
- [x] Add failing tests for the document title, accessible logo name, and visible brand label.
- [x] Verify the tests fail because the current generic name is still rendered.
- [x] Update only the console's product presentation; retain repository/package identifiers.
- [x] Run the focused site-build tests.

### Task 2: Raise console design quality against the supplied reference

**Files:** `scripts/console/index.html`, `scripts/console/console.css`, `tests/test_site_build.py`.

- [x] Add failing assertions for persistent desktop navigation control, 44px targets, accessible labels, reduced-motion styling, and dark/light theme tokens.
- [x] Verify those assertions fail for the specific missing behaviors.
- [x] Refine the charcoal/purple Sysdig-inspired visual language with the supplied Inter-first system-font stack, compact sidebar, consistent page density, and restrained motion.
- [x] Keep the layout distinct from Sysdig trade dress; retain this product's AWS-first read-only labels and fixture evidence.
- [x] Run focused build tests and static JavaScript/CSS checks.

### Task 3: Give the local assistant a memorable, honest persona

**Files:** `scripts/console/index.html`, `scripts/console/console.css`, `scripts/console/console.js`, `tests/test_site_build.py`.

- [x] Add failing tests for the assistant's name, personality copy, evidence-based answer behavior, visible local-only disclosure, and absence of network calls.
- [x] Verify the tests fail on current generic copy or behavior.
- [x] Shape the CSS 3D assistant as a recognizable, restrained security sentinel with a short, precise voice; make it decorative to assistive technology and respect reduced motion.
- [x] Keep every answer grounded in the currently selected local report and preserve the visible “no model connected/no AWS calls” boundary.
- [x] Run the focused build tests and browser keyboard/responsive checks.

### Task 4: Grade plan adherence and obtain independent reviews

**Files:** No product-code changes unless a reviewer identifies a concrete defect.

- [x] Run the full pytest suite and production-site build.
- [x] Review the full uncommitted diff, verify `git diff --check`, and inspect AWS API/permission inventory for write operations.
- [x] Obtain independent plan-compliance and UI/accessibility reviews against the final implementation; request numeric scores with evidence and unresolved blockers.
- [x] Fix P0/P1 review findings using a failing regression test first, then rerun relevant and full test suites.
- [x] Report Section 13 amended acceptance and broader original-plan architecture as separate scores; never round either score upward or claim market/trademark clearance from a web search.
