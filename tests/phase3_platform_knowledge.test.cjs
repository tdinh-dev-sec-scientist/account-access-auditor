const assert = require("node:assert/strict");
const test = require("node:test");

let knowledge = null;
try {
  knowledge = require("../scripts/console/knowledge.js");
} catch (_error) {
  // The assertion below makes a missing production module a normal test failure.
}

function answerPlatformQuestion(question) {
  assert.ok(knowledge, "the production platform knowledge module is available");
  return knowledge.answerPlatformQuestion(question);
}

test("platform questions use versioned, cited approved knowledge", () => {
  const answer = answerPlatformQuestion("What does this platform do?");
  assert.equal(answer.version, "1.0.0");
  assert.match(answer.text, /read-only/i);
  assert.ok(answer.citations.includes("README.md · What Phase 2 includes"));
});

test("knowledge clearly reports that Phase 3 live acceptance is pending", () => {
  const answer = answerPlatformQuestion("Is the Phase 3 website live?");
  assert.equal(answer.version, "1.0.0");
  assert.match(answer.text, /no live stage gate has passed/i);
  assert.ok(answer.citations.includes("docs/phase3-status.md · Stage status"));
});

test("unsupported platform questions do not receive invented knowledge", () => {
  assert.equal(answerPlatformQuestion("What is the AWS account number?"), null);
});

test("Rin boundary answer distinguishes AWS reads from internal quota writes", () => {
  const answer = answerPlatformQuestion("Does Rin write to AWS?");
  const permissionsAnswer = answerPlatformQuestion("What permissions does Rin have?");
  assert.match(answer.text, /scan worker reads target AWS resources only/i);
  assert.match(answer.text, /public API reads sanitized scan data and its feature flag/i);
  assert.match(answer.text, /Rin reads sanitized scan data, its feature flag, and its provider secret/i);
  assert.match(answer.text, /quota function.*writes per-session and daily counters/i);
  assert.match(answer.text, /cannot change target AWS resources or scan results/i);
  assert.equal(permissionsAnswer.id, "read-only-boundary");
  assert.match(permissionsAnswer.text, /Rin's role writes only to its own CloudWatch log group/i);
  assert.ok(permissionsAnswer.citations.includes("infra/phase3/control-plane/stage3.tf · Rin runtime and log policy"));
  assert.ok(permissionsAnswer.citations.includes(".github/workflows/phase3-terraform.yml · Protected apply"));
});

test("Rin knowledge explains input and output Guardrail checks with fixture fallback", () => {
  const answer = answerPlatformQuestion("How does Rin's Guardrail protect prompts?");
  assert.equal(answer.id, "rin-privacy");
  assert.match(answer.text, /checks the bounded redacted input before the external model/i);
  assert.match(answer.text, /validates the answer before it reaches the visitor/i);
  assert.match(answer.text, /Guardrail error selects the fixture fallback/i);
  assert.ok(answer.citations.includes("docs/phase3-bootstrap.md · Rin Bedrock Guardrail"));
});

test("a finding question addressed to Rin does not trigger platform privacy boilerplate", () => {
  assert.equal(answerPlatformQuestion("Rin, how many findings?"), null);
});

test("approved knowledge covers architecture, IaC, controls, drift, and cost status", () => {
  const cases = [
    ["How does data flow through this platform?", /private snapshot/i, "docs/phase3-status.md"],
    ["What file types can IaC scanning handle?", /Terraform.*Kubernetes/i, "docs/iac-scanning.md"],
    ["What CIS controls are mapped?", /11 of 14/i, "docs/cis-mapping.md"],
    ["How does drift handle an incomplete scan?", /UNKNOWN/i, "docs/fleet-scanning.md"],
    ["What monthly budget is approved?", /AWS pricing estimate or monthly AWS cap.*both are required before Stage 2/i, "docs/costs.md"],
    ["How does budget enforcement work?", /Rin must also stay disabled until a provider and model.*separate AI budget/i, "docs/phase3-status.md"],
  ];

  for (const [question, expectedAnswer, source] of cases) {
    const answer = answerPlatformQuestion(question);
    assert.ok(answer, `knowledge should answer: ${question}`);
    assert.match(answer.text, expectedAnswer);
    assert.ok(answer.citations.some((citation) => citation.startsWith(source)));
  }
});

test("topic keywords do not divert finding-specific questions to platform answers", () => {
  for (const question of [
    "Explain the Terraform finding in this report.",
    "Which CIS control applies to this finding?",
    "What is the cost impact of this resource?",
  ]) {
    assert.equal(answerPlatformQuestion(question), null, question);
  }
});

test("natural topic questions resolve to the matching knowledge entry", () => {
  const cases = [
    ["How does IaC scanning work?", "iac-inputs"],
    ["How does CIS mapping work?", "cis-coverage"],
    ["How does drift work?", "drift-semantics"],
    ["How does budget enforcement work?", "budget-status"],
    ["Which CIS control IDs are mapped?", "cis-coverage"],
    ["What rule IDs does the catalog cover?", "rule-catalog"],
    ["What is Rin's monthly budget?", "budget-status"],
  ];

  for (const [question, expectedId] of cases) {
    const answer = answerPlatformQuestion(question);
    assert.ok(answer, `knowledge should answer: ${question}`);
    assert.equal(answer.id, expectedId, question);
  }
});
