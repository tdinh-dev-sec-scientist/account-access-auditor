const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");

const root = path.resolve(__dirname, "..");
const script = fs.readFileSync(path.join(root, "scripts/console/console.js"), "utf8");

test("collapsed navigation labels use explicit names instead of badge text", () => {
  assert.ok(/item\.dataset\.label = item\.getAttribute\("aria-label"\)/.test(script), "initial label should use the explicit accessible name");
  assert.ok(/item\.dataset\.label \|\| item\.getAttribute\("aria-label"\)/.test(script), "collapsed label fallback should avoid badge text");
});

test("navigation accessible names stay explicit in expanded and mobile layouts", () => {
  assert.ok(script.includes('item.setAttribute("aria-label", label);'), "each nav item should keep its explicit accessible name");
  assert.ok(!script.includes('item.removeAttribute("aria-label")'), "layout changes should not expose badge text as the name");
});

test("mobile navigation makes obscured controls inert and restores them on close", () => {
  for (const name of ["workspace", "skipLink", "assistantLauncher"]) {
    assert.ok(new RegExp(`${name}\\.inert = open`).test(script), `${name} should be inert while the drawer is open`);
    assert.ok(new RegExp(`${name}\\.inert = false`).test(script), `${name} should be restored when the drawer closes`);
  }
});
