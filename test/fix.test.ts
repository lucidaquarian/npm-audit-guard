import { test } from "node:test";
import assert from "node:assert/strict";
import { fixToHuman } from "../src/report.js";
import { classify } from "../src/core.js";
import { parseAuditReport } from "../src/parse.js";
import { resolveConfig } from "../src/config.js";
import { cleanReport, v7Report } from "./fixtures.js";
import type { FixResult } from "../src/fix.js";

const NOW = new Date("2026-06-26T12:00:00Z");

function audited(report: typeof v7Report) {
  return classify(parseAuditReport(report), resolveConfig({}), { now: NOW });
}

test("fixToHuman reports resolved findings when after-audit is clean", () => {
  const before = audited(v7Report);
  const after = audited(cleanReport);
  const result: FixResult = {
    before,
    after,
    resolved: before.active,
    remaining: [],
    npmOutput: "",
  };
  const out = fixToHuman(result);
  assert.match(out, /Resolved 2 blocking vulnerabilities/);
  assert.match(out, /minimist/);
  assert.match(out, /lodash/);
  assert.match(out, /PASS/);
});

test("fixToHuman flags remaining findings that could not be fixed", () => {
  const before = audited(v7Report);
  const after = audited(v7Report); // nothing changed
  const result: FixResult = {
    before,
    after,
    resolved: [],
    remaining: after.active,
    npmOutput: "",
  };
  const out = fixToHuman(result);
  assert.match(out, /could not be fixed automatically/);
  // dev-only-pkg has no fix available; lodash needs no force, minimist fixAvailable=true
  assert.match(out, /FAIL/);
});
