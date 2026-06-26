import { test } from "node:test";
import assert from "node:assert/strict";
import { parseAuditReport, sortFindings } from "../src/parse.js";
import { cleanReport, v6Report, v7Report } from "./fixtures.js";

test("parses npm v7 report into findings with counts", () => {
  const { findings, counts } = parseAuditReport(v7Report);
  assert.equal(findings.length, 4);
  assert.deepEqual(counts, {
    info: 0,
    low: 1,
    moderate: 1,
    high: 1,
    critical: 1,
  });
});

test("extracts GHSA id, title, and direct flag from v7 via entries", () => {
  const { findings } = parseAuditReport(v7Report);
  const lodash = findings.find((f) => f.name === "lodash");
  assert.ok(lodash);
  assert.equal(lodash.severity, "high");
  assert.equal(lodash.direct, true);
  assert.equal(lodash.ghsa, "GHSA-jf85-cpcp-j695");
  assert.match(lodash.title ?? "", /Prototype Pollution/);
  assert.ok(lodash.ids.includes("GHSA-jf85-cpcp-j695"));
  assert.ok(lodash.ids.includes("lodash"));
  assert.ok(lodash.ids.includes("1065"));
});

test("normalizes the three fixAvailable shapes", () => {
  const { findings } = parseAuditReport(v7Report);
  const lodash = findings.find((f) => f.name === "lodash")!;
  const minimist = findings.find((f) => f.name === "minimist")!;
  const devOnly = findings.find((f) => f.name === "dev-only-pkg")!;
  assert.deepEqual(lodash.fixAvailable, {
    name: "lodash",
    version: "4.17.21",
    isSemVerMajor: false,
  });
  assert.equal(minimist.fixAvailable, true);
  assert.equal(devOnly.fixAvailable, false);
});

test("parses legacy npm v6 advisories", () => {
  const { findings, counts } = parseAuditReport(v6Report);
  assert.equal(findings.length, 1);
  const lodash = findings[0]!;
  assert.equal(lodash.name, "lodash");
  assert.equal(lodash.severity, "high");
  assert.ok(lodash.ids.includes("CVE-2019-10744"));
  assert.equal(counts.high, 1);
});

test("handles a clean report", () => {
  const { findings, counts } = parseAuditReport(cleanReport);
  assert.equal(findings.length, 0);
  assert.equal(counts.high, 0);
});

test("handles an unrecognized report shape without throwing", () => {
  const { findings } = parseAuditReport({ something: "else" });
  assert.equal(findings.length, 0);
});

test("sortFindings orders by severity then name", () => {
  const { findings } = parseAuditReport(v7Report);
  const sorted = sortFindings(findings);
  assert.deepEqual(
    sorted.map((f) => f.severity),
    ["critical", "high", "moderate", "low"],
  );
});
