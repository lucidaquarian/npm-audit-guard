import { test } from "node:test";
import assert from "node:assert/strict";
import { classify } from "../src/core.js";
import { parseAuditReport } from "../src/parse.js";
import { resolveConfig } from "../src/config.js";
import { v7Report } from "./fixtures.js";

const parsed = () => parseAuditReport(v7Report);
const NOW = new Date("2026-06-26T12:00:00Z");

test("default level=high blocks high and critical, not moderate/low", () => {
  const result = classify(parsed(), resolveConfig({}), { now: NOW });
  assert.equal(result.config.level, "high");
  assert.deepEqual(
    result.active.map((f) => f.name),
    ["minimist", "lodash"],
  );
  assert.deepEqual(
    result.belowThreshold.map((f) => f.name).sort(),
    ["dev-only-pkg", "info-pkg"],
  );
  assert.equal(result.ok, false);
});

test("level=critical blocks only critical findings", () => {
  const result = classify(
    parsed(),
    resolveConfig({}, { level: "critical" }),
    { now: NOW },
  );
  assert.deepEqual(
    result.active.map((f) => f.name),
    ["minimist"],
  );
});

test("an active ignore rule suppresses a finding by package name", () => {
  const config = resolveConfig({}, {
    ignore: [{ id: "minimist", reason: "patched in our fork" }],
  });
  const result = classify(parsed(), config, { now: NOW });
  assert.deepEqual(
    result.active.map((f) => f.name),
    ["lodash"],
  );
  assert.equal(result.ignored.length, 1);
  assert.equal(result.ignored[0]!.name, "minimist");
  assert.equal(result.ignored[0]!.ignoredBy.reason, "patched in our fork");
});

test("ignore rule matches by GHSA id too", () => {
  const config = resolveConfig({}, {
    ignore: [{ id: "GHSA-jf85-cpcp-j695" }],
  });
  const result = classify(parsed(), config, { now: NOW });
  assert.ok(!result.active.some((f) => f.name === "lodash"));
  assert.ok(result.ignored.some((f) => f.name === "lodash"));
});

test("a non-expired ignore (future date) suppresses", () => {
  const config = resolveConfig({}, {
    ignore: [{ id: "lodash", expires: "2026-12-31" }],
  });
  const result = classify(parsed(), config, { now: NOW });
  assert.ok(result.ignored.some((f) => f.name === "lodash"));
  assert.equal(result.expiredIgnores.length, 0);
});

test("an expired ignore stops suppressing and is surfaced", () => {
  const config = resolveConfig({}, {
    ignore: [{ id: "lodash", expires: "2026-01-01" }],
  });
  const result = classify(parsed(), config, { now: NOW });
  // lodash is back to active because the ignore expired.
  assert.ok(result.active.some((f) => f.name === "lodash"));
  assert.equal(result.expiredIgnores.length, 1);
  assert.equal(result.expiredIgnores[0]!.id, "lodash");
});

test("expiry date is inclusive through end of the given day", () => {
  // now is exactly the expiry day at noon; should still be valid.
  const config = resolveConfig({}, {
    ignore: [{ id: "lodash", expires: "2026-06-26" }],
  });
  const result = classify(parsed(), config, { now: NOW });
  assert.ok(result.ignored.some((f) => f.name === "lodash"));
  assert.equal(result.expiredIgnores.length, 0);
});

test("unused ignore rules are reported", () => {
  const config = resolveConfig({}, {
    ignore: [{ id: "nonexistent-pkg" }],
  });
  const result = classify(parsed(), config, { now: NOW });
  assert.equal(result.unusedIgnores.length, 1);
  assert.equal(result.unusedIgnores[0]!.id, "nonexistent-pkg");
});

test("ok is true when all blocking findings are ignored", () => {
  const config = resolveConfig({}, {
    ignore: [{ id: "lodash" }, { id: "minimist" }],
  });
  const result = classify(parsed(), config, { now: NOW });
  assert.equal(result.active.length, 0);
  assert.equal(result.ok, true);
});

test("counts reflect all findings regardless of filtering", () => {
  const result = classify(parsed(), resolveConfig({}), { now: NOW });
  assert.deepEqual(result.counts, {
    info: 0,
    low: 1,
    moderate: 1,
    high: 1,
    critical: 1,
  });
});
