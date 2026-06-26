import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  loadFileConfig,
  resolveConfig,
  DEFAULT_LEVEL,
} from "../src/config.js";

async function withTempDir(
  fn: (dir: string) => Promise<void>,
): Promise<void> {
  const dir = await mkdtemp(join(tmpdir(), "audit-guard-test-"));
  try {
    await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test("resolveConfig falls back to defaults when empty", () => {
  const config = resolveConfig({});
  assert.equal(config.level, DEFAULT_LEVEL);
  assert.equal(config.prodOnly, false);
  assert.deepEqual(config.ignore, []);
});

test("CLI overrides beat file config", () => {
  const config = resolveConfig(
    { level: "low", prodOnly: false },
    { level: "critical", prodOnly: true },
  );
  assert.equal(config.level, "critical");
  assert.equal(config.prodOnly, true);
});

test("string ignore entries normalize to rule objects", () => {
  const config = resolveConfig({ ignore: ["lodash", { id: "minimist", reason: "x" }] });
  assert.deepEqual(config.ignore, [
    { id: "lodash" },
    { id: "minimist", reason: "x", expires: undefined },
  ]);
});

test("loads .audit-guard.json from a directory", async () => {
  await withTempDir(async (dir) => {
    await writeFile(
      join(dir, ".audit-guard.json"),
      JSON.stringify({
        level: "moderate",
        prodOnly: true,
        ignore: [{ id: "lodash", reason: "ok" }],
      }),
    );
    const fileConfig = await loadFileConfig({ cwd: dir });
    const config = resolveConfig(fileConfig);
    assert.equal(config.level, "moderate");
    assert.equal(config.prodOnly, true);
    assert.equal(config.ignore[0]!.id, "lodash");
  });
});

test("reads the auditGuard key from package.json when no dotfile", async () => {
  await withTempDir(async (dir) => {
    await writeFile(
      join(dir, "package.json"),
      JSON.stringify({
        name: "demo",
        auditGuard: { level: "critical" },
      }),
    );
    const fileConfig = await loadFileConfig({ cwd: dir });
    assert.equal(fileConfig.level, "critical");
  });
});

test("returns empty config when nothing is present", async () => {
  await withTempDir(async (dir) => {
    const fileConfig = await loadFileConfig({ cwd: dir });
    assert.deepEqual(fileConfig, {});
  });
});

test("rejects an invalid level in config", async () => {
  await withTempDir(async (dir) => {
    await writeFile(
      join(dir, ".audit-guard.json"),
      JSON.stringify({ level: "nope" }),
    );
    await assert.rejects(() => loadFileConfig({ cwd: dir }), /level/);
  });
});

test("explicit config path is honored", async () => {
  await withTempDir(async (dir) => {
    const path = join(dir, "custom.json");
    await writeFile(path, JSON.stringify({ level: "low" }));
    const fileConfig = await loadFileConfig({ cwd: dir, configPath: path });
    assert.equal(fileConfig.level, "low");
  });
});
