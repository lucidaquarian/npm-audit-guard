import { runNpmAudit, type RawAuditReport } from "./npm-audit.js";
import { parseAuditReport } from "./parse.js";
import { classify } from "./core.js";
import { loadFileConfig, resolveConfig } from "./config.js";
import type { AuditResult, GuardConfig } from "./types.js";

export interface AuditOptions {
  /** Directory to audit. Defaults to process.cwd(). */
  cwd?: string;
  /** Only consider production dependencies. */
  prodOnly?: boolean;
  /** Minimum severity that counts as a failure (default: "high"). */
  level?: GuardConfig["level"];
  /** Justified ignore rules. When set, overrides any from a config file. */
  ignore?: GuardConfig["ignore"];
  /** Explicit config file path. Skips auto-discovery. */
  configPath?: string;
  /**
   * Provide a pre-fetched `npm audit --json` report instead of spawning npm.
   * Useful for testing or for piping audit output from elsewhere.
   */
  report?: RawAuditReport;
  /** "Now" used for evaluating ignore expiry. Defaults to current time. */
  now?: Date;
}

/**
 * Run a guarded audit and return a structured result.
 *
 * Pipeline: load + merge config -> run `npm audit --json` (unless a `report`
 * is supplied) -> normalize findings -> classify against the threshold and
 * ignore rules. `result.ok === false` indicates a real, non-ignored risk at
 * or above the configured level.
 *
 * @example
 * import { audit } from "npm-audit-guard";
 * const result = await audit({ prodOnly: true, level: "high" });
 * if (!result.ok) process.exit(1);
 */
export async function audit(options: AuditOptions = {}): Promise<AuditResult> {
  const fileConfig = await loadFileConfig({
    cwd: options.cwd,
    configPath: options.configPath,
  });

  const config = resolveConfig(fileConfig, {
    level: options.level,
    prodOnly: options.prodOnly,
    ignore: options.ignore,
  });

  const raw =
    options.report ??
    (await runNpmAudit({ cwd: options.cwd, prodOnly: config.prodOnly }));

  const parsed = parseAuditReport(raw);
  return classify(parsed, config, { now: options.now });
}

export { classify } from "./core.js";
export { parseAuditReport } from "./parse.js";
export { loadFileConfig, resolveConfig, DEFAULT_LEVEL } from "./config.js";
export { runNpmAudit, AuditExecutionError } from "./npm-audit.js";
export * from "./types.js";
