import { audit, type AuditOptions } from "./index.js";
import { runNpmAuditFix } from "./npm-audit.js";
import type { AuditResult, Finding } from "./types.js";

export interface FixOptions extends AuditOptions {
  /** Allow semver-major upgrades (`npm audit fix --force`). Opt-in. */
  force?: boolean;
}

export interface FixResult {
  /** Guarded audit before fixes were applied. */
  before: AuditResult;
  /** Guarded audit after `npm audit fix` ran. */
  after: AuditResult;
  /** Blocking findings present before that are gone afterwards. */
  resolved: Finding[];
  /** Blocking findings that `npm audit fix` could not resolve. */
  remaining: Finding[];
  /** Combined stdout/stderr from `npm audit fix`. */
  npmOutput: string;
}

/** Stable identity for a finding across before/after runs. */
function findingKey(f: Finding): string {
  return `${f.name}@${f.ghsa ?? ""}`;
}

/**
 * Run `npm audit fix`, then re-audit and report what was resolved and what
 * still blocks. The before/after comparison is done on *active* (blocking)
 * findings, since those are what determine the exit status.
 *
 * A pre-fetched `report` is honored for the "before" snapshot only; the
 * "after" snapshot always re-runs `npm audit` since the tree changed.
 */
export async function fix(options: FixOptions = {}): Promise<FixResult> {
  const { force, report, ...auditOptions } = options;

  const before = await audit({ ...auditOptions, report });

  const npmOutput = await runNpmAuditFix({
    cwd: options.cwd,
    prodOnly: before.config.prodOnly,
    force,
  });

  // Re-audit from disk (the dependency tree has changed).
  const after = await audit(auditOptions);

  const beforeKeys = new Set(before.active.map(findingKey));
  const afterKeys = new Set(after.active.map(findingKey));

  const resolved = before.active.filter((f) => !afterKeys.has(findingKey(f)));
  const remaining = after.active.filter((f) => beforeKeys.has(findingKey(f)));

  return { before, after, resolved, remaining, npmOutput };
}
