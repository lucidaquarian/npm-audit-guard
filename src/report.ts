import { colors, colorForSeverity } from "./colors.js";
import { maxSeverity } from "./core.js";
import {
  type AuditResult,
  type Finding,
  type FixAvailable,
  type Severity,
  SEVERITIES,
} from "./types.js";

/** Build the machine-readable JSON payload for `--json`. */
export function toJson(result: AuditResult): string {
  return JSON.stringify(
    {
      ok: result.ok,
      level: result.config.level,
      prodOnly: result.config.prodOnly,
      counts: result.counts,
      active: result.active,
      ignored: result.ignored.map((f) => ({
        ...f,
        ignoredBy: f.ignoredBy,
      })),
      belowThreshold: result.belowThreshold,
      expiredIgnores: result.expiredIgnores,
      unusedIgnores: result.unusedIgnores,
    },
    null,
    2,
  );
}

/** Render a human-readable report. Returns the full string to print. */
export function toHuman(result: AuditResult): string {
  const lines: string[] = [];
  const { active, ignored, belowThreshold, expiredIgnores, unusedIgnores } =
    result;

  lines.push(
    colors.bold("npm-audit-guard") +
      colors.gray(
        `  ·  level ≥ ${result.config.level}` +
          (result.config.prodOnly ? "  ·  production only" : ""),
      ),
  );
  lines.push("");

  // Summary line of total counts by severity.
  lines.push(summaryLine(result.counts));
  lines.push("");

  if (active.length > 0) {
    lines.push(
      colors.red(
        colors.bold(
          `✖ ${active.length} blocking ${plural(active.length, "vulnerability", "vulnerabilities")} ` +
            `at or above ${result.config.level}:`,
        ),
      ),
    );
    lines.push("");
    for (const f of active) lines.push(...renderFinding(f));
  }

  if (ignored.length > 0) {
    lines.push(
      colors.gray(
        `↪ ${ignored.length} ignored by rule${ignored.length === 1 ? "" : "s"}:`,
      ),
    );
    for (const f of ignored) {
      const exp = f.ignoredBy.expires
        ? colors.gray(` (expires ${f.ignoredBy.expires})`)
        : "";
      const why = f.ignoredBy.reason ? `: ${f.ignoredBy.reason}` : "";
      lines.push(
        colors.gray(
          `    ${f.name} [${f.severity}]${exp}${colors.dim(why)}`,
        ),
      );
    }
    lines.push("");
  }

  if (belowThreshold.length > 0) {
    const top = maxSeverity(belowThreshold);
    lines.push(
      colors.gray(
        `· ${belowThreshold.length} below threshold ` +
          `(highest: ${top ?? "n/a"}) — not blocking.`,
      ),
    );
    lines.push("");
  }

  if (expiredIgnores.length > 0) {
    lines.push(
      colors.yellow(
        `⚠ ${expiredIgnores.length} ignore rule${expiredIgnores.length === 1 ? "" : "s"} expired and no longer suppress findings:`,
      ),
    );
    for (const rule of expiredIgnores) {
      lines.push(
        colors.yellow(`    ${rule.id} (expired ${rule.expires})`),
      );
    }
    lines.push("");
  }

  if (unusedIgnores.length > 0) {
    lines.push(
      colors.gray(
        `· ${unusedIgnores.length} ignore rule${unusedIgnores.length === 1 ? "" : "s"} matched nothing (safe to remove): ` +
          unusedIgnores.map((r) => r.id).join(", "),
      ),
    );
    lines.push("");
  }

  lines.push(
    result.ok
      ? colors.green(colors.bold("✔ PASS")) +
          colors.gray("  no blocking production risk found.")
      : colors.red(colors.bold("✖ FAIL")) +
          colors.gray(
            `  ${active.length} blocking ${plural(active.length, "issue", "issues")}.`,
          ),
  );

  return lines.join("\n");
}

function renderFinding(f: Finding): string[] {
  const sev = colorForSeverity(f.severity, f.severity.toUpperCase());
  const direct = f.direct ? colors.cyan(" direct") : colors.gray(" transitive");
  const header = `  ${colors.bold(f.name)}  ${sev}${direct}`;
  const out = [header];
  if (f.title) out.push(colors.gray(`    ${f.title}`));
  if (f.range) out.push(colors.gray(`    affected: ${f.range}`));
  out.push(colors.gray(`    fix: ${describeFix(f.fixAvailable)}`));
  if (f.url) out.push(colors.gray(`    ${colors.underline(f.url)}`));
  out.push("");
  return out;
}

function describeFix(fix: FixAvailable): string {
  if (fix === false) return "no automatic fix available";
  if (fix === true) return "available via `npm audit fix`";
  const major = fix.isSemVerMajor ? " (breaking / semver-major)" : "";
  return `upgrade ${fix.name} to ${fix.version}${major}`;
}

function summaryLine(counts: Record<Severity, number>): string {
  const parts: string[] = [];
  for (const sev of [...SEVERITIES].reverse()) {
    const n = counts[sev];
    if (n === 0) continue;
    parts.push(colorForSeverity(sev, `${n} ${sev}`));
  }
  const total = SEVERITIES.reduce((sum, s) => sum + counts[s], 0);
  if (total === 0) return colors.green("No known vulnerabilities.");
  return `Found ${total} total: ` + parts.join(colors.gray(", "));
}

function plural(n: number, one: string, many: string): string {
  return n === 1 ? one : many;
}
