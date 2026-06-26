import {
  type AuditResult,
  type Finding,
  type GuardConfig,
  type IgnoredFinding,
  type IgnoreRule,
  type Severity,
  SEVERITY_RANK,
} from "./types.js";
import { type ParsedReport, sortFindings } from "./parse.js";

export interface ClassifyOptions {
  /** "Now" used for evaluating ignore expiry. Defaults to current time. */
  now?: Date;
}

/**
 * Apply a guard configuration to a parsed report: split findings into active
 * (failing), ignored, and below-threshold buckets, and surface expired and
 * unused ignore rules.
 *
 * This is pure and deterministic given (report, config, now) — the I/O of
 * actually running `npm audit` lives in core.ts's `audit()` wrapper.
 */
export function classify(
  report: ParsedReport,
  config: GuardConfig,
  options: ClassifyOptions = {},
): AuditResult {
  const now = options.now ?? new Date();
  const threshold = SEVERITY_RANK[config.level];

  const active: Finding[] = [];
  const ignored: IgnoredFinding[] = [];
  const belowThreshold: Finding[] = [];

  const expiredRules = new Map<string, IgnoreRule>();
  const usedRuleKeys = new Set<string>();

  for (const finding of report.findings) {
    const match = findMatchingRule(finding, config.ignore, now);

    if (match) {
      usedRuleKeys.add(ruleKey(match.rule));
      if (match.expired) {
        expiredRules.set(ruleKey(match.rule), match.rule);
        // Expired ignore => finding is reconsidered against the threshold.
      } else {
        ignored.push({ ...finding, ignoredBy: match.rule });
        continue;
      }
    }

    if (SEVERITY_RANK[finding.severity] >= threshold) {
      active.push(finding);
    } else {
      belowThreshold.push(finding);
    }
  }

  const unusedIgnores = config.ignore.filter(
    (rule) => !usedRuleKeys.has(ruleKey(rule)),
  );

  return {
    active: sortFindings(active),
    ignored: sortFindings(ignored) as IgnoredFinding[],
    belowThreshold: sortFindings(belowThreshold),
    expiredIgnores: [...expiredRules.values()],
    unusedIgnores,
    counts: report.counts,
    config,
    ok: active.length === 0,
  };
}

interface RuleMatch {
  rule: IgnoreRule;
  expired: boolean;
}

function findMatchingRule(
  finding: Finding,
  rules: IgnoreRule[],
  now: Date,
): RuleMatch | undefined {
  const ids = new Set(finding.ids.map((id) => id.toLowerCase()));
  let expiredMatch: RuleMatch | undefined;

  for (const rule of rules) {
    if (!ids.has(rule.id.toLowerCase())) continue;
    const expired = isExpired(rule, now);
    if (!expired) return { rule, expired: false };
    // Remember the first expired match but keep looking for a live one.
    if (!expiredMatch) expiredMatch = { rule, expired: true };
  }

  return expiredMatch;
}

function isExpired(rule: IgnoreRule, now: Date): boolean {
  if (!rule.expires) return false;
  const expiry = parseExpiry(rule.expires);
  if (expiry === undefined) return false; // unparseable => treat as no expiry
  return now.getTime() > expiry;
}

/**
 * Parse an `expires` value to an end-of-day epoch (UTC). A bare date like
 * "2026-09-01" remains valid through the whole of that day.
 */
function parseExpiry(value: string): number | undefined {
  const dateOnly = /^\d{4}-\d{2}-\d{2}$/.test(value.trim());
  const ts = Date.parse(value.trim());
  if (Number.isNaN(ts)) return undefined;
  if (dateOnly) {
    // Date.parse of a bare date is UTC midnight; extend to end of that day.
    return ts + (24 * 60 * 60 * 1000 - 1);
  }
  return ts;
}

function ruleKey(rule: IgnoreRule): string {
  return `${rule.id}|${rule.expires ?? ""}|${rule.reason ?? ""}`;
}

/** Highest severity present among a set of findings, or undefined if empty. */
export function maxSeverity(findings: Finding[]): Severity | undefined {
  let best: Severity | undefined;
  for (const f of findings) {
    if (best === undefined || SEVERITY_RANK[f.severity] > SEVERITY_RANK[best]) {
      best = f.severity;
    }
  }
  return best;
}
