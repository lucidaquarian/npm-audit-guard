/** Vulnerability severity levels, ordered from least to most severe. */
export type Severity = "info" | "low" | "moderate" | "high" | "critical";

/** Numeric weight for each severity, used for threshold comparisons. */
export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  moderate: 2,
  high: 3,
  critical: 4,
};

/** All severities ordered low -> high. */
export const SEVERITIES: Severity[] = [
  "info",
  "low",
  "moderate",
  "high",
  "critical",
];

export function isSeverity(value: unknown): value is Severity {
  return typeof value === "string" && value in SEVERITY_RANK;
}

/**
 * A justified suppression of a finding. Matched against a finding's package
 * name or any of its advisory identifiers (GHSA id, CVE, npm advisory number).
 */
export interface IgnoreRule {
  /** Package name, GHSA id, CVE, or npm advisory number to suppress. */
  id: string;
  /** Why this risk is accepted. Recorded in output for auditability. */
  reason?: string;
  /**
   * ISO date (YYYY-MM-DD) after which the ignore stops applying and the
   * finding becomes active again. Encourages revisiting accepted risk.
   */
  expires?: string;
}

/** Resolved guard configuration, after merging file config with CLI flags. */
export interface GuardConfig {
  /** Minimum severity that counts as a failure. Default: "high". */
  level: Severity;
  /** Only audit production dependencies (ignore devDependencies). */
  prodOnly: boolean;
  /** Justified suppressions. */
  ignore: IgnoreRule[];
}

/** What npm reports for an available fix. */
export type FixAvailable =
  | boolean
  | { name: string; version: string; isSemVerMajor: boolean };

/** A single normalized vulnerability finding. */
export interface Finding {
  /** Affected package name. */
  name: string;
  severity: Severity;
  title?: string;
  url?: string;
  /** GitHub Security Advisory id, when known (e.g. GHSA-xxxx-xxxx-xxxx). */
  ghsa?: string;
  /** Affected semver range. */
  range?: string;
  /** True when the package is a direct dependency of the project. */
  direct: boolean;
  fixAvailable: FixAvailable;
  /** All identifiers an ignore rule may match against (name, GHSA, CVE, id). */
  ids: string[];
}

/** A finding suppressed by an active ignore rule. */
export interface IgnoredFinding extends Finding {
  ignoredBy: IgnoreRule;
}

/** The outcome of an audit run. */
export interface AuditResult {
  /** Findings at or above `level` that are not ignored. Non-empty => failure. */
  active: Finding[];
  /** Findings suppressed by an active (non-expired) ignore rule. */
  ignored: IgnoredFinding[];
  /** Findings below the configured `level`. Reported but not failing. */
  belowThreshold: Finding[];
  /**
   * Ignore rules whose `expires` date has passed. Their findings (if any) are
   * treated as active again; surfaced so they can be cleaned up or renewed.
   */
  expiredIgnores: IgnoreRule[];
  /** Ignore rules that did not match any finding. Likely stale. */
  unusedIgnores: IgnoreRule[];
  /** Count of all findings by severity (before threshold/ignore filtering). */
  counts: Record<Severity, number>;
  /** The resolved configuration used for this run. */
  config: GuardConfig;
  /** True when there are no active findings (the build should pass). */
  ok: boolean;
}
