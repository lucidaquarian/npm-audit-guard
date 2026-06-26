import type { RawAuditReport } from "./npm-audit.js";
import {
  type Finding,
  type FixAvailable,
  type Severity,
  SEVERITIES,
  isSeverity,
} from "./types.js";

const EMPTY_COUNTS = (): Record<Severity, number> => ({
  info: 0,
  low: 0,
  moderate: 0,
  high: 0,
  critical: 0,
});

export interface ParsedReport {
  findings: Finding[];
  counts: Record<Severity, number>;
}

/**
 * Normalize an `npm audit --json` report into a flat list of findings,
 * supporting both the npm v7+ ("vulnerabilities") and the legacy npm v6
 * ("advisories") schemas.
 */
export function parseAuditReport(report: RawAuditReport): ParsedReport {
  if (report && typeof report === "object" && "vulnerabilities" in report) {
    return parseV7(report);
  }
  if (report && typeof report === "object" && "advisories" in report) {
    return parseV6(report);
  }
  // No recognizable vulnerability data => clean report.
  return { findings: [], counts: EMPTY_COUNTS() };
}

const GHSA_RE = /GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i;
const CVE_RE = /CVE-\d{4}-\d+/i;

function extractGhsa(url?: string): string | undefined {
  if (!url) return undefined;
  const m = url.match(GHSA_RE);
  return m ? m[0] : undefined;
}

/** npm v7+ schema: `{ vulnerabilities: { <pkg>: {...} } }`. */
function parseV7(report: RawAuditReport): ParsedReport {
  const counts = EMPTY_COUNTS();
  const findings: Finding[] = [];
  const vulns = (report.vulnerabilities ?? {}) as Record<
    string,
    V7Vulnerability
  >;

  for (const [name, vuln] of Object.entries(vulns)) {
    if (!vuln || !isSeverity(vuln.severity)) continue;
    const severity = vuln.severity;
    counts[severity] += 1;

    const ids = new Set<string>([name]);
    let title: string | undefined;
    let url: string | undefined;
    let ghsa: string | undefined;

    for (const via of vuln.via ?? []) {
      if (typeof via === "string") {
        ids.add(via);
        continue;
      }
      if (typeof via.source === "number") ids.add(String(via.source));
      if (via.url) {
        const g = extractGhsa(via.url);
        if (g) ids.add(g);
        const cve = via.url.match(CVE_RE);
        if (cve) ids.add(cve[0]);
      }
      if (Array.isArray(via.cwe)) for (const c of via.cwe) ids.add(c);
      if (!title && via.title) title = via.title;
      if (!url && via.url) url = via.url;
      if (!ghsa) ghsa = extractGhsa(via.url);
    }

    findings.push({
      name,
      severity,
      title,
      url,
      ghsa,
      range: vuln.range,
      direct: Boolean(vuln.isDirect),
      fixAvailable: normalizeFix(vuln.fixAvailable),
      ids: [...ids],
    });
  }

  return { findings, counts };
}

/** Legacy npm v6 schema: `{ advisories: { <id>: {...} } }`. */
function parseV6(report: RawAuditReport): ParsedReport {
  const counts = EMPTY_COUNTS();
  const findings: Finding[] = [];
  const advisories = (report.advisories ?? {}) as Record<
    string,
    V6Advisory
  >;

  for (const [advId, adv] of Object.entries(advisories)) {
    if (!adv || !isSeverity(adv.severity)) continue;
    const severity = adv.severity;
    counts[severity] += 1;

    const name = adv.module_name ?? advId;
    const ids = new Set<string>([name, advId]);
    const ghsa = extractGhsa(adv.url);
    if (ghsa) ids.add(ghsa);
    for (const cve of adv.cves ?? []) ids.add(cve);

    const direct = (adv.findings ?? []).some((f) =>
      (f.paths ?? []).some((p) => p === name || !p.includes(">")),
    );

    findings.push({
      name,
      severity,
      title: adv.title,
      url: adv.url,
      ghsa,
      range: adv.vulnerable_versions,
      direct,
      fixAvailable: Boolean(adv.patched_versions && adv.patched_versions !== "<0.0.0"),
      ids: [...ids],
    });
  }

  return { findings, counts };
}

function normalizeFix(fix: V7Vulnerability["fixAvailable"]): FixAvailable {
  if (fix === undefined || fix === null) return false;
  if (typeof fix === "boolean") return fix;
  if (typeof fix === "object" && typeof fix.name === "string") {
    return {
      name: fix.name,
      version: fix.version ?? "",
      isSemVerMajor: Boolean(fix.isSemVerMajor),
    };
  }
  return false;
}

/** Sort findings by severity (most severe first), then by package name. */
export function sortFindings(findings: Finding[]): Finding[] {
  const rank = (s: Severity) => SEVERITIES.indexOf(s);
  return [...findings].sort(
    (a, b) => rank(b.severity) - rank(a.severity) || a.name.localeCompare(b.name),
  );
}

// --- Loose schema types for the raw npm output ---------------------------

interface V7Via {
  source?: number;
  name?: string;
  dependency?: string;
  title?: string;
  url?: string;
  severity?: string;
  cwe?: string[];
}

interface V7Vulnerability {
  name?: string;
  severity?: string;
  isDirect?: boolean;
  via?: Array<string | V7Via>;
  range?: string;
  fixAvailable?:
    | boolean
    | { name?: string; version?: string; isSemVerMajor?: boolean }
    | null;
}

interface V6Finding {
  paths?: string[];
}

interface V6Advisory {
  module_name?: string;
  severity?: string;
  title?: string;
  url?: string;
  cves?: string[];
  vulnerable_versions?: string;
  patched_versions?: string;
  findings?: V6Finding[];
}
