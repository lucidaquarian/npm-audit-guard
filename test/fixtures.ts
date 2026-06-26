import type { RawAuditReport } from "../src/npm-audit.js";

/** A representative npm v7+ `npm audit --json` report. */
export const v7Report: RawAuditReport = {
  auditReportVersion: 2,
  vulnerabilities: {
    lodash: {
      name: "lodash",
      severity: "high",
      isDirect: true,
      via: [
        {
          source: 1065,
          name: "lodash",
          dependency: "lodash",
          title: "Prototype Pollution in lodash",
          url: "https://github.com/advisories/GHSA-jf85-cpcp-j695",
          severity: "high",
          cwe: ["CWE-1321"],
          range: "<4.17.12",
        },
      ],
      effects: [],
      range: "<4.17.12",
      nodes: ["node_modules/lodash"],
      fixAvailable: { name: "lodash", version: "4.17.21", isSemVerMajor: false },
    },
    minimist: {
      name: "minimist",
      severity: "critical",
      isDirect: false,
      via: [
        {
          source: 1179,
          name: "minimist",
          dependency: "minimist",
          title: "Prototype Pollution in minimist",
          url: "https://github.com/advisories/GHSA-vh95-rmgr-6w4m",
          severity: "critical",
          cwe: ["CWE-1321"],
          range: "<1.2.3",
        },
      ],
      effects: ["mkdirp"],
      range: "<1.2.3",
      nodes: ["node_modules/minimist"],
      fixAvailable: true,
    },
    "dev-only-pkg": {
      name: "dev-only-pkg",
      severity: "moderate",
      isDirect: true,
      via: [
        {
          source: 2222,
          name: "dev-only-pkg",
          title: "ReDoS in dev-only-pkg",
          url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
          severity: "moderate",
        },
      ],
      effects: [],
      range: "*",
      nodes: ["node_modules/dev-only-pkg"],
      fixAvailable: false,
    },
    "info-pkg": {
      name: "info-pkg",
      severity: "low",
      isDirect: false,
      via: [
        {
          source: 3333,
          name: "info-pkg",
          title: "Minor info leak",
          url: "https://github.com/advisories/GHSA-dddd-eeee-ffff",
          severity: "low",
        },
      ],
      effects: [],
      range: "<2.0.0",
      nodes: ["node_modules/info-pkg"],
      fixAvailable: true,
    },
  },
  metadata: {
    vulnerabilities: {
      info: 0,
      low: 1,
      moderate: 1,
      high: 1,
      critical: 1,
      total: 4,
    },
  },
};

/** A clean npm v7+ report with no vulnerabilities. */
export const cleanReport: RawAuditReport = {
  auditReportVersion: 2,
  vulnerabilities: {},
  metadata: {
    vulnerabilities: {
      info: 0,
      low: 0,
      moderate: 0,
      high: 0,
      critical: 0,
      total: 0,
    },
  },
};

/** A legacy npm v6 report. */
export const v6Report: RawAuditReport = {
  advisories: {
    "1065": {
      module_name: "lodash",
      severity: "high",
      title: "Prototype Pollution",
      url: "https://npmjs.com/advisories/1065",
      cves: ["CVE-2019-10744"],
      vulnerable_versions: "<4.17.12",
      patched_versions: ">=4.17.12",
      findings: [{ paths: ["lodash"] }],
    },
  },
  metadata: {
    vulnerabilities: {
      info: 0,
      low: 0,
      moderate: 0,
      high: 1,
      critical: 0,
      total: 1,
    },
  },
};
