#!/usr/bin/env node
import { audit, fix } from "./index.js";
import { AuditExecutionError } from "./npm-audit.js";
import { fixToHuman, fixToJson, toHuman, toJson } from "./report.js";
import { colors } from "./colors.js";
import { isSeverity, type Severity } from "./types.js";

const HELP = `npm-audit-guard — smarter npm audit for CI

A wrapper around \`npm audit\` that filters dev vs prod vulnerabilities,
honors justified ignore rules with expiry dates, prints readable output,
and exits non-zero ONLY on real, non-ignored production risk.

Usage:
  npm-audit-guard [options]

Options:
  -l, --level <severity>   Minimum severity that fails the build.
                           One of: info, low, moderate, high, critical.
                           Default: high (or "level" from config).
  -p, --prod-only          Audit production dependencies only (npm --omit=dev).
      --fix                Run \`npm audit fix\`, then re-audit and report what
                           was resolved and what still blocks.
      --force              With --fix, allow semver-major upgrades
                           (\`npm audit fix --force\`). May be breaking.
      --json               Output machine-readable JSON instead of text.
  -c, --config <path>      Path to a config file (skips auto-discovery).
  -C, --cwd <path>         Directory to audit. Default: current directory.
      --no-color           Disable colored output (or set NO_COLOR).
  -v, --version            Print version and exit.
  -h, --help               Show this help and exit.

Config (.audit-guard.json, or "auditGuard" key in package.json):
  {
    "level": "high",
    "prodOnly": true,
    "ignore": [
      { "id": "lodash", "reason": "not reachable in prod", "expires": "2026-12-31" },
      { "id": "GHSA-xxxx-xxxx-xxxx", "reason": "accepted risk" }
    ]
  }

Exit codes:
  0  no blocking risk found (build passes)
  1  blocking vulnerabilities found at or above the level
  2  execution error (npm missing, no lockfile, bad config, etc.)
`;

interface CliArgs {
  level?: Severity;
  prodOnly?: boolean;
  fix: boolean;
  force: boolean;
  json: boolean;
  configPath?: string;
  cwd?: string;
  help: boolean;
  version: boolean;
}

class CliError extends Error {}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    fix: false,
    force: false,
    json: false,
    help: false,
    version: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    switch (arg) {
      case "-h":
      case "--help":
        args.help = true;
        break;
      case "-v":
      case "--version":
        args.version = true;
        break;
      case "-p":
      case "--prod-only":
      case "--production":
        args.prodOnly = true;
        break;
      case "--fix":
        args.fix = true;
        break;
      case "--force":
        args.force = true;
        break;
      case "--json":
        args.json = true;
        break;
      case "--no-color":
        process.env.NO_COLOR = "1";
        break;
      case "-l":
      case "--level": {
        const value = argv[++i];
        if (!value) throw new CliError(`${arg} requires a severity value.`);
        if (!isSeverity(value)) {
          throw new CliError(
            `Invalid level "${value}". Use info, low, moderate, high, or critical.`,
          );
        }
        args.level = value;
        break;
      }
      case "-c":
      case "--config": {
        const value = argv[++i];
        if (!value) throw new CliError(`${arg} requires a path.`);
        args.configPath = value;
        break;
      }
      case "-C":
      case "--cwd": {
        const value = argv[++i];
        if (!value) throw new CliError(`${arg} requires a path.`);
        args.cwd = value;
        break;
      }
      default:
        if (arg.startsWith("--level=")) {
          const value = arg.slice("--level=".length);
          if (!isSeverity(value)) {
            throw new CliError(`Invalid level "${value}".`);
          }
          args.level = value;
        } else if (arg.startsWith("--config=")) {
          args.configPath = arg.slice("--config=".length);
        } else if (arg.startsWith("--cwd=")) {
          args.cwd = arg.slice("--cwd=".length);
        } else {
          throw new CliError(`Unknown option: ${arg}`);
        }
    }
  }

  return args;
}

async function readVersion(): Promise<string> {
  try {
    const { readFile } = await import("node:fs/promises");
    const { fileURLToPath } = await import("node:url");
    const { dirname, join } = await import("node:path");
    const here = dirname(fileURLToPath(import.meta.url));
    const pkg = JSON.parse(
      await readFile(join(here, "..", "package.json"), "utf8"),
    );
    return typeof pkg.version === "string" ? pkg.version : "0.0.0";
  } catch {
    return "0.0.0";
  }
}

async function main(): Promise<number> {
  let args: CliArgs;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(colors.red((err as Error).message) + "\n");
    process.stderr.write(`Run \`npm-audit-guard --help\` for usage.\n`);
    return 2;
  }

  if (args.help) {
    process.stdout.write(HELP);
    return 0;
  }
  if (args.version) {
    process.stdout.write((await readVersion()) + "\n");
    return 0;
  }

  if (args.force && !args.fix) {
    process.stderr.write(
      colors.yellow("Note: --force has no effect without --fix.") + "\n",
    );
  }

  try {
    if (args.fix) {
      const fixResult = await fix({
        cwd: args.cwd,
        level: args.level,
        prodOnly: args.prodOnly,
        configPath: args.configPath,
        force: args.force,
      });
      process.stdout.write(
        (args.json ? fixToJson(fixResult) : fixToHuman(fixResult)) + "\n",
      );
      return fixResult.after.ok ? 0 : 1;
    }

    const result = await audit({
      cwd: args.cwd,
      level: args.level,
      prodOnly: args.prodOnly,
      configPath: args.configPath,
    });

    if (args.json) {
      process.stdout.write(toJson(result) + "\n");
    } else {
      process.stdout.write(toHuman(result) + "\n");
    }

    return result.ok ? 0 : 1;
  } catch (err) {
    if (err instanceof AuditExecutionError) {
      process.stderr.write(colors.red(`Error: ${err.message}`) + "\n");
      if (err.detail) process.stderr.write(colors.gray(err.detail) + "\n");
    } else {
      process.stderr.write(
        colors.red(`Error: ${(err as Error).message}`) + "\n",
      );
    }
    return 2;
  }
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(colors.red(`Unexpected error: ${err}\n`));
    process.exit(2);
  },
);
