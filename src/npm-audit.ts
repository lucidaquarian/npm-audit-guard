import { spawn } from "node:child_process";

export interface RunOptions {
  /** Working directory to run `npm audit` in. Defaults to process.cwd(). */
  cwd?: string;
  /** Only audit production dependencies. Adds `--omit=dev`. */
  prodOnly?: boolean;
}

/**
 * The shape of the parsed `npm audit --json` output. We keep this loose
 * because npm emits two different schemas (v6 "advisories" and v7+
 * "vulnerabilities"); normalization happens in parse.ts.
 */
export type RawAuditReport = Record<string, unknown>;

const NPM_BIN = process.platform === "win32" ? "npm.cmd" : "npm";

/**
 * Run `npm audit --json` and return the parsed report object.
 *
 * `npm audit` intentionally exits with a non-zero code when vulnerabilities
 * are found, so the exit code is NOT treated as an error here. We only fail
 * if npm produced no parseable JSON at all (e.g. npm missing, no lockfile).
 */
export async function runNpmAudit(
  options: RunOptions = {},
): Promise<RawAuditReport> {
  const args = ["audit", "--json"];
  if (options.prodOnly) args.push("--omit=dev");

  const { stdout, stderr } = await spawnCapture(NPM_BIN, args, options.cwd);

  const trimmed = stdout.trim();
  if (!trimmed) {
    throw new AuditExecutionError(
      "`npm audit` produced no output. Is npm installed and is there a " +
        "package-lock.json / npm-shrinkwrap.json in this directory?",
      stderr,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new AuditExecutionError(
      "Could not parse `npm audit --json` output as JSON.",
      stderr || trimmed.slice(0, 500),
    );
  }

  if (parsed && typeof parsed === "object" && "error" in parsed) {
    const err = (parsed as { error?: { summary?: string; detail?: string } })
      .error;
    throw new AuditExecutionError(
      err?.summary || "`npm audit` reported an error.",
      err?.detail,
    );
  }

  return parsed as RawAuditReport;
}

export class AuditExecutionError extends Error {
  detail?: string;
  constructor(message: string, detail?: string) {
    super(message);
    this.name = "AuditExecutionError";
    this.detail = detail;
  }
}

function spawnCapture(
  command: string,
  args: string[],
  cwd?: string,
): Promise<{ stdout: string; stderr: string; code: number | null }> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd,
      shell: false,
      env: process.env,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d.toString()));
    child.stderr.on("data", (d) => (stderr += d.toString()));
    child.on("error", (err) => {
      reject(
        new AuditExecutionError(
          `Failed to run \`${command} ${args.join(" ")}\`: ${err.message}`,
        ),
      );
    });
    child.on("close", (code) => resolve({ stdout, stderr, code }));
  });
}
