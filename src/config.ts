import { readFile } from "node:fs/promises";
import { join, isAbsolute } from "node:path";
import {
  type GuardConfig,
  type IgnoreRule,
  type Severity,
  isSeverity,
} from "./types.js";

/** Config file names searched for, in priority order. */
export const CONFIG_FILES = [
  ".audit-guard.json",
  ".auditguardrc.json",
  ".auditguardrc",
];

export const DEFAULT_LEVEL: Severity = "high";

/** Partial config as it may appear in a file or package.json. */
export interface FileConfig {
  level?: string;
  prodOnly?: boolean;
  ignore?: Array<string | IgnoreRule>;
}

export interface LoadConfigOptions {
  cwd?: string;
  /** Explicit config file path; skips auto-discovery when set. */
  configPath?: string;
}

/**
 * Load configuration from (in priority order): an explicit `configPath`, the
 * first matching dotfile in `cwd`, or the `auditGuard` key in package.json.
 * Returns an empty config if none is found.
 */
export async function loadFileConfig(
  options: LoadConfigOptions = {},
): Promise<FileConfig> {
  const cwd = options.cwd ?? process.cwd();

  if (options.configPath) {
    const path = isAbsolute(options.configPath)
      ? options.configPath
      : join(cwd, options.configPath);
    return normalizeFileConfig(await readJson(path), path);
  }

  for (const file of CONFIG_FILES) {
    const path = join(cwd, file);
    const json = await readJsonIfExists(path);
    if (json !== undefined) return normalizeFileConfig(json, path);
  }

  const pkg = await readJsonIfExists(join(cwd, "package.json"));
  if (pkg && typeof pkg === "object" && "auditGuard" in pkg) {
    return normalizeFileConfig(
      (pkg as { auditGuard: unknown }).auditGuard,
      "package.json#auditGuard",
    );
  }

  return {};
}

/**
 * Merge file config with CLI overrides into a fully-resolved GuardConfig.
 * CLI values win over file values; file values win over defaults.
 */
export function resolveConfig(
  fileConfig: FileConfig,
  overrides: Partial<GuardConfig> = {},
): GuardConfig {
  const level =
    overrides.level ??
    (isSeverity(fileConfig.level) ? fileConfig.level : undefined) ??
    DEFAULT_LEVEL;

  return {
    level,
    prodOnly: overrides.prodOnly ?? fileConfig.prodOnly ?? false,
    ignore: overrides.ignore ?? normalizeIgnores(fileConfig.ignore),
  };
}

function normalizeIgnores(
  ignore: FileConfig["ignore"],
): IgnoreRule[] {
  if (!Array.isArray(ignore)) return [];
  const rules: IgnoreRule[] = [];
  for (const entry of ignore) {
    if (typeof entry === "string") {
      rules.push({ id: entry });
    } else if (entry && typeof entry.id === "string") {
      rules.push({
        id: entry.id,
        reason: entry.reason,
        expires: entry.expires,
      });
    }
  }
  return rules;
}

function normalizeFileConfig(value: unknown, source: string): FileConfig {
  if (!value || typeof value !== "object") {
    throw new Error(`Config in ${source} must be a JSON object.`);
  }
  const obj = value as Record<string, unknown>;
  if (obj.level !== undefined && !isSeverity(obj.level)) {
    throw new Error(
      `Config in ${source}: "level" must be one of info, low, moderate, high, critical.`,
    );
  }
  return {
    level: obj.level as string | undefined,
    prodOnly:
      typeof obj.prodOnly === "boolean" ? obj.prodOnly : undefined,
    ignore: Array.isArray(obj.ignore)
      ? (obj.ignore as Array<string | IgnoreRule>)
      : undefined,
  };
}

async function readJson(path: string): Promise<unknown> {
  const text = await readFile(path, "utf8");
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(
      `Failed to parse JSON config at ${path}: ${(err as Error).message}`,
    );
  }
}

async function readJsonIfExists(path: string): Promise<unknown | undefined> {
  try {
    return await readJson(path);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw err;
  }
}
