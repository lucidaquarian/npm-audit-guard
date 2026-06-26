/**
 * Tiny zero-dependency ANSI color helper. Honors NO_COLOR and FORCE_COLOR
 * and disables itself when stdout is not a TTY (e.g. piped or in CI logs
 * that don't request color).
 *
 * https://no-color.org/  |  https://force-color.org/
 */

function colorEnabled(): boolean {
  if (process.env.NO_COLOR !== undefined && process.env.NO_COLOR !== "") {
    return false;
  }
  if (process.env.FORCE_COLOR === "0") return false;
  if (
    process.env.FORCE_COLOR !== undefined &&
    process.env.FORCE_COLOR !== ""
  ) {
    return true;
  }
  return Boolean(process.stdout && process.stdout.isTTY);
}

const ENABLED = colorEnabled();

function wrap(open: number, close: number) {
  return (text: string): string =>
    ENABLED ? `[${open}m${text}[${close}m` : text;
}

export const colors = {
  enabled: ENABLED,
  red: wrap(31, 39),
  green: wrap(32, 39),
  yellow: wrap(33, 39),
  blue: wrap(34, 39),
  magenta: wrap(35, 39),
  cyan: wrap(36, 39),
  gray: wrap(90, 39),
  bold: wrap(1, 22),
  dim: wrap(2, 22),
  underline: wrap(4, 24),
};

import type { Severity } from "./types.js";

/** Color a string according to a severity level. */
export function colorForSeverity(severity: Severity, text: string): string {
  switch (severity) {
    case "critical":
      return colors.bold(colors.red(text));
    case "high":
      return colors.red(text);
    case "moderate":
      return colors.yellow(text);
    case "low":
      return colors.cyan(text);
    case "info":
    default:
      return colors.gray(text);
  }
}
