# npm-audit-guard

> Smarter `npm audit` for CI — fail the build on **real** production risk, not noise.

`npm audit` is famously noisy: it floods you with dev-only advisories, vulnerabilities you've already triaged, and findings with no available fix — then exits non-zero and breaks CI. The result is that most teams either pin `--audit-level` and forget it, or ignore audit failures entirely.

**npm-audit-guard** wraps `npm audit` and makes it usable in a pipeline:

- 🎯 **Filters dev vs prod** — audit only what ships (`--prod-only`), so a vulnerable test helper doesn't block your release.
- 📝 **Justified ignore rules with expiry dates** — suppress an accepted risk _with a reason and an expiry_, so it comes back for review instead of being silenced forever.
- 👀 **Human-readable output** — grouped by what's blocking, what's ignored, and what's below your threshold. Colorized, with fix guidance.
- 🚦 **Exits non-zero only on real risk** — at or above your severity threshold, after ignores. Clean, deterministic exit codes for CI.
- 📦 **Zero runtime dependencies** — small, auditable, fast to install.
- 🧩 **CLI _and_ programmatic API** — drop it in a script or call `audit()` from code.

```console
$ npx npm-audit-guard --prod-only --level high
npm-audit-guard  ·  level ≥ high  ·  production only

Found 3 total: 1 critical, 1 high, 1 moderate

✖ 1 blocking vulnerability at or above high:

  minimist  CRITICAL transitive
    Prototype Pollution in minimist
    affected: <1.2.3
    fix: available via `npm audit fix`
    https://github.com/advisories/GHSA-vh95-rmgr-6w4m

↪ 1 ignored by rule:
    lodash [high] (expires 2026-12-31): patched via resolutions, tracked in JIRA-123

· 1 below threshold (highest: moderate) — not blocking.

✖ FAIL  1 blocking issue.
```

## Install

```bash
# one-off, in CI
npx npm-audit-guard --prod-only --level high

# or as a dev dependency
npm install --save-dev npm-audit-guard
```

Requires Node.js ≥ 18 and a lockfile (`package-lock.json` or `npm-shrinkwrap.json`).

## Usage

```
npm-audit-guard [options]

Options:
  -l, --level <severity>   Minimum severity that fails the build.
                           One of: info, low, moderate, high, critical.
                           Default: high (or "level" from config).
  -p, --prod-only          Audit production dependencies only (npm --omit=dev).
      --fix                Run `npm audit fix`, then re-audit and report what
                           was resolved and what still blocks.
      --force              With --fix, allow semver-major upgrades
                           (`npm audit fix --force`). May be breaking.
      --json               Output machine-readable JSON instead of text.
  -c, --config <path>      Path to a config file (skips auto-discovery).
  -C, --cwd <path>         Directory to audit. Default: current directory.
      --no-color           Disable colored output (or set NO_COLOR).
  -v, --version            Print version and exit.
  -h, --help               Show this help and exit.
```

### Exit codes

| Code | Meaning                                                            |
| ---- | ----------------------------------------------------------------- |
| `0`  | No blocking risk found — build passes.                            |
| `1`  | Blocking vulnerabilities found at or above the level.             |
| `2`  | Execution error (npm missing, no lockfile, bad config, etc.).     |

## Configuration

npm-audit-guard looks for configuration in this order:

1. A path passed via `--config`.
2. `.audit-guard.json` (or `.auditguardrc.json` / `.auditguardrc`) in the working directory.
3. An `"auditGuard"` key in `package.json`.

CLI flags always override file configuration.

```jsonc
// .audit-guard.json
{
  "level": "high",
  "prodOnly": true,
  "ignore": [
    {
      "id": "lodash",
      "reason": "Patched via resolutions; advisory does not apply to our usage.",
      "expires": "2026-12-31"
    },
    {
      "id": "GHSA-vh95-rmgr-6w4m",
      "reason": "No upstream fix yet; not reachable in production paths."
    }
  ]
}
```

### Ignore rules

Each ignore rule matches a finding by **any** of its identifiers:

- the **package name** (e.g. `lodash`),
- a **GHSA id** (e.g. `GHSA-vh95-rmgr-6w4m`),
- a **CVE** (e.g. `CVE-2021-23337`), or
- the **npm advisory number** (e.g. `1179`).

Optional fields:

- **`reason`** — recorded in the report so accepted risk is documented, not hidden.
- **`expires`** — an ISO date (`YYYY-MM-DD`). The rule applies through the **end** of that day; afterwards the finding becomes active again and the expired rule is surfaced as a warning. This keeps suppressions from silently outliving their justification.

A bare string is shorthand for `{ "id": "<string>" }`:

```jsonc
{ "ignore": ["lodash", "GHSA-vh95-rmgr-6w4m"] }
```

Ignore rules that match nothing are reported as safe to remove.

## Auto-fixing

`--fix` runs `npm audit fix`, then re-audits and shows you exactly what changed — which blocking findings were resolved and which still remain:

```console
$ npx npm-audit-guard --fix
npm-audit-guard fix

✔ Resolved 1 blocking vulnerability:
    minimist [critical]

— post-fix audit —
...
✔ PASS  no blocking production risk found.
```

By default `npm audit fix` only applies non-breaking upgrades. Add `--force` to allow semver-major bumps (`npm audit fix --force`) for findings that can't be resolved within your stated dependency ranges. Findings with no fix at all are reported as such. The exit code reflects the **post-fix** state, so `--fix` is safe to use directly in CI.

```bash
npx npm-audit-guard --fix          # safe, non-breaking fixes only
npx npm-audit-guard --fix --force  # allow breaking upgrades
```

The same is available programmatically via `fix()`, which returns `{ before, after, resolved, remaining, npmOutput }`.

## Programmatic API

```ts
import { audit } from "npm-audit-guard";

const result = await audit({
  prodOnly: true,
  level: "high",
  // ignore rules can also come from a config file
  ignore: [{ id: "lodash", reason: "tracked in JIRA-123", expires: "2026-12-31" }],
});

if (!result.ok) {
  console.error(`${result.active.length} blocking vulnerabilities`);
  process.exit(1);
}
```

`audit()` returns an [`AuditResult`](./src/types.ts):

| Field             | Description                                                    |
| ----------------- | ------------------------------------------------------------- |
| `ok`              | `true` when there are no active (blocking) findings.          |
| `active`          | Findings at/above `level` that are **not** ignored.           |
| `ignored`         | Findings suppressed by an active ignore rule (with the rule). |
| `belowThreshold`  | Findings below `level` — reported, not blocking.              |
| `expiredIgnores`  | Ignore rules whose `expires` date has passed.                 |
| `unusedIgnores`   | Ignore rules that matched nothing.                            |
| `counts`          | Totals by severity across all findings.                       |
| `config`          | The resolved configuration used for the run.                  |

You can also pass a pre-fetched report instead of spawning npm:

```ts
import { execSync } from "node:child_process";
import { audit } from "npm-audit-guard";

const raw = JSON.parse(execSync("npm audit --json").toString());
const result = await audit({ report: raw, level: "high" });
```

## CI examples

**GitHub Actions**

```yaml
- run: npx npm-audit-guard --prod-only --level high
```

**package.json script**

```jsonc
{
  "scripts": {
    "audit:ci": "npm-audit-guard --prod-only --level high"
  }
}
```

## How it works

- Dev/prod filtering is delegated to npm itself: `--prod-only` runs `npm audit --json --omit=dev`, so it uses npm's own dependency-tree resolution rather than guessing.
- The raw report is normalized into a flat list of findings (supporting both the npm v7+ `vulnerabilities` schema and the legacy npm v6 `advisories` schema).
- Findings are classified against your threshold and ignore rules. Only non-ignored findings at or above `level` are "active" and cause a non-zero exit.

## Development

```bash
npm install
npm run build      # compile TypeScript to dist/
npm test           # run the test suite (node:test)
npm run typecheck  # type-check without emitting
```

## License

MIT
