# Architecture (as discovered in the codebase)

This document describes the system that actually exists in this repository, not an intended design.

## Runtime shape

```
Browser (owner dashboard)          Connected customer website
  platform/public/index.html          demo-apps/*  +  bug-shield-sdk.js
        |  REST + WebSocket                |  POST /api/v1/issues
        v                                  v
  server.js  (Express + ws)  ──────────────────────────┐
        |                                                 |
        v                                                 v
  platform/services/store.js  ──>  data/bugshield.db  (node:sqlite, WAL)
        |
        v
  platform/agents/orchestrator.js
        ├── detectorAgent.js   (Agent 1/2)  -> workspace.js + analyzers.js
        ├── riskAgent.js       (Agent 3)    -> riskConfig.js
        ├── patchAgent.js      (Agent 4)    -> analyzers.js
        ├── pipelineAgent.js   (Agent 5)    -> real sandboxed execution
        └── canaryAgent.js     (Agent 6)    -> file write + git + health probe
```

`api/platform.js` is a second Express entry point for serverless hosts (Vercel). It reuses the same
services and agents. **Known gap:** it duplicates routes rather than sharing a router, so the two entry
points can drift. This should be consolidated.

## Persistence

SQLite via the built-in `node:sqlite` (`DatabaseSync`), WAL enabled, at `data/bugshield.db`
(`/tmp` on Vercel). Schema is created idempotently in `platform/services/database.js`.

| Table | Holds |
|---|---|
| `applications` | Connected apps, sdk keys, repo URLs |
| `issues` | Bug reports, status, risk level/score, root cause |
| `patches` | Diff, original + updated code, AST validity |
| `pipelines` | Run status, current step, accumulated agent logs |
| `validation_runs` | Real validation evidence (exit codes, test counts, commands) |
| `deployments` | Strategy, health checks, rollback status |

Legacy seed data is migrated from `data/db.json` only when `customers` is empty.

## Source access

`platform/services/workspace.js` resolves, per application, in this order:

1. an explicit local folder (`data/sources.json`),
2. a previously cloned workspace under `data/workspaces/<appId>`,
3. cloning `applications.repo_url`,
4. the platform's own checkout, when the app points at this same repository.

If none resolve, the agent reports `SOURCE_UNAVAILABLE` and changes nothing. It never falls back to
guessing a file.

## Defect analysis

`platform/services/analyzers.js` is deterministic static analysis, not a language model. Detectors:

| Type | Detects | Remediation |
|---|---|---|
| `DIV_ZERO` | Division whose denominator can evaluate to 0 | Injected `__bugShieldSafeDiv` guard |
| `UNDEFINED_DYNAMIC_KEY` | Object literal indexed by a key that can hold an unknown value | Nullish fallback to the median of known values |
| `MISSING_AWAIT` | Async persistence call neither awaited nor wrapped in try/catch | `await` + try/catch |
| `NULL_DEREF` | Value initialised to `null` then dereferenced | Detected only, not auto-fixed |

Non-product paths (`tests/`, `benchmark/`, `scripts/`, `__mocks__/`, `*.test.js`, …) are excluded,
because such files embed sample source as string literals and produce findings with no runtime path.

## Honest capability boundaries

These are **not** implemented, and the platform reports them as such rather than simulating them:

- No authentication, no users, no organisations, no RBAC. Every API is unauthenticated.
- No tenant isolation. Any caller can read any application, issue, or patch by ID.
- No GitHub App / OAuth. Repository access is local-folder or `git clone` only.
- No pull-request creation; fixes are committed and pushed with git when the remote matches.
- No blue/green, canary or rolling adapter. Deployment is an in-place file write, which is **not**
  zero-downtime, and the agent labels it `zeroDowntime: false`.
- No database migration handling.
- No self-hosted source agent.
- Risk policy is a code-level constant, not configurable per-tenant, and is not version-stored.
- Detectors cover JavaScript/TypeScript only. Python, Java and other languages are not analysed.
- Patch generation is pattern-based. It cannot fix defects outside the four detectors above.