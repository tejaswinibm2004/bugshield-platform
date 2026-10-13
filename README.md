# BugShield — Multi-Agent Driven Intelligent Bug Detection and Secure Deployment System

A multi-tenant platform that connects to real customer websites and repositories, detects
genuine defects in their source code, generates candidate patches, validates them with real
tools, and deploys eligible fixes behind a risk-based approval gate.

Everything the platform reports comes from something it actually executed. Where a capability
is missing it says so rather than simulating success.

---

## Contents

- [Quick start](#quick-start)
- [Architecture](#architecture)
- [The agent pipeline](#the-agent-pipeline)
- [Roles](#roles)
- [Connecting a website](#connecting-a-website)
- [Connecting a repository](#connecting-a-repository)
- [Self-hosted source agent](#self-hosted-source-agent)
- [Deployment to Render](#deployment-to-render)
- [Tests and evaluation](#tests-and-evaluation)
- [What works and what does not](#what-works-and-what-does-not)

---

## Quick start

Requires **Node 24+** (`node:sqlite` is unavailable before 23 without a flag).

```bash
npm install
npm start          # http://localhost:3000
```

On first run a bootstrap owner account is created and its password is printed **once** to the
console. It is stored only as a scrypt hash and cannot be recovered.

Set `BOOTSTRAP_OWNER_EMAIL` and `BOOTSTRAP_OWNER_PASSWORD` in `.env` to control it.

### Commands

| Command | Purpose |
|---|---|
| `npm start` | Run the platform |
| `npm test` | Full test suite (92 tests) |
| `npm run eval` | Reproducible evaluation over the labelled corpus |
| `npm run seed-corpus` | Rebuild the benchmark corpus |

---

## Architecture

```
Browser dashboard (platform/public)      Connected customer website
  login.html · index.html                  demo-apps/*  +  sdk/bug-shield-sdk.js
        |  REST + WebSocket                        |  POST /api/v1/issues
        v                                          v
  server.js  (Express + ws)  ──────────────────────────┐
        |                                                 |
        v                                                 v
  platform/http/apiRouter.js  ──>  platform/services/store.js
   (one router, both entry points)             │
                                              v
                                     data/bugshield.db  (node:sqlite, WAL)
                                              |
                                              v
                                     platform/agents/orchestrator.js
```

| Component | File | Role |
|---|---|---|
| API surface | `platform/http/apiRouter.js` | Every route, defined once, mounted by both entry points |
| Identity | `platform/middleware/auth.js` | Sessions, CSRF, capability matrix |
| Tenancy | `platform/services/tenantStore.js` | Every query scoped by `org_id` |
| Schema | `platform/services/database.js`, `migrations.js` | Additive, non-destructive migrations |
| Analysis | `platform/services/analyzers.js` | Static detectors, remediations, real unified diff |
| Source access | `platform/services/workspace.js` | Local folder, git clone, agent delegation |
| Integrations | `repositoryProviders.js`, `ciProviders.js`, `mailer.js` | GitHub, Jenkins/GitHub Actions, SMTP |

---

## The agent pipeline

```
Issue received
   └─ Agent 1  Detection        locate the real file, prove a defect exists
   └─ Agent 2  Risk             explainable 0-100 score under the tenant's policy
   └─ Agent 3  Patch            synthesise a fix, emit a real unified diff
   └─ Agent 4  Validation       node --check, run the project's real tests, npm audit
   └─ Agent 5  Approval gate    only for high-risk or unverified changes
   └─ Agent 6  Deployment       backup, write, health check, rollback
```

Defect classes detected (`platform/services/analyzers.js`):

| Class | Detects | Remediation |
|---|---|---|
| `DIV_ZERO` | Division whose denominator can evaluate to 0 | Injected safe-division guard |
| `UNDEFINED_DYNAMIC_KEY` | Object indexed by a key that can be unknown | Fallback to the median of known values |
| `MISSING_AWAIT` | Async persistence call neither awaited nor guarded | `await` + try/catch |
| `NULL_DEREF` | Value initialised to `null` then dereferenced | Detected, not auto-fixed |

Validation is real: the candidate is parsed with `node --check`, and the project's own test
suite is executed in a temporary sandbox copy. If no test script exists, the platform reports
that behavioural verification was **not** achieved rather than claiming success.

---

## Roles

| Role | Capabilities |
|---|---|
| **Owner** | Everything, including member management and risk policy |
| **Admin** | Manage members, policy, deployments; cannot remove the owner |
| **Developer** | Create projects and applications; **cannot approve patches** |
| **Reviewer** | View and approve/reject patches |
| **Viewer** | **Websites only** — a customer stakeholder, sees no platform internals |

A Viewer receives a single list of connected websites. Every internal API returns 403, and the
website projection deliberately excludes SDK keys, repository URLs and source information.

Security-critical paths (`auth`, `payment`, `checkout`, …) can never be classified LOW risk and
always require a human, regardless of tenant configuration.

---

## Connecting a website

1. Sign in as Owner or Admin.
2. **Connect Website** → name, type, and either a local source path or a Git URL.
3. Register the public site URL so Viewers have something to open:
   `POST /api/v1/apps/<appId>/site-url { "siteUrl": "https://shop.example.com" }`
4. Add the SDK to the customer site:

```html
<script src="https://your-platform/sdk/bug-shield-sdk.js"></script>
<script>
  BugShieldSDK.init({ appId: 'APP-123', ingestionKey: 'bsk_...' });
</script>
```

### Ingestion keys

Create a scoped key from **Apps → Ingestion keys** (`POST /api/v1/apps/:id/ingestion-keys`):

- Stored hashed; shown once; individually revocable
- Optional origin allow-list
- Rate limited per key (30/min) and per IP (60/min)
- Repeat events are aggregated onto one issue rather than spawning a pipeline each time

The legacy SDK key still works but is weaker; migrate to an ingestion key.

---

## Connecting a repository

### GitHub (implemented)

Set one of:

```bash
# GitHub App (recommended, short-lived installation tokens)
GITHUB_APP_ID=
GITHUB_APP_INSTALLATION_ID=
GITHUB_APP_PRIVATE_KEY=      # PEM, \n for newlines

# Development only
GITHUB_TOKEN=
```

`GET /api/v1/integrations/status` performs a real API call and reports `ok:false` with a reason
when credentials are absent or rejected. It never reports a connection that was not established.

### GitLab (planned)

Registered as `implemented: false` and says so. Do not present it as supported.

---

## Self-hosted source agent

For customers whose source must not leave their infrastructure.

```bash
node agent/agent.js \
  --platform https://your-platform \
  --secret bsa_... \
  --dir C:\projects\service-a \
  --dir /srv/service-b \
  --poll 15000
```

Properties:

- **Opens no inbound port** — it only makes outbound requests to the platform
- Reads only the allow-listed directories, and refuses any root outside them
- Transmits **file references only** by default; add `--send-source` to share content
- Read-only: it never writes to the customer's filesystem
- Secret stored hashed and revocable

When the platform cannot see a customer's source and an agent exists, analysis is delegated to
the agent (`AGENT_ANALYSIS_QUEUED`). On response:

| Agent sends | Platform does |
|---|---|
| References only | `AGENT_SOURCE_REQUIRED` — asks for content, does not pretend to analyse |
| Content | Runs the real detectors, records root cause and risk |
| Clean content | `INVALID_REPORT` — no false positives |

---

## Deployment to Render

### Prerequisites

- **Paid plan.** Persistent disks are not available on the free tier.
- Node 24 (set in `render.yaml`).

### Steps

1. Push the repository to GitHub.
2. Render → **New → Blueprint** → select the repo. `render.yaml` is read automatically.
3. Fill in the prompted secrets:
   - `BOOTSTRAP_OWNER_EMAIL`
   - `BOOTSTRAP_OWNER_PASSWORD` — generate with
     `node -e "console.log(require('crypto').randomBytes(9).toString('base64url'))"`
   - `ALLOWED_ORIGINS` — your dashboard origin once known
4. Deploy. Health check: `GET /api/health`.

### Critical: persistent storage

`render.yaml` mounts a 1 GB disk at `/var/data` and sets `BUGSHIELD_DATA_DIR` to match. This is
mandatory. On an ephemeral filesystem **every restart destroys** users, sessions, history, audit
records and cloned repositories, and re-seeds a new owner password.

The startup check logs an error and warns if the data directory is not writable.

### Optional integrations

Leave unset and the platform reports them as *not configured* rather than faking a connection:
`SMTP_HOST`/`SMTP_USER`/`SMTP_PASS`, `GITHUB_APP_*`, `JENKINS_URL`/`JENKINS_TOKEN`,
`HEALTH_CHECK_URL`.

### Security checklist

- [ ] Paid plan with a persistent disk attached
- [ ] `NODE_ENV=production` (enables Secure cookies)
- [ ] `ALLOWED_ORIGINS` set to your real dashboard origin
- [ ] Real `BOOTSTRAP_OWNER_PASSWORD`, rotated from the first-boot value
- [ ] `.env` never committed
- [ ] SMTP configured so invitations email rather than falling back to a manual link

---

## Tests and evaluation

```bash
npm test          # 92 tests
npm run eval      # reproducible evaluation -> benchmark/results.json
```

The suite covers analyzer correctness, real test execution (passing and failing), source-drift
detection, risk explainability, authentication, session handling, CSRF, capability enforcement,
cross-tenant isolation, ingestion key hashing and revocation, rate limiting, de-duplication,
agent authentication, provider honesty, and viewer lockdown.

### Evaluation

8 labelled cases (5 genuine defects, 3 negative controls), three systems compared:

| System | File ID acc. | Recall | Type acc. | False-positive | Patch validity |
|---|---|---|---|---|---|
| Keyword-only baseline | 80% | 80% | 0% | 66.7% | no validation stage |
| Static-analysis-only | 100% | 100% | 100% | 0% | no validation stage |
| Full pipeline | 100% | 100% | 100% | 0% | 100% |

**8 cases cannot support a general accuracy claim.** These figures describe this corpus only.

---

## What works and what does not

### Working

- Multi-tenant authentication, sessions, capability-based authorisation, audit logging
- Tenant isolation on every query (identifier swapping returns 404, never data)
- Real static analysis with syntax-validating remediations and truthful diffs
- Real validation: parsing, the project's own test suite, dependency audit, security scan
- Scoped ingestion keys with origin allow-lists, rate limiting and de-duplication
- Persistent history of issues, analyses, patches, validation evidence, deployments, approvals
- Self-hosted source agent, delegation and resume
- Explanable, policy-driven risk scoring with security floors

### Not implemented — stated, not faked

- **No zero-downtime deployment.** Deployment is an in-place file write; the agent reports
  `zeroDowntime: false`. No blue/green, canary or rolling adapter exists.
- **GitLab** is planned only.
- **GitHub's happy path is untested end to end** — no credentials were available during
  development. Listing, branch creation and pull requests have never run against live GitHub.
- **CI adapters** cannot be exercised without a Jenkins instance or Actions repository.
- **Detection is JavaScript/TypeScript only.** Python, Java and others are not analysed.
- **Patch generation is pattern-based**, covering only the four defect classes above.
- **The agent path stops at `AWAITING_AGENT_PATCH`** — the platform cannot write to the
  customer's filesystem, and no patch-return channel exists.
- **Single instance only.** SQLite plus in-process jobs; a job queue is not implemented.

See `docs/IMPLEMENTATION_STATE.md` for the phased record and `docs/ARCHITECTURE.md` for
architecture detail.