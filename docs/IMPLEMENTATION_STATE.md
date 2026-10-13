# Implementation state

Phased delivery record. Phases are only marked complete when verified by an executed test or a real
run. Nothing here is aspirational.

## Phase status

| Phase | Scope | Status |
|---|---|---|
| 1 | Inspect repository, document architecture and gaps | **Done** |
| 2 | Persistence, authentication, authorisation, tenancy, audit | **Done** |
| 3 | Repository integration + hardened ingestion API | **Done** (GitHub provider, scoped ingestion keys) |
| 4 | Restricted self-hosted agent, CI/CD adapters | **Done** (agent + Jenkins/GitHub Actions adapters) |
| 5 | Intake, detection, risk, patch generation | **Done for JS/TS**, pattern-based only |
| 6 | Isolated validation and reproducible test execution | **Done** (real sandbox execution) |
| 7 | Approvals, deployment adapters, health checks, rollback | **Partial** (approval + file-level rollback; no zero-downtime adapter) |
| 8 | Frontend on real APIs, History repaired | **Done** |
| 9 | Reproducible evaluation addressing reviewer concerns | **Done** (`npm run eval`) |
| 10 | Documentation and setup instructions | **Partial** (this file + ARCHITECTURE.md) |

## Completed in this session

**Removed fabrication.** The validation agent previously emitted invented results: a hardcoded
"14/14 specs passing", a random Jenkins build number, and a Docker tag for a registry that does not
exist. The deployment agent printed invented health probes ("Probe #1: 200 OK (14ms)") for an endpoint
it never contacted, and claimed "no service interruption".

These are now real or explicitly absent:

- Syntax validation runs `node --check` on a staged copy and records the real exit code.
- The project's own test suite is executed in a temp sandbox copy (never in the live tree). Real
  stdout/stderr, exit code, duration and parsed counts are persisted.
- Dependency audit runs `npm audit` only when a lockfile exists, and reports "not run" when offline.
- CI is reported as not configured unless `JENKINS_URL`/`JENKINS_JOB` are set. No build ID is invented.
- Health probes only run against a configured endpoint; otherwise the agent states that live traffic
  was not verified.
- Deployment is labelled `in-place source update`, `zeroDowntime: false`.

**Security fix.** Test execution never uses `shell: true`; a customer's `package.json` is untrusted
input, so npm is invoked through `npm-cli.js` using the current Node binary. If no shell-free runner
exists, the stage reports "not performed" rather than executing something unsafe.

**Lifecycle correction.** Validation previously ran *after* the approval gate, so an admin approved a
diff with no test evidence. Validation now runs before any approval request, and is re-run immediately
before deployment after approval, so source drift is caught.

**Non-product exclusion.** Analysis now skips `tests/`, `benchmark/`, `scripts/` and `*.test.js`. Without
this, `benchmark/seed-corpus.mjs` (which contains sample coupon code inside a string literal) outranked
the real defect. The validation gate correctly refused the resulting invalid patch, which is how the
issue was found.

**Real bug fixed in the risk model.** The base score was counted twice (initialised *and* added through
the breakdown), so scores exceeded their own components. A test now asserts the score equals the sum of
its factors after clamping. Verified: the coupon defect now scores 74 from 25+20+20+9.

## Phase 2 -- identity, tenancy and authorisation (completed)

**Schema** (`platform/services/migrations.js`). Additive only. New tables:
`organizations`, `users`, `memberships`, `sessions`, `projects`, `risk_policies`,
`audit_logs`, `ingestion_keys`. Existing tables gained `org_id` (plus `commit_sha`,
`occurrence_count`, `health_url`, `project_id`). All pre-existing applications,
issues, patches, pipelines, validation runs and deployments were backfilled into the
bootstrap organisation, so no historical record was orphaned. Verified: 0 null
`org_id` values across all six tables.

**Credentials.** scrypt (N=16384, r=8, p=1, 64-byte key) with a per-user random
salt, compared with `timingSafeEqual`. Session tokens are 256-bit random values; only
their SHA-256 hash is stored, so a database leak cannot be replayed as a session.
Login runs a verification even for unknown accounts so response timing does not
disclose whether an email exists. The bootstrap owner password is printed once at
first boot and never persisted.

**Sessions.** Opaque HttpOnly cookie, `SameSite=Strict`, `Secure` in production,
12-hour expiry, revocable, and invalidated when membership is removed.

**CSRF.** Mutations require an `X-Requested-With: bugshield` header, which a
cross-site attacker cannot set without a CORS preflight, plus an Origin/Host match.
API errors return JSON and never expose stack traces.

**Authorisation.** A capability matrix rather than scattered role checks:

| Capability | Roles |
|---|---|
| `project:create`, `app:create`, `app:update` | owner, admin, developer |
| `project:delete`, `app:disconnect` | owner, admin |
| `patch:approve`, `patch:reject` | owner, admin, reviewer |
| `policy:manage`, `member:manage`, `audit:view` | owner, admin |
| `patch:view`, `settings:view` | all roles |

Developers cannot approve patches (separation of duties); viewers are read-only.

**Tenant isolation.** All HTTP data access goes through `platform/services/tenantStore.js`,
where every method requires an explicit `orgId` and includes it in the SQL
predicate. There is deliberately no id-only lookup for tenant-owned records, so
changing an identifier returns 404 rather than another tenant's data. Verified by
tests that attempt cross-tenant reads of issues, patches, source status, and
approval/rejection.

**Route consolidation.** `server.js` and `api/platform.js` previously defined routes
separately, and `server.js` still contained stale unguarded copies of three routes
that Express matched *before* the secured versions. All API routes now live once in
`platform/http/apiRouter.js`, mounted by both entry points.

**Bugs found and fixed during this phase**
- Stale unauthenticated `/api/v1/issues`, `/issues/:id/patch`, `/validation`,
  `/issues/:id/validation` and `/deployments` handlers were shadowing their secured
  replacements, leaving tenant data reachable without a session.
- Login resolved the organisation with `orgs[0].org_id`, but the query aliases the
  column to `id`. This passed `undefined` to SQLite, so every first-login attempt
  returned a 500.
- User emails were not canonicalised. Lookups lowercase the address while seeded
  rows mixed case, so those accounts could never authenticate. Migration now
  lowercases stored emails where it cannot collide.
- `store._mapIssue` was invoked detached, losing `this` and throwing on JSON columns.
  Tenant-scoped view mappers now live in `tenantStore`.

## Phase 3 — ingestion hardening and integration providers (completed)

**Ingestion** (`ingestion_keys` table, `platform/services/rateLimiter.js`).
Browser submissions now authenticate with a scoped ingestion key rather than the
application's long-lived SDK key. Keys are stored as SHA-256 hashes and returned in
plaintext exactly once; they can carry an origin allow-list and are individually
revocable. The endpoint additionally applies per-key and per-IP rate limits
(30/min and 60/min), payload caps on every field, and de-duplication that aggregates
repeat occurrences onto one issue via `occurrence_count`. The legacy `sdk_key` path
still works for backwards compatibility and is labelled as such in the audit log.

**Self-hosted source agent** (`agent/agent.js`). Polls the platform outbound; it
opens no listening socket. Reads only from directories the customer allow-lists,
refuses any root outside them, and transmits file *references* by default — source
content is sent only when the operator passes `--send-source`. Authenticates with a
per-agent bearer secret stored hashed, revocable, and exempt from CSRF because
browsers never attach bearer tokens automatically.

**Repository providers** (`platform/services/repositoryProviders.js`). A provider
interface with a real GitHub implementation supporting GitHub App installation
tokens (RS256-signed, short-lived) and, for development only, a PAT. GitLab is
registered but explicitly `implemented: false` and says so. `verify()` performs a
real API call and returns `ok:false` with a reason otherwise; it can never report a
connection that was not established.

**CI adapters** (`platform/services/ciProviders.js`). Jenkins and GitHub Actions
adapters with real `verify()` calls; unconfigured means `configured:false`.

**Bugs found and fixed during this phase**
- Issue identifiers came from a 4-digit random space (9000 values). Under load this
  guarantees collisions, producing `UNIQUE constraint failed: issues.id` and a 500.
  Now generated from a wide space with a uniqueness check and a monotonic fallback.
- The CSRF same-origin guard blocked *all* legitimate browser ingestion, because an
  SDK on `customer.example` necessarily posts cross-origin to the platform. The
  ingestion route is now exempt and enforces its own per-key origin allow-list.
- `GitHubProvider.request()` threw on network failure instead of returning a failed
  verification, which would have broken the integrations status endpoint.
- Test files share one SQLite database and were running concurrently, corrupting
  each other. The suite now runs serially (`--test-concurrency=1`).

## Phase 4 -- per-tenant risk policy and agent integration (completed)

**Risk policy is now enforced.** `riskAgent.classify()` accepts the owning
organisation's versioned policy. Thresholds are per tenant, and the score itself
is policy-independent so a tenant cannot inflate it by loosening thresholds. Two
governance rules cannot be configured away:

- Automatic deployment is **off** unless the tenant explicitly enables it.
- Security- and money-critical paths can never be classified LOW and always require
  a human. A tenant that sets `low: 90` gets a floor override (recorded as
  `floorApplied`), never a silent downgrade.

The policy id and version are attached to every risk decision and appear in the
agent log, so a decision can be traced to the policy that produced it.

**The self-hosted agent is in the pipeline.** When the platform cannot see a
customer's source and an active agent is registered, `BugDetectionAgent` delegates
via an `onSourceUnavailable` hook; the orchestrator enqueues an `agent_jobs` row
and the issue moves to `AGENT_ANALYSIS_QUEUED` (not `INVALID_REPORT`). When the
agent posts results the pipeline resumes:

- File references only (the default, no `--send-source`) -> `AGENT_SOURCE_REQUIRED`.
  The platform says it needs content rather than pretending to have analysed code.
- Content shared -> the same static detectors run on it, a real root cause and risk
  score are recorded, and the issue moves to `AWAITING_AGENT_PATCH`. The platform
  does not write to the customer's filesystem.
- Clean content -> `INVALID_REPORT`. No false positives.

**Bugs found and fixed during this phase**
- The DIV_ZERO detector only inspected `const x = a / b`, missing the very common
  `return a / b`. Detection coverage was silently lower than assumed; an agent test
  caught it.
- `classify(..., policy = {})` threw on an explicit `null`, because a default
  parameter only applies to `undefined`. Every unconfigured tenant would have hit
  a 500 the first time a report arrived.
- `MultiAgentOrchestrator` was referenced in the agent result handler without being
  imported, so resume silently failed.

## Verified results

`npm test` -- 92/92 passing.
refusal, patch generation, real diff correctness, real test execution (passing and
failing), source-drift detection, risk explainability and security escalation,
non-product exclusion, plus authentication, session handling, CSRF rejection,
capability enforcement, cross-tenant isolation, ingestion key hashing/revocation,
origin allow-lists, rate limiting, de-duplication, agent authentication, and
provider honesty (never reporting an unverified connection as working).

`npm run eval` — 8 labelled cases, 5 genuine defects, 3 negative controls:

| System | File ID acc. | Recall | Type acc. | False-positive | Patch validity | Escalated |
|---|---|---|---|---|---|---|
| Keyword-only baseline | 80% | 80% | 0% | 66.7% | no validation stage | 0 of 5 |
| Static-analysis-only | 100% | 100% | 100% | 0% | no validation stage | 0 of 5 |
| Full pipeline | 100% | 100% | 100% | 0% | 100% | 4 of 5 |

Mean decision time: 0.46 ms / 0.82 ms / 1.94 ms. Mean time to a validated patch: 2.62 ms.

The single non-escalated case is `c04-null-deref`. Before the base-score fix all five escalated; with
the fix it scores 50 (MEDIUM). It still cannot auto-deploy, because `NULL_DEREF` is detection-only and
therefore produces no patch, so the run ends at `PATCH_FAILED`. Escalation and deployability are
independent gates, and this is a case where they differ.


## Open problems that must not be hidden

1. **GitHub provider is unverified against live GitHub.** It makes real REST calls
   and is tested for unconfigured and unreachable states, but no credentials were
   available here, so repository listing, branch creation and pull-request creation
   have not run end to end.
2. **CI adapters cannot be exercised** without a Jenkins instance or GitHub Actions repo.
3. **The agent path stops at patching.** When a customer agent shares source, the
   defect and risk are confirmed, but the platform cannot write to their filesystem,
   so `AWAITING_AGENT_PATCH` requires the customer to apply the change themselves.
   A patch-return channel is not implemented.
4. **Risk calibration is unproven.** 4 of 5 genuine defects escalate. Thresholds were
   not lowered to improve the deployment count. 8 cases cannot support a general
   accuracy claim.
5. **Patch coverage.** Only four defect classes can be fixed automatically, and
   detection is JavaScript/TypeScript only. Python, Java and other languages are not
   analysed.
6. **No zero-downtime deployment.** In-place file writes can briefly interrupt a
   running Node process; the agent reports `zeroDowntime: false`.
7. **References unverified.** No bibliography was supplied, so no DOI/arXiv claim has
   been checked.


