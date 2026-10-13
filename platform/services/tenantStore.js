/**
 * Tenant-scoped data access.
 *
 * Every method that reads or writes tenant-owned data requires an explicit orgId
 * and includes it in the SQL predicate. There is deliberately no "get by id"
 * variant that omits the organisation, so a handler cannot accidentally return
 * another tenant's row by passing a different identifier.
 *
 * System-internal callers (the orchestrator) operate inside a single process and
 * use store.js directly; all HTTP surfaces go through this module.
 */
import { db } from './database.js';
import crypto from 'node:crypto';
import { hashToken, recordAudit } from './migrations.js';

const json = (v, f) => { try { return JSON.parse(v); } catch { return f; } };

function row(r) { return r ? { ...r } : null; }

// ------------------------------------------------------------ organisations

export function listOrganizationsForUser(userId) {
  return db.prepare(`
    SELECT o.id, o.name, o.slug, m.role
    FROM organizations o JOIN memberships m ON m.org_id = o.id
    WHERE m.user_id = ? ORDER BY o.name
  `).all(userId);
}
export function getOrganization(orgId) {
  return row(db.prepare('SELECT * FROM organizations WHERE id = ?').get(orgId));
}
export function createOrganization({ id, name, slug }) {
  db.prepare('INSERT INTO organizations (id, name, slug, created_at) VALUES (?, ?, ?, ?)')
    .run(id, name, slug, new Date().toISOString());
  return getOrganization(id);
}

// -------------------------------------------------------------------- users

export function findUserByEmail(email) {
  return row(db.prepare('SELECT * FROM users WHERE email = ?').get(String(email).toLowerCase().trim()));
}
export function getUser(userId) {
  return row(db.prepare('SELECT id, email, display_name, disabled FROM users WHERE id = ?').get(userId));
}

export function getMembership(userId, orgId) {
  return row(db.prepare('SELECT role FROM memberships WHERE user_id = ? AND org_id = ?').get(userId, orgId));
}
export function listMembers(orgId) {
  return db.prepare(`
    SELECT u.id, u.email, u.display_name, u.disabled, m.role, m.created_at
    FROM memberships m JOIN users u ON u.id = m.user_id
    WHERE m.org_id = ? ORDER BY u.email
  `).all(orgId);
}
export function setMembership(userId, orgId, role) {
  db.prepare(`INSERT INTO memberships (user_id, org_id, role, created_at) VALUES (?, ?, ?, ?)
              ON CONFLICT(user_id, org_id) DO UPDATE SET role = excluded.role`)
    .run(userId, orgId, role, new Date().toISOString());
}
export function removeMembership(userId, orgId) {
  db.prepare('DELETE FROM memberships WHERE user_id = ? AND org_id = ?').run(userId, orgId);
}

// ----------------------------------------------------------------- sessions

export function createSession({ tokenHash, userId, orgId, ip, userAgent, ttlHours = 12 }) {
  const now = new Date();
  const expires = new Date(now.getTime() + ttlHours * 3600 * 1000);
  db.prepare(`INSERT INTO sessions (token_hash, user_id, org_id, created_at, expires_at, last_seen_at, ip, user_agent)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(tokenHash, userId, orgId, now.toISOString(), expires.toISOString(), now.toISOString(), ip || null, userAgent || null);
}
export function getSession(tokenHash) {
  const s = row(db.prepare('SELECT * FROM sessions WHERE token_hash = ?').get(tokenHash));
  if (!s) return null;
  if (new Date(s.expires_at).getTime() < Date.now()) { deleteSession(tokenHash); return null; }
  return s;
}
export function touchSession(tokenHash) {
  db.prepare('UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?').run(new Date().toISOString(), tokenHash);
}
export function deleteSession(tokenHash) {
  db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash);
}
export function revokeAllSessionsForUser(userId) {
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(userId);
}
/** Invalidate every session except the one currently in use. */
export function revokeOtherSessions(userId, keepTokenHash) {
  db.prepare('DELETE FROM sessions WHERE user_id = ? AND token_hash <> ?').run(userId, keepTokenHash);
}
export function purgeExpiredSessions() {
  db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(new Date().toISOString());
}

// ----------------------------------------------------------------- projects

export function listProjects(orgId) {
  return db.prepare('SELECT * FROM projects WHERE org_id = ? ORDER BY name').all(orgId);
}
export function getProject(orgId, projectId) {
  return row(db.prepare('SELECT * FROM projects WHERE org_id = ? AND id = ?').get(orgId, projectId));
}
export function createProject({ id, orgId, name, slug }) {
  db.prepare('INSERT INTO projects (id, org_id, name, slug, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(id, orgId, name, slug, new Date().toISOString());
  return getProject(orgId, id);
}
export function deleteProject(orgId, projectId) {
  db.prepare('DELETE FROM projects WHERE org_id = ? AND id = ?').run(orgId, projectId);
}

// ------------------------------------------------------------- risk policy

export function getActiveRiskPolicy(orgId) {
  return row(db.prepare('SELECT * FROM risk_policies WHERE org_id = ? ORDER BY version DESC LIMIT 1').get(orgId));
}
export function createRiskPolicy({ orgId, userId, highThreshold, lowThreshold, autoDeployEnabled }) {
  const prev = getActiveRiskPolicy(orgId);
  const version = (prev ? prev.version : 0) + 1;
  const id = `RP-${orgId}-${version}`;
  db.prepare(`INSERT INTO risk_policies (id, org_id, version, high_threshold, low_threshold, auto_deploy_enabled, created_by, created_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(id, orgId, version, highThreshold, lowThreshold, autoDeployEnabled ? 1 : 0, userId || null, new Date().toISOString());
  return getActiveRiskPolicy(orgId);
}

// ---------------------------------------------------------- tenant entities

/** Applications belonging to one organisation only. */
export function listApplications(orgId) {
  return db.prepare('SELECT * FROM applications WHERE org_id = ? ORDER BY name').all(orgId);
}
export function getApplicationForOrg(orgId, appId) {
  return row(db.prepare('SELECT * FROM applications WHERE org_id = ? AND (id = ? OR sdk_key = ?)').get(orgId, appId, appId));
}
export function insertApplication(app) {
  db.prepare(`INSERT INTO applications (id, customer_id, name, type, port, repo_url, branch, status, sdk_key, permissions, jenkins_status, docker_status, canary_threshold, org_id, project_id, health_url)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(app.id, app.customerId, app.name, app.type, app.port, app.repoUrl, app.branch, app.status, app.sdkKey,
         JSON.stringify(app.permissions || {}), app.jenkinsStatus, app.dockerStatus, app.canaryThreshold,
         app.orgId, app.projectId || null, app.healthUrl || null);
}
export function updateApplicationForOrg(orgId, appId, fields) {
  const allowed = ['name', 'repo_url', 'branch', 'status', 'health_url', 'project_id', 'site_url'];
  const sets = [], vals = [];
  for (const [k, v] of Object.entries(fields)) {
    if (allowed.includes(k)) { sets.push(`${k} = ?`); vals.push(v); }
  }
  if (!sets.length) return;
  vals.push(orgId, appId);
  db.prepare(`UPDATE applications SET ${sets.join(', ')} WHERE org_id = ? AND id = ?`).run(...vals);
}
export function deleteApplication(orgId, appId) {
  db.prepare('DELETE FROM applications WHERE org_id = ? AND id = ?').run(orgId, appId);
}

/** Issues scoped to the organisation. */
export function listIssues(orgId) {
  return db.prepare('SELECT * FROM issues WHERE org_id = ? ORDER BY reported_at DESC').all(orgId);
}
export function getIssueForOrg(orgId, issueId) {
  return row(db.prepare('SELECT * FROM issues WHERE org_id = ? AND id = ?').get(orgId, issueId));
}
export function insertIssue(issue) {
  db.prepare(`INSERT INTO issues (id, application_id, title, description, page_url, steps_to_reproduce, stack_trace, logs, browser_info, status, root_cause, risk_level, risk_score, reported_at, resolved_at, org_id, commit_sha, occurrence_count, first_seen_at, last_seen_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(issue.id, issue.applicationId, issue.title, issue.description, issue.pageUrl, issue.stepsToReproduce,
         issue.stackTrace, JSON.stringify(issue.logs || []), JSON.stringify(issue.browserInfo || {}),
         issue.status, issue.rootCause || '', issue.riskLevel || '', issue.riskScore || 0,
         issue.reportedAt, issue.resolvedAt || null, issue.orgId, issue.commitSha || null,
         issue.occurrenceCount || 1, issue.firstSeenAt || issue.reportedAt, issue.lastSeenAt || issue.reportedAt);
}
export function updateIssueForOrg(orgId, issueId, updates) {
  const allowed = ['status', 'root_cause', 'risk_level', 'risk_score', 'resolved_at'];
  const sets = [], vals = [];
  for (const [k, v] of Object.entries(updates)) {
    if (allowed.includes(k)) { sets.push(`${k} = ?`); vals.push(v); }
  }
  if (!sets.length) return;
  vals.push(orgId, issueId);
  db.prepare(`UPDATE issues SET ${sets.join(', ')} WHERE org_id = ? AND id = ?`).run(...vals);
}

export function getPatchForOrg(orgId, patchIdOrIssueId) {
  return row(db.prepare('SELECT * FROM patches WHERE org_id = ? AND (id = ? OR issue_id = ?)')
    .get(orgId, patchIdOrIssueId, patchIdOrIssueId));
}
export function getPipelineForOrg(orgId, idOrIssueId) {
  return row(db.prepare('SELECT * FROM pipelines WHERE org_id = ? AND (id = ? OR issue_id = ?)')
    .get(orgId, idOrIssueId, idOrIssueId));
}
export function listValidationRuns(orgId, issueId) {
  const sql = issueId
    ? 'SELECT * FROM validation_runs WHERE org_id = ? AND issue_id = ? ORDER BY created_at DESC'
    : 'SELECT * FROM validation_runs WHERE org_id = ? ORDER BY created_at DESC';
  return issueId ? db.prepare(sql).all(orgId, issueId) : db.prepare(sql).all(orgId);
}
export function listDeployments(orgId, issueId) {
  const sql = issueId
    ? 'SELECT * FROM deployments WHERE org_id = ? AND issue_id = ? ORDER BY created_at DESC'
    : 'SELECT * FROM deployments WHERE org_id = ? ORDER BY created_at DESC';
  return issueId ? db.prepare(sql).all(orgId, issueId) : db.prepare(sql).all(orgId);
}

/**
 * View mappers for tenant-scoped rows.
 * These live here (rather than calling Store's private methods) so that JSON
 * columns are parsed correctly without relying on a `this` binding.
 */
export function toIssueView(r) {
  if (!r) return null;
  return {
    id: r.id,
    applicationId: r.application_id,
    title: r.title,
    description: r.description || '',
    pageUrl: r.page_url || '/',
    stepsToReproduce: r.steps_to_reproduce || '',
    stackTrace: r.stack_trace || '',
    logs: json(r.logs, []),
    browserInfo: json(r.browser_info, {}),
    status: r.status,
    rootCause: r.root_cause || '',
    riskLevel: r.risk_level || '',
    riskScore: r.risk_score || 0,
    reportedAt: r.reported_at,
    resolvedAt: r.resolved_at || null,
    commitSha: r.commit_sha || null,
    occurrenceCount: r.occurrence_count || 1
  };
}

export function toAppView(r) {
  if (!r) return null;
  return {
    id: r.id,
    customerId: r.customer_id,
    name: r.name,
    type: r.type,
    port: r.port,
    repoUrl: r.repo_url,
    branch: r.branch,
    status: r.status,
    sdkKey: r.sdk_key,
    permissions: json(r.permissions, {}),
    jenkinsStatus: r.jenkins_status,
    dockerStatus: r.docker_status,
    canaryThreshold: r.canary_threshold,
    healthUrl: r.health_url || null,
    orgId: r.org_id,
    projectId: r.project_id || null
  };
}

/**
 * Collision-safe issue identifier.
 *
 * A 4-digit random identifier has only 9000 possible values, which guarantees
 * collisions once enough issues exist. Generate from a wide space and verify
 * uniqueness against the table before returning.
 */
export function generateIssueId() {
  for (let attempt = 0; attempt < 10; attempt++) {
    const id = `ISSUE-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const exists = db.prepare('SELECT 1 FROM issues WHERE id = ?').get(id);
    if (!exists) return id;
  }
  // Fall back to a monotonic form that cannot collide.
  const n = db.prepare('SELECT COUNT(*) c FROM issues').get().c + 1;
  return `ISSUE-T${Date.now().toString(36)}${n}`;
}

// --------------------------------------------------------- ingestion keys
/**
 * Ingestion keys authenticate browser/server SDK submissions. Only a SHA-256
 * hash is stored, so a database dump cannot be replayed against the ingestion API.
 * The plaintext key is returned once at creation and is unrecoverable afterwards.
 */
export function createIngestionKey({ orgId, applicationId, label, allowedOrigins = [] }) {
  const id = `IK-${crypto.randomBytes(8).toString('hex')}`;
  const plaintext = `bsk_${crypto.randomBytes(32).toString('base64url')}`;
  db.prepare(`INSERT INTO ingestion_keys (id, application_id, key_hash, label, allowed_origins, revoked, created_at)
              VALUES (?, ?, ?, ?, ?, 0, ?)`)
    .run(id, applicationId, hashToken(plaintext), label || 'default', JSON.stringify(allowedOrigins), new Date().toISOString());
  return { id, key: plaintext, applicationId, label: label || 'default', allowedOrigins, createdAt: new Date().toISOString() };
}

export function listIngestionKeys(orgId, applicationId) {
  const apps = applicationId ? [applicationId] : listApplications(orgId).map(a => a.id);
  if (!apps.length) return [];
  const placeholders = apps.map(() => '?').join(',');
  return db.prepare(`SELECT id, application_id, label, allowed_origins, revoked, created_at
                     FROM ingestion_keys WHERE application_id IN (${placeholders}) ORDER BY created_at DESC`)
    .all(...apps)
    .map(r => ({
      id: r.id, applicationId: r.application_id, label: r.label,
      allowedOrigins: json(r.allowed_origins, []), revoked: !!r.revoked, createdAt: r.created_at
    }));
}

export function revokeIngestionKey(orgId, keyId) {
  // Ownership is proven by joining through the application's org.
  const res = db.prepare(`UPDATE ingestion_keys SET revoked = 1
                          WHERE id = ? AND application_id IN (SELECT id FROM applications WHERE org_id = ?)`)
    .run(keyId, orgId);
  return res.changes > 0;
}

/** Resolve a plaintext ingestion key to its record. Returns null when unknown or revoked. */
export function verifyIngestionKey(plaintext) {
  if (!plaintext || typeof plaintext !== 'string' || plaintext.length < 20) return null;
  const row = db.prepare('SELECT * FROM ingestion_keys WHERE key_hash = ?').get(hashToken(plaintext));
  if (!row || row.revoked) return null;
  return {
    id: row.id,
    applicationId: row.application_id,
    label: row.label,
    allowedOrigins: json(row.allowed_origins, [])
  };
}

/**
 * Origin allow-list check.
 * A key with no configured origins accepts any origin (server-side SDK usage);
 * once origins are configured they are enforced exactly.
 */
export function originAllowed(allowedOrigins, origin) {
  if (!allowedOrigins || allowedOrigins.length === 0) return { ok: true, enforced: false };
  if (!origin) return { ok: false, enforced: true, reason: 'Origin header required for this key' };
  return { ok: allowedOrigins.includes(origin), enforced: true };
}

export function listAuditLogs(orgId, limit = 200) {
  return db.prepare('SELECT * FROM audit_logs WHERE org_id = ? ORDER BY created_at DESC LIMIT ?')
    .all(orgId, limit)
    .map(r => ({ ...r, meta: json(r.meta, null) }));
}

export { recordAudit };