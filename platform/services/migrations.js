/**
 * Additive schema migrations for multi-tenancy, identity and audit.
 *
 * Rules:
 *  - Never drops or rewrites an existing table.
 *  - Adds new columns with ALTER TABLE only when absent.
 *  - Backfills legacy rows into a bootstrap organisation so existing
 *    applications / issues / patches / pipelines stay reachable.
 *
 * Run automatically on import of database.js.
 */
import { db } from './database.js';
import crypto from 'node:crypto';

export const ROLES = ['owner', 'admin', 'developer', 'reviewer', 'viewer'];
export const ROLE_RANK = { owner: 5, admin: 4, developer: 3, reviewer: 2, viewer: 1 };

export const BOOTSTRAP_ORG_ID = 'ORG-BOOTSTRAP';
export const BOOTSTRAP_OWNER_EMAIL = process.env.BOOTSTRAP_OWNER_EMAIL || 'owner@bugshield.local';

function columns(table) {
  try { return db.prepare(`PRAGMA table_info(${table})`).all().map(r => r.name); }
  catch { return []; }
}
function addColumn(table, column, decl) {
  if (!columns(table).includes(column)) {
    db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${decl}`);
    return true;
  }
  return false;
}
function addIndex(name, sql) {
  try { db.exec(`CREATE INDEX IF NOT EXISTS ${name} ${sql}`); } catch { /* index is best-effort */ }
}

export function migrateTenancy() {
  // ---------------------------------------------------------------- tenancy
  db.exec(`
    CREATE TABLE IF NOT EXISTS organizations (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      slug TEXT NOT NULL UNIQUE,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      password_salt TEXT NOT NULL,
      password_params TEXT NOT NULL,
      disabled INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS memberships (
      user_id TEXT NOT NULL,
      org_id TEXT NOT NULL,
      role TEXT NOT NULL,
      created_at TEXT NOT NULL,
      PRIMARY KEY (user_id, org_id)
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token_hash TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      org_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      last_seen_at TEXT,
      ip TEXT,
      user_agent TEXT
    );

    CREATE TABLE IF NOT EXISTS projects (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      name TEXT NOT NULL,
      slug TEXT NOT NULL,
      created_at TEXT NOT NULL,
      UNIQUE (org_id, slug)
    );

    CREATE TABLE IF NOT EXISTS risk_policies (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      version INTEGER NOT NULL,
      high_threshold INTEGER NOT NULL,
      low_threshold INTEGER NOT NULL,
      auto_deploy_enabled INTEGER NOT NULL DEFAULT 0,
      created_by TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      org_id TEXT,
      user_id TEXT,
      action TEXT NOT NULL,
      entity_type TEXT,
      entity_id TEXT,
      outcome TEXT NOT NULL,
      meta TEXT,
      ip TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS ingestion_keys (
      id TEXT PRIMARY KEY,
      application_id TEXT NOT NULL,
      key_hash TEXT NOT NULL,
      label TEXT,
      allowed_origins TEXT,
      revoked INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL
    );

    -- Self-hosted source agents: the platform polls outward, never inbound.
    CREATE TABLE IF NOT EXISTS source_agents (
      id TEXT PRIMARY KEY,
      org_id TEXT NOT NULL,
      application_id TEXT,
      name TEXT NOT NULL,
      secret_hash TEXT NOT NULL,
      fingerprint TEXT,
      roots TEXT,
      status TEXT NOT NULL DEFAULT 'ACTIVE',
      last_seen_at TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS agent_jobs (
      id TEXT PRIMARY KEY,
      agent_id TEXT NOT NULL,
      org_id TEXT NOT NULL,
      issue_id TEXT NOT NULL,
      application_id TEXT,
      root TEXT,
      title TEXT,
      description TEXT,
      status TEXT NOT NULL DEFAULT 'QUEUED',
      result TEXT,
      created_at TEXT NOT NULL,
      completed_at TEXT
    );

    -- One-time activation links so an invited member can set their own password
    -- without the administrator ever knowing or transmitting it.
    CREATE TABLE IF NOT EXISTS invitations (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      token_hash TEXT NOT NULL,
      org_id TEXT NOT NULL,
      role TEXT NOT NULL,
      invited_by TEXT,
      used INTEGER NOT NULL DEFAULT 0,
      expires_at TEXT NOT NULL,
      created_at TEXT NOT NULL
    );
  `);

  // Link existing tenant-owned records to an organisation.
  addColumn('applications', 'org_id', 'TEXT');
  addColumn('applications', 'project_id', 'TEXT');
  addColumn('applications', 'health_url', 'TEXT');
  addColumn('applications', 'site_url', 'TEXT');
  addColumn('issues', 'org_id', 'TEXT');
  addColumn('issues', 'commit_sha', 'TEXT');
  addColumn('issues', 'occurrence_count', 'INTEGER DEFAULT 1');
  addColumn('issues', 'first_seen_at', 'TEXT');
  addColumn('issues', 'last_seen_at', 'TEXT');
  addColumn('patches', 'org_id', 'TEXT');
  addColumn('pipelines', 'org_id', 'TEXT');
  addColumn('validation_runs', 'org_id', 'TEXT');
  addColumn('deployments', 'org_id', 'TEXT');

  addIndex('idx_apps_org', 'ON applications (org_id)');
  addIndex('idx_issues_org', 'ON issues (org_id)');
  addIndex('idx_patches_org', 'ON patches (org_id)');
  addIndex('idx_pipelines_org', 'ON pipelines (org_id)');
  addIndex('idx_sessions_user', 'ON sessions (user_id)');
  addIndex('idx_memberships_org', 'ON memberships (org_id)');
  addIndex('idx_audit_org', 'ON audit_logs (org_id, created_at)');

  bootstrapOrganisation();
}

/**
 * Create the bootstrap organisation, its owner and default project, then attach
 * every pre-existing record to it so no historical data becomes orphaned.
 * Idempotent.
 */
function bootstrapOrganisation() {
  const org = db.prepare('SELECT id FROM organizations WHERE id = ?').get(BOOTSTRAP_ORG_ID);
  if (!org) {
    db.prepare('INSERT INTO organizations (id, name, slug, created_at) VALUES (?, ?, ?, ?)')
      .run(BOOTSTRAP_ORG_ID, 'Acme Software Labs', 'acme', new Date().toISOString());
  }
  db.prepare('INSERT OR IGNORE INTO projects (id, org_id, name, slug, created_at) VALUES (?, ?, ?, ?, ?)')
    .run('PRJ-BOOTSTRAP', BOOTSTRAP_ORG_ID, 'Default Project', 'default', new Date().toISOString());

  const now = new Date().toISOString();
  for (const table of ['applications', 'issues', 'patches', 'pipelines', 'validation_runs', 'deployments']) {
    db.prepare(`UPDATE ${table} SET org_id = ? WHERE org_id IS NULL`).run(BOOTSTRAP_ORG_ID);
  }
  db.prepare(`UPDATE applications SET project_id = 'PRJ-BOOTSTRAP' WHERE project_id IS NULL`).run();
  db.prepare(`UPDATE issues SET first_seen_at = COALESCE(first_seen_at, reported_at), last_seen_at = COALESCE(last_seen_at, reported_at)`).run();

  // Emails are compared case-insensitively, so storage must be canonical.
  // Lowercase only where it cannot collide with an existing address.
  const users = db.prepare('SELECT id, email FROM users').all();
  for (const u of users) {
    if (u.email === u.email.toLowerCase()) continue;
    const lower = u.email.toLowerCase();
    const clash = db.prepare('SELECT id FROM users WHERE email = ? AND id <> ?').get(lower, u.id);
    if (!clash) db.prepare('UPDATE users SET email = ? WHERE id = ?').run(lower, u.id);
  }

  const owner = db.prepare('SELECT id FROM users WHERE email = ?').get(BOOTSTRAP_OWNER_EMAIL);
  let ownerId;
  if (!owner) {
    const password = process.env.BOOTSTRAP_OWNER_PASSWORD || crypto.randomBytes(9).toString('base64url');
    const { hash, salt, params } = hashPassword(password);
    ownerId = 'USR-' + crypto.randomBytes(6).toString('hex');
    db.prepare(`INSERT INTO users (id, email, display_name, password_hash, password_salt, password_params, disabled, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 0, ?)`)
      .run(ownerId, BOOTSTRAP_OWNER_EMAIL, 'Platform Owner', hash, salt, params, now);
    db.prepare('INSERT OR IGNORE INTO memberships (user_id, org_id, role, created_at) VALUES (?, ?, ?, ?)')
      .run(ownerId, BOOTSTRAP_ORG_ID, 'owner', now);
    // Printed once, at creation only. Never stored anywhere.
    console.log('\n=========================================================');
    console.log(' BOOTSTRAP OWNER ACCOUNT CREATED');
    console.log(`   email    : ${BOOTSTRAP_OWNER_EMAIL}`);
    console.log(`   password : ${password}`);
    console.log('   Change this password before any real deployment.');
    console.log('=========================================================\n');
  }
  return ownerId;
}

/** scrypt password hashing with a per-user random salt. */
export function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const N = 16384, r = 8, p = 1, keylen = 64;
  const hash = crypto.scryptSync(password, salt, keylen, { N, r, p }).toString('hex');
  return { hash, salt, params: JSON.stringify({ N, r, p, keylen }) };
}

/** Constant-time password verification. */
export function verifyPassword(password, user) {
  if (!user) return false;
  try {
    const { N, r, p, keylen } = JSON.parse(user.password_params);
    const candidate = crypto.scryptSync(password, user.password_salt, keylen, { N, r, p });
    const expected = Buffer.from(user.password_hash, 'hex');
    // Length check first, then constant-time compare.
    if (candidate.length !== expected.length) return false;
    return crypto.timingSafeEqual(candidate, expected);
  } catch {
    return false;
  }
}

/** Opaque session token; only its hash is persisted. */
export function newSessionToken() {
  return crypto.randomBytes(32).toString('base64url');
}
export function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

export function recordAudit({ orgId = null, userId = null, action, entityType = null, entityId = null, outcome = 'success', meta = null, ip = null }) {
  db.prepare(`INSERT INTO audit_logs (org_id, user_id, action, entity_type, entity_id, outcome, meta, ip, created_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(orgId, userId, action, entityType, entityId, outcome, meta ? JSON.stringify(meta) : null, ip, new Date().toISOString());
}

export default migrateTenancy;