/**
 * Security tests: authentication, session handling, RBAC and tenant isolation.
 * These start a real HTTP server and make real requests.
 * Run: npm test
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';

import { db } from '../platform/services/database.js';
import { hashPassword } from '../platform/services/migrations.js';
import * as tenant from '../platform/services/tenantStore.js';
import { roleCan } from '../platform/middleware/auth.js';

process.env.NODE_ENV = 'test';

// Create two isolated organisations with distinct users.
const ORG_A = 'ORG-TEST-A';
const ORG_B = 'ORG-TEST-B';
const now = new Date().toISOString();

function ensureFixture() {
  for (const [id, name, slug] of [[ORG_A, 'Tenant A', 'tenant-a'], [ORG_B, 'Tenant B', 'tenant-b']]) {
    db.prepare('INSERT OR IGNORE INTO organizations (id, name, slug, created_at) VALUES (?,?,?,?)').run(id, name, slug, now);
  }
  const mk = (email, display, org, role, password) => {
    const canonical = email.toLowerCase();
    let u = db.prepare('SELECT id FROM users WHERE email = ?').get(canonical);
    if (!u) {
      const id = `USR-${crypto.randomBytes(6).toString('hex')}`;
      const { hash, salt, params } = hashPassword(password);
      db.prepare(`INSERT INTO users (id,email,display_name,password_hash,password_salt,password_params,disabled,created_at)
                  VALUES (?,?,?,?,?,?,0,?)`).run(id, canonical, display, hash, salt, params, now);
      u = { id };
    }
    db.prepare('INSERT OR IGNORE INTO memberships (user_id,org_id,role,created_at) VALUES (?,?,?,?)').run(u.id, org, role, now);
    return u.id;
  };
  const ownerA = mk(`owner-a-${ORG_A}@test.local`, 'Owner A', ORG_A, 'owner', 'Passw0rd!A');
  const devA = mk(`dev-a-${ORG_A}@test.local`, 'Dev A', ORG_A, 'developer', 'Passw0rd!A');
  const reviewerA = mk(`rev-a-${ORG_A}@test.local`, 'Rev A', ORG_A, 'reviewer', 'Passw0rd!A');
  const ownerB = mk(`owner-b-${ORG_B}@test.local`, 'Owner B', ORG_B, 'owner', 'Passw0rd!B');
  return { ownerA, devA, reviewerA, ownerB };
}

const users = ensureFixture();

// Seed one application + one issue for each tenant.
function seedAppAndIssue(orgId, appId, issueId) {
  db.prepare(`INSERT OR REPLACE INTO applications (id,customer_id,name,type,port,repo_url,branch,status,sdk_key,permissions,jenkins_status,docker_status,canary_threshold,org_id,project_id)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(appId, orgId, `App ${appId}`, 'Web', 3000, 'https://example.invalid/x', 'main', 'Connected',
         `sdk_${appId.toLowerCase()}_live`, '{}', 'none', 'none', '99%', orgId, null);
  db.prepare(`INSERT OR REPLACE INTO issues (id,application_id,title,description,page_url,steps_to_reproduce,stack_trace,logs,browser_info,status,root_cause,risk_level,risk_score,reported_at,resolved_at,org_id,occurrence_count,first_seen_at,last_seen_at)
              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
    .run(issueId, appId, `Bug in ${appId}`, 'secret business logic', '/x', '', '', '[]', '{}',
         'AWAITING_ADMIN_APPROVAL', 'root cause', 'HIGH', 80, now, null, orgId, 1, now, now);
  db.prepare(`INSERT OR REPLACE INTO patches (id,issue_id,application_id,diff,description,status,patch_result,created_at,approved_at,org_id)
              VALUES (?,?,?,?,?,?,?,?,?,?)`)
    .run(`PATCH-${issueId}`, issueId, appId, '--- a\n+++ b', 'fix', 'PENDING_APPROVAL', '{}', now, null, orgId);
}
seedAppAndIssue(ORG_A, 'APP-TEST-A1', 'ISSUE-TEST-A1');
seedAppAndIssue(ORG_B, 'APP-TEST-B1', 'ISSUE-TEST-B1');

// --- boot the real app on an ephemeral port ---
process.env.PORT = '0';
const { default: app } = await import('../api/platform.js');
const server = http.createServer(app);
await new Promise(r => server.listen(0, '127.0.0.1', r));
const BASE = `http://127.0.0.1:${server.address().port}`;

async function login(email, password) {
  const res = await fetch(`${BASE}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield' },
    body: JSON.stringify({ email, password })
  });
  const cookie = (res.headers.get('set-cookie') || '').split(';')[0];
  return { res, body: await res.json(), cookie };
}

test.after(() => server.close());

// ------------------------------------------------------------ authentication

test('unauthenticated access to tenant data is rejected', async () => {
  const res = await fetch(`${BASE}/api/v1/issues`, { headers: { 'X-Requested-With': 'bugshield' } });
  assert.equal(res.status, 401, 'issues must require authentication');
});

test('login with correct credentials establishes a session', async () => {
  const { res, body, cookie } = await login(`owner-a-${ORG_A}@test.local`, 'Passw0rd!A');
  assert.equal(res.status, 200);
  assert.equal(body.success, true);
  assert.equal(body.organization.id, ORG_A);
  assert.ok(cookie.startsWith('bs_session='), 'session cookie must be issued');
  assert.ok(!/HttpOnly/i.test(res.headers.get('set-cookie') || '') === false, 'cookie must be HttpOnly');
});

test('login with a wrong password is rejected', async () => {
  const { res, body } = await login(`owner-a-${ORG_A}@test.local`, 'wrong-password');
  assert.equal(res.status, 401);
  assert.equal(body.success, false);
  // The error must not reveal whether the account exists.
  assert.match(body.error, /Invalid email or password/);
});

test('unknown account gives the same error as a wrong password', async () => {
  const { res, body } = await login('nobody@nowhere.local', 'whatever');
  assert.equal(res.status, 401);
  assert.match(body.error, /Invalid email or password/);
});

test('mutations without the CSRF header are rejected', async () => {
  const { cookie } = await login(`owner-a-${ORG_A}@test.local`, 'Passw0rd!A');
  const res = await fetch(`${BASE}/api/v1/projects`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookie }, // no X-Requested-With
    body: JSON.stringify({ name: 'CSRF attempt' })
  });
  assert.equal(res.status, 403, 'missing CSRF header must be refused');
});

test('forged session cookie is rejected', async () => {
  const res = await fetch(`${BASE}/api/v1/issues`, {
    headers: { 'X-Requested-With': 'bugshield', Cookie: `bs_session=${crypto.randomBytes(32).toString('base64url')}` }
  });
  assert.equal(res.status, 401);
});

// ----------------------------------------------------------- tenant isolation

test('tenant A cannot list or read tenant B data', async () => {
  const { cookie } = await login(`owner-a-${ORG_A}@test.local`, 'Passw0rd!A');
  const H = { 'X-Requested-With': 'bugshield', Cookie: cookie };

  const list = await (await fetch(`${BASE}/api/v1/issues`, { headers: H })).json();
  const ids = (list.issues || []).map(i => i.id);
  assert.ok(ids.includes('ISSUE-TEST-A1'), 'tenant A must see its own issue');
  assert.ok(!ids.includes('ISSUE-TEST-B1'), 'tenant A must never see tenant B issues');

  const apps = await (await fetch(`${BASE}/api/v1/apps`, { headers: H })).json();
  const appIds = (apps || []).map(a => a.id);
  assert.ok(appIds.includes('APP-TEST-A1'));
  assert.ok(!appIds.includes('APP-TEST-B1'));
});

test('tenant A cannot fetch tenant B patch by identifier', async () => {
  const { cookie } = await login(`owner-a-${ORG_A}@test.local`, 'Passw0rd!A');
  const H = { 'X-Requested-With': 'bugshield', Cookie: cookie };
  const res = await fetch(`${BASE}/api/v1/issues/ISSUE-TEST-B1/patch`, { headers: H });
  assert.equal(res.status, 404, 'cross-tenant identifier must not resolve');
  const body = await res.json();
  // The response must not carry any patch content belonging to the other tenant.
  assert.equal(body.diff, undefined, 'no diff may leak');
  assert.equal(body.patchResult, undefined, 'no patch payload may leak');
  assert.equal(body.issueId, undefined, 'no foreign record identifier may leak');
});

test('tenant A cannot read tenant B source-code status', async () => {
  const { cookie } = await login(`owner-a-${ORG_A}@test.local`, 'Passw0rd!A');
  const H = { 'X-Requested-With': 'bugshield', Cookie: cookie };
  const res = await fetch(`${BASE}/api/v1/apps/APP-TEST-B1/source`, { headers: H });
  assert.equal(res.status, 404);
});

test('tenant A cannot approve or reject a tenant B patch', async () => {
  const { cookie } = await login(`owner-a-${ORG_A}@test.local`, 'Passw0rd!A');
  const H = { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield', Cookie: cookie };
  const approve = await fetch(`${BASE}/api/v1/issues/ISSUE-TEST-B1/approve`, { method: 'POST', headers: H });
  assert.equal(approve.status, 404, 'approval must not reach another tenant');
  const reject = await fetch(`${BASE}/api/v1/issues/ISSUE-TEST-B1/reject`, { method: 'POST', headers: H });
  assert.equal(reject.status, 404);
});

test('tenant B sees only its own data', async () => {
  const { cookie } = await login(`owner-b-${ORG_B}@test.local`, 'Passw0rd!B');
  const H = { 'X-Requested-With': 'bugshield', Cookie: cookie };
  const list = await (await fetch(`${BASE}/api/v1/issues`, { headers: H })).json();
  const ids = (list.issues || []).map(i => i.id);
  assert.ok(ids.includes('ISSUE-TEST-B1'));
  assert.ok(!ids.includes('ISSUE-TEST-A1'));
});

// ------------------------------------------------------------------------ RBAC

test('capability matrix enforces least privilege', () => {
  assert.equal(roleCan('owner', 'member:manage'), true);
  assert.equal(roleCan('admin', 'member:manage'), true);
  assert.equal(roleCan('developer', 'member:manage'), false);
  assert.equal(roleCan('reviewer', 'member:manage'), false);
  assert.equal(roleCan('viewer', 'member:manage'), false);

  assert.equal(roleCan('reviewer', 'patch:approve'), true, 'reviewers approve patches');
  assert.equal(roleCan('developer', 'patch:approve'), false, 'developers may not approve their own patch');
  assert.equal(roleCan('viewer', 'patch:approve'), false);

  // A viewer is a customer stakeholder, not a read-only engineer: they may
  // list their websites and nothing else about the platform.
  assert.equal(roleCan('viewer', 'websites:view'), true, 'viewers can list their websites');
  assert.equal(roleCan('viewer', 'patch:view'), false, 'viewers must not read bug internals');
  assert.equal(roleCan('viewer', 'settings:view'), false);
  assert.equal(roleCan('viewer', 'deploy:trigger'), false);
  assert.equal(roleCan('viewer', 'audit:view'), false);

  assert.equal(roleCan('developer', 'patch:view'), true, 'developers keep engineering read access');
  assert.equal(roleCan('reviewer', 'patch:view'), true);

  assert.equal(roleCan('developer', 'app:disconnect'), false, 'only owner/admin disconnect');
  assert.equal(roleCan('admin', 'app:disconnect'), true);
});

test('developer is refused approval and member management at the HTTP layer', async () => {
  const { cookie } = await login(`dev-a-${ORG_A}@test.local`, 'Passw0rd!A');
  const H = { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield', Cookie: cookie };

  const approve = await fetch(`${BASE}/api/v1/issues/ISSUE-TEST-A1/approve`, { method: 'POST', headers: H });
  assert.equal(approve.status, 403, 'developer must not approve');

  const members = await fetch(`${BASE}/api/v1/members`, {
    method: 'POST', headers: H, body: JSON.stringify({ email: 'x@y.z', role: 'admin' })
  });
  assert.equal(members.status, 403, 'developer must not manage members');
});

test('reviewer may approve within their own tenant', async () => {
  const { cookie } = await login(`rev-a-${ORG_A}@test.local`, 'Passw0rd!A');
  const H = { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield', Cookie: cookie };
  const res = await fetch(`${BASE}/api/v1/issues/ISSUE-TEST-A1/approve`, { method: 'POST', headers: H });
  // The pipeline for this fixture has no patch payload, so it resolves to a
  // controlled no-op rather than deploying anything. The point is authorisation passed.
  assert.notEqual(res.status, 403, 'reviewer must not be blocked by authorisation');
  assert.notEqual(res.status, 404);
});

test('denied actions are written to the audit log', async () => {
  const { cookie } = await login(`dev-a-${ORG_A}@test.local`, 'Passw0rd!A');
  await fetch(`${BASE}/api/v1/issues/ISSUE-TEST-A1/approve`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield', Cookie: cookie }
  });
  const logs = tenant.listAuditLogs(ORG_A);
  assert.ok(logs.some(l => l.action === 'authz.denied'), 'authorization denials must be recorded');
  assert.ok(logs.some(l => l.action === 'auth.login'), 'logins must be recorded');
});

test('risk policy is versioned per tenant', () => {
  const before = tenant.getActiveRiskPolicy(ORG_A);
  const first = tenant.createRiskPolicy({ orgId: ORG_A, userId: users.ownerA, highThreshold: 80, lowThreshold: 30, autoDeployEnabled: false });
  const second = tenant.createRiskPolicy({ orgId: ORG_A, userId: users.ownerA, highThreshold: 85, lowThreshold: 40, autoDeployEnabled: true });
  assert.equal(second.version, first.version + 1, 'each policy change increments the version');
  assert.equal(second.high_threshold, 85);
  assert.ok(first.version > (before ? before.version : 0) - 1);

  const policyB = tenant.getActiveRiskPolicy(ORG_B);
  assert.equal(policyB, null, 'policies must not leak between tenants');
});

test('invalid risk thresholds are refused by the tenant store contract', async () => {
  const { cookie } = await login(`owner-a-${ORG_A}@test.local`, 'Passw0rd!A');
  const res = await fetch(`${BASE}/api/v1/risk-policy`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield', Cookie: cookie },
    body: JSON.stringify({ highThreshold: 10, lowThreshold: 90 }) // inverted
  });
  assert.equal(res.status, 400, 'low >= high must be rejected');
});

test('logout invalidates the session', async () => {
  const { cookie } = await login(`owner-a-${ORG_A}@test.local`, 'Passw0rd!A');
  const H = { 'X-Requested-With': 'bugshield', Cookie: cookie };
  assert.equal((await fetch(`${BASE}/api/v1/auth/me`, { headers: H })).status, 200);
  await fetch(`${BASE}/api/v1/auth/logout`, { method: 'POST', headers: H });
  assert.equal((await fetch(`${BASE}/api/v1/auth/me`, { headers: H })).status, 401, 'session must be dead after logout');
});

test('ingestion endpoint stays reachable without a session but rejects bad keys', async () => {
  const res = await fetch(`${BASE}/api/v1/issues`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield' },
    body: JSON.stringify({ application_id: 'APP-DOES-NOT-EXIST', title: 'x' })
  });
  assert.equal(res.status, 401, 'unknown ingestion key must be refused');
});