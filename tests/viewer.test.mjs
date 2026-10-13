/**
 * Viewer-role isolation.
 *
 * A Viewer is a customer stakeholder, not an engineer. They may see the list of
 * websites their organisation uses, and nothing else about the platform.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';

import { db } from '../platform/services/database.js';
import { hashPassword } from '../platform/services/migrations.js';

process.env.NODE_ENV = 'test';

const ORG = 'ORG-VIEWER-TEST';
const now = new Date().toISOString();
db.prepare('INSERT OR IGNORE INTO organizations (id,name,slug,created_at) VALUES (?,?,?,?)').run(ORG, 'Viewer Test', 'viewer-test', now);

// One owner (to drive the UI) and one viewer, same org.
const mkUser = (email, name, role) => {
  let u = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!u) {
    const id = `USR-${crypto.randomBytes(5).toString('hex')}`;
    const { hash, salt, params } = hashPassword('Passw0rd!Viewer');
    db.prepare(`INSERT INTO users (id,email,display_name,password_hash,password_salt,password_params,disabled,created_at) VALUES (?,?,?,?,?,?,0,?)`)
      .run(id, email, name, hash, salt, params, now);
    u = { id };
  }
  db.prepare('INSERT OR IGNORE INTO memberships (user_id,org_id,role,created_at) VALUES (?,?,?,?)').run(u.id, ORG, role, now);
  return u.id;
};
mkUser('owner@viewer-test.local', 'Owner', 'owner');
const viewerId = mkUser('viewer@viewer-test.local', 'Stakeholder', 'viewer');

db.prepare(`INSERT OR REPLACE INTO applications (id,customer_id,name,type,port,repo_url,branch,status,sdk_key,permissions,jenkins_status,docker_status,canary_threshold,org_id,project_id,site_url)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
  .run('APP-VIEW-1', ORG, 'Customer Shop', 'Web Store', 3000, 'https://github.com/customer/private-repo',
       'main', 'Connected', 'sdk_view1_live', '{}', 'none', 'none', '99%', ORG, null, 'https://shop.example.com');

const { default: app } = await import('../api/platform.js');
const server = http.createServer(app);
await new Promise(r => server.listen(0, '127.0.0.1', r));
const BASE = `http://127.0.0.1:${server.address().port}`;
test.after(() => server.close());

const login = async (email) => {
  const res = await fetch(`${BASE}/api/v1/auth/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield' },
    body: JSON.stringify({ email, password: 'Passw0rd!Viewer' })
  });
  return (res.headers.get('set-cookie') || '').split(';')[0];
};
const asViewer = (path, opts = {}) => fetch(`${BASE}${path}`, {
  ...opts, headers: { 'X-Requested-With': 'bugshield', ...(opts.headers || {}), Cookie: viewerCookie }
});
const asOwner = (path, opts = {}) => fetch(`${BASE}${path}`, {
  ...opts, headers: { 'X-Requested-With': 'bugshield', ...(opts.headers || {}), Cookie: ownerCookie }
});

const viewerCookie = await login('viewer@viewer-test.local');
const ownerCookie = await login('owner@viewer-test.local');

test('viewer session reports no internal capabilities', async () => {
  const me = await (await asViewer('/api/v1/auth/me')).json();
  assert.equal(me.role, 'viewer');
  assert.deepEqual(me.capabilities, ['websites:view'], 'a viewer may only list websites');
});

test('viewer can see the connected websites', async () => {
  const res = await asViewer('/api/v1/websites');
  assert.equal(res.status, 200);
  const d = await res.json();
  assert.equal(d.viewerMode, true);
  assert.equal(d.websites.length, 1);
  assert.equal(d.websites[0].name, 'Customer Shop');
  assert.equal(d.websites[0].siteUrl, 'https://shop.example.com');
});

test('the website projection leaks no SDK key, repo or source information', async () => {
  const d = await (await asViewer('/api/v1/websites')).json();
  const raw = JSON.stringify(d);
  assert.ok(!raw.includes('sdk_view1_live'), 'SDK key must not be exposed');
  assert.ok(!raw.includes('private-repo'), 'repository URL must not be exposed');
  for (const w of d.websites) {
    assert.equal(w.sdkKey, undefined);
    assert.equal(w.repoUrl, undefined);
    assert.equal(w.permissions, undefined);
  }
});

test('viewer is refused every internal read endpoint', async () => {
  const internal = [
    '/api/v1/issues',
    '/api/v1/apps',
    '/api/v1/pipelines',
    '/api/v1/validation',
    '/api/v1/deployments',
    '/api/v1/projects',
    '/api/v1/risk-policy',
    '/api/v1/risk-model',
    '/api/v1/evaluation',
    '/api/v1/integrations/status',
    '/api/v1/integrations/ci/verify',
    '/api/v1/source-agents',
    '/api/v1/members',
    '/api/v1/audit'
  ];
  for (const path of internal) {
    const res = await asViewer(path);
    assert.equal(res.status, 403, `${path} must be refused for a viewer (got ${res.status})`);
  }
});

test('viewer cannot approve, reject, invite, or change configuration', async () => {
  const H = { 'Content-Type': 'application/json' };
  const cases = [
    ['POST', '/api/v1/issues/ANY/approve', {}],
    ['POST', '/api/v1/issues/ANY/reject', {}],
    ['POST', '/api/v1/members', { email: 'x@y.z', role: 'admin', confirmPassword: 'Passw0rd!Viewer' }],
    ['POST', '/api/v1/projects', { name: 'sneaky' }],
    ['POST', '/api/v1/risk-policy', { highThreshold: 10, lowThreshold: 1 }],
    ['POST', '/api/v1/apps', { name: 'sneaky' }],
    ['POST', '/api/v1/apps/APP-VIEW-1/source', { sourcePath: 'C:/tmp' }],
    ['POST', '/api/v1/apps/APP-VIEW-1/ingestion-keys', { label: 'sneaky' }],
    ['POST', '/api/v1/source-agents', { name: 'sneaky' }]
  ];
  for (const [method, path, body] of cases) {
    const res = await asViewer(path, { method, headers: H, body: JSON.stringify(body) });
    assert.equal(res.status, 403, `${method} ${path} must be refused for a viewer (got ${res.status})`);
  }
});

test('viewer cannot reach another tenant, even via identifiers', async () => {
  // A viewer of ORG-VIEWER-TEST must not read another org's issue.
  db.prepare(`INSERT OR REPLACE INTO issues (id,application_id,title,description,page_url,status,root_cause,risk_level,risk_score,reported_at,org_id,occurrence_count,first_seen_at,last_seen_at)
              VALUES (?,?,?,?,'/x','RECEIVED','','',0,?,?,1,?,?)`)
    .run('ISSUE-OTHER-TENANT', 'APP-OTHER', 'secret bug', 'secret details', now, 'ORG-SOMEBODY-ELSE', now, now);

  const res = await asViewer('/api/v1/issues/ISSUE-OTHER-TENANT/patch');
  assert.equal(res.status, 403, 'viewer must be refused before any tenant lookup happens');
  const body = await res.json();
  assert.ok(!JSON.stringify(body).includes('secret'), 'no other tenant data may leak');
});

test('owner and developer are unaffected by the viewer lockdown', async () => {
  assert.equal((await asOwner('/api/v1/issues')).status, 200, 'owner must keep full read access');
  assert.equal((await asOwner('/api/v1/apps')).status, 200);

  const devEmail = 'dev@viewer-test.local';
  mkUser(devEmail, 'Developer', 'developer');
  const devCookie = await login(devEmail);
  const res = await fetch(`${BASE}/api/v1/issues`, { headers: { 'X-Requested-With': 'bugshield', Cookie: devCookie } });
  assert.equal(res.status, 200, 'developer must keep engineering read access');

  const devApps = await fetch(`${BASE}/api/v1/apps`, { headers: { 'X-Requested-With': 'bugshield', Cookie: devCookie } });
  assert.equal(devApps.status, 200);
});

test('viewer can still sign out', async () => {
  const res = await asViewer('/api/v1/auth/logout', { method: 'POST' });
  assert.equal(res.status, 200);
  assert.equal((await asViewer('/api/v1/auth/me')).status, 401);
});