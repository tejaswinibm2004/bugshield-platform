/**
 * Integration-honesty tests.
 *
 * These assert the platform never claims a connection or a verification result
 * it did not actually obtain, and that agent + provider auth is enforced.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';

import { db } from '../platform/services/database.js';
import { hashPassword, hashToken } from '../platform/services/migrations.js';
import { GitHubProvider, getProvider } from '../platform/services/repositoryProviders.js';
import { JenkinsProvider, GitHubActionsProvider } from '../platform/services/ciProviders.js';

process.env.NODE_ENV = 'test';

const ORG = 'ORG-INTEGRATION-TEST';
const now = new Date().toISOString();
db.prepare('INSERT OR IGNORE INTO organizations (id,name,slug,created_at) VALUES (?,?,?,?)').run(ORG, 'Integration Test', 'integration-test', now);
const email = 'owner@integration-test.local';
let ownerId;
{
  let u = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!u) {
    ownerId = `USR-${crypto.randomBytes(5).toString('hex')}`;
    const { hash, salt, params } = hashPassword('Passw0rd!Integration');
    db.prepare(`INSERT INTO users (id,email,display_name,password_hash,password_salt,password_params,disabled,created_at) VALUES (?,?,?,?,?,?,0,?)`)
      .run(ownerId, email, 'Integration Owner', hash, salt, params, now);
    u = { id: ownerId };
  }
  db.prepare('INSERT OR IGNORE INTO memberships (user_id,org_id,role,created_at) VALUES (?,?,?,?)').run(u.id, ORG, 'owner', now);
}

const { default: app } = await import('../api/platform.js');
const server = http.createServer(app);
await new Promise(r => server.listen(0, '127.0.0.1', r));
const BASE = `http://127.0.0.1:${server.address().port}`;
test.after(() => server.close());

const authed = (url, options = {}) => fetch(`${BASE}${url}`, {
  ...options,
  headers: { 'X-Requested-With': 'bugshield', ...(options.headers || {}) }
});

// ------------------------------------------------------------- repo provider

test('GitHub provider reports unconfigured instead of pretending to work', async () => {
  const saved = { ...process.env };
  delete process.env.GITHUB_TOKEN;
  delete process.env.GITHUB_APP_ID;
  delete process.env.GITHUB_APP_INSTALLATION_ID;
  delete process.env.GITHUB_APP_PRIVATE_KEY;

  const gh = new GitHubProvider();
  assert.equal(gh.isConfigured(), false);
  const v = await gh.verify();
  assert.equal(v.ok, false, 'must not report success without credentials');
  assert.equal(v.configured, false);
  assert.match(v.error, /GITHUB_APP_ID|GITHUB_TOKEN/);

  const list = await gh.listRepositories();
  assert.equal(list.ok, false);
  assert.deepEqual(list.repositories, [], 'no repository may be invented');
  process.env = saved;
});

test('GitHub provider reports failure when the API rejects the token', async () => {
  const saved = process.env.GITHUB_TOKEN;
  process.env.GITHUB_TOKEN = 'definitely_not_a_valid_token';
  process.env.GITHUB_API_URL = 'http://127.0.0.1:59997'; // nothing listening
  const gh = new GitHubProvider();
  assert.equal(gh.isConfigured(), true, 'token presence means configured');
  const v = await gh.verify();
  assert.equal(v.ok, false, 'an unreachable API must not verify');
  process.env.GITHUB_TOKEN = saved;
  delete process.env.GITHUB_API_URL;
});

test('GitLab is declared unimplemented rather than silently missing', async () => {
  const gl = getProvider('gitlab');
  assert.ok(gl);
  const v = await gl.verify();
  assert.equal(v.ok, false);
  assert.match(v.error, /not implemented/i);
});

test('integration status endpoint is honest when nothing is configured', async () => {
  const saved = { ...process.env };
  for (const k of ['GITHUB_TOKEN', 'GITHUB_APP_ID', 'JENKINS_URL', 'JENKINS_TOKEN', 'GITHUB_REPOSITORY']) delete process.env[k];

  const cookie = (await fetch(`${BASE}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield' },
    body: JSON.stringify({ email, password: 'Passw0rd!Integration' })
  }).then(r => (r.headers.get('set-cookie') || '').split(';')[0]));

  const d = await (await authed('/api/v1/integrations/status', { headers: { Cookie: cookie } })).json();
  const gh = d.repository.find(r => r.provider === 'github');
  assert.equal(gh.ok, false, 'GitHub must not verify without credentials');
  assert.equal(d.repository.find(r => r.provider === 'gitlab').implemented, false);
  assert.ok(d.ci.every(c => c.configured === false), 'no CI provider may claim configuration');
  assert.equal(d.deployment[0].zeroDowntime, false, 'zero-downtime must be reported unsupported');
  process.env = saved;
});

test('listing GitHub repositories fails cleanly when unconfigured', async () => {
  const saved = { ...process.env };
  delete process.env.GITHUB_TOKEN;
  const cookie = (await fetch(`${BASE}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield' },
    body: JSON.stringify({ email, password: 'Passw0rd!Integration' })
  }).then(r => (r.headers.get('set-cookie') || '').split(';')[0]));
  const res = await authed('/api/v1/integrations/github/repositories', { headers: { Cookie: cookie } });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.success, false);
  assert.ok(!body.repositories, 'no repository list may be returned');
  process.env = saved;
});

// --------------------------------------------------------------- CI adapters

test('CI adapters refuse to verify without configuration', async () => {
  const saved = { ...process.env };
  for (const k of ['JENKINS_URL', 'JENKINS_TOKEN', 'GITHUB_TOKEN', 'GITHUB_REPOSITORY']) delete process.env[k];
  const j = new JenkinsProvider();
  assert.equal(j.isConfigured(), false);
  assert.equal((await j.verify()).ok, false);
  const g = new GitHubActionsProvider();
  assert.equal(g.isConfigured(), false);
  assert.equal((await g.verify()).ok, false);
  process.env = saved;
});

// ------------------------------------------------------------ source agents

test('agent endpoints reject missing and invalid secrets', async () => {
  const anon = await fetch(`${BASE}/api/agent/poll`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({})
  });
  assert.equal(anon.status, 401);

  const forged = await fetch(`${BASE}/api/agent/poll`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer bsa_${'z'.repeat(40)}` }, body: '{}'
  });
  assert.equal(forged.status, 401, 'forged agent secret must be refused');
});

test('agent secret is stored hashed and polling works end to end', async () => {
  const cookie = (await fetch(`${BASE}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield' },
    body: JSON.stringify({ email, password: 'Passw0rd!Integration' })
  }).then(r => (r.headers.get('set-cookie') || '').split(';')[0]));

  const created = await (await authed('/api/v1/source-agents', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Cookie: cookie },
    body: JSON.stringify({ name: 'on-prem agent', roots: ['C:\\projects\\service'] })
  })).json();
  assert.equal(created.success, true);
  assert.ok(created.secret.startsWith('bsa_'));

  const row = db.prepare('SELECT secret_hash FROM source_agents WHERE id = ?').get(created.agent.id);
  assert.notEqual(row.secret_hash, created.secret, 'secret must be stored hashed');

  const poll = await fetch(`${BASE}/api/agent/poll`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${created.secret}` },
    body: JSON.stringify({ fingerprint: 'abc123' })
  });
  assert.equal(poll.status, 200);
  const pollBody = await poll.json();
  assert.equal(pollBody.success, true);
  assert.deepEqual(pollBody.jobs, [], 'no jobs queued yet');

  // Revocation must invalidate the secret immediately.
  const del = await authed(`/api/v1/source-agents/${created.agent.id}`, { method: 'DELETE', headers: { Cookie: cookie } });
  assert.equal(del.status, 200);
  const after = await fetch(`${BASE}/api/agent/poll`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${created.secret}` },
    body: '{}'
  });
  assert.equal(after.status, 401, 'revoked agent must be refused');
});

test('agent secret lookup matches on hash, not plaintext', () => {
  const secret = 'bsa_example_secret_value_for_hash_test';
  const h = hashToken(secret);
  assert.notEqual(h, secret);
  assert.equal(hashToken(secret), h, 'hashing is deterministic for lookup');
});