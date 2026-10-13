/**
 * Ingestion security tests: scoped keys, origin allow-lists, revocation,
 * rate limiting, payload caps and de-duplication.
 * Run: npm test
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';

import { db } from '../platform/services/database.js';
import { createIngestionKey, listIngestionKeys, originAllowed, revokeIngestionKey, verifyIngestionKey } from '../platform/services/tenantStore.js';
import { hashPassword } from '../platform/services/migrations.js';
import { _resetRateLimits } from '../platform/services/rateLimiter.js';

process.env.NODE_ENV = 'test';

const ORG = 'ORG-INGEST-TEST';
const APP = 'APP-INGEST-TEST';
const now = new Date().toISOString();

// fixture org + app owned by ORG, and an app owned by a DIFFERENT org
db.prepare('INSERT OR IGNORE INTO organizations (id,name,slug,created_at) VALUES (?,?,?,?)').run(ORG, 'Ingest Test', 'ingest-test', now);
db.prepare(`INSERT OR IGNORE INTO applications (id,customer_id,name,type,port,repo_url,branch,status,sdk_key,permissions,jenkins_status,docker_status,canary_threshold,org_id,project_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
  .run(APP, ORG, 'Ingest App', 'Web', 3000, 'https://example.invalid/i', 'main', 'Connected', 'sdk_ingest_test_live', '{}', 'none', 'none', '99%', ORG, null);
db.prepare(`INSERT OR IGNORE INTO applications (id,customer_id,name,type,port,repo_url,branch,status,sdk_key,permissions,jenkins_status,docker_status,canary_threshold,org_id,project_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
  .run('APP-OTHER-ORG', 'ORG-SOMEONE-ELSE', 'Other', 'Web', 3000, 'x', 'main', 'Connected', 'sdk_other_live', '{}', 'none', 'none', '99%', 'ORG-SOMEONE-ELSE', null);

const owner = (() => {
  const email = 'owner@ingest-test.local';
  let u = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (!u) {
    const id = `USR-${crypto.randomBytes(5).toString('hex')}`;
    const { hash, salt, params } = hashPassword('Passw0rd!Ingest');
    db.prepare(`INSERT INTO users (id,email,display_name,password_hash,password_salt,password_params,disabled,created_at) VALUES (?,?,?,?,?,?,0,?)`)
      .run(id, email, 'Ingest Owner', hash, salt, params, now);
    u = { id };
  }
  db.prepare('INSERT OR IGNORE INTO memberships (user_id,org_id,role,created_at) VALUES (?,?,?,?)').run(u.id, ORG, 'owner', now);
  return u.id;
})();

const { default: app } = await import('../api/platform.js');
const server = http.createServer(app);
await new Promise(r => server.listen(0, '127.0.0.1', r));
const BASE = `http://127.0.0.1:${server.address().port}`;
test.after(() => server.close());

function login() {
  return fetch(`${BASE}/api/v1/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield' },
    body: JSON.stringify({ email: 'owner@ingest-test.local', password: 'Passw0rd!Ingest' })
  }).then(r => (r.headers.get('set-cookie') || '').split(';')[0]);
}

const post = (path, body, cookie, extraHeaders = {}) => fetch(`${BASE}${path}`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield', ...(cookie ? { Cookie: cookie } : {}), ...extraHeaders },
  body: JSON.stringify(body)
});

// ------------------------------------------------------------- key handling

test('ingestion key is stored hashed and never recoverable', () => {
  const created = createIngestionKey({ orgId: ORG, applicationId: APP, label: 'test-key' });
  assert.ok(created.key.startsWith('bsk_'), 'plaintext key is returned once');
  const rows = db.prepare('SELECT * FROM ingestion_keys WHERE id = ?').all(created.id);
  assert.equal(rows[0].key_hash !== created.key, true, 'stored value must be the hash, not the key');
  assert.equal(verifyIngestionKey(created.key).id, created.id, 'the key must verify');
});

test('revoked ingestion key stops working immediately', () => {
  const created = createIngestionKey({ orgId: ORG, applicationId: APP, label: 'to-revoke' });
  assert.ok(verifyIngestionKey(created.key), 'key works before revocation');
  assert.equal(revokeIngestionKey(ORG, created.id), true);
  assert.equal(verifyIngestionKey(created.key), null, 'revoked key must not verify');
});

test('a key cannot be revoked across tenants', () => {
  const created = createIngestionKey({ orgId: ORG, applicationId: APP, label: 'foreign-revoke' });
  assert.equal(revokeIngestionKey('ORG-SOMEONE-ELSE', created.id), false, 'ownership must be enforced');
  assert.ok(verifyIngestionKey(created.key), 'key must survive a foreign revoke attempt');
});

test('garbage keys are rejected without touching the database', () => {
  for (const bad of [null, '', 'short', 'a'.repeat(64), 'bsk_' + 'x'.repeat(50)]) {
    assert.equal(verifyIngestionKey(bad), null);
  }
});

test('origin allow-list is enforced only when configured', () => {
  assert.deepEqual(originAllowed([], 'https://evil.example'), { ok: true, enforced: false });
  assert.equal(originAllowed(['https://shop.example'], 'https://evil.example').ok, false);
  assert.equal(originAllowed(['https://shop.example'], 'https://shop.example').ok, true);
  assert.equal(originAllowed(['https://shop.example'], null).ok, false, 'missing Origin must fail when restricted');
});

// -------------------------------------------------------------- enforcement

test('invalid ingestion key cannot submit a report', async () => {
  _resetRateLimits();
  const res = await post('/api/v1/issues', { ingestion_key: 'bsk_' + 'q'.repeat(43), title: 'x' });
  assert.equal(res.status, 401);
});

test('origin not on the allow-list is rejected', async () => {
  _resetRateLimits();
  const created = createIngestionKey({ orgId: ORG, applicationId: APP, label: 'origin-scoped', allowedOrigins: ['https://shop.example'] });
  const res = await post('/api/v1/issues', { ingestion_key: created.key, title: 'boom', description: 'd' }, null, { Origin: 'https://evil.example' });
  assert.equal(res.status, 403, 'disallowed origin must be refused');

  const ok = await post('/api/v1/issues', { ingestion_key: created.key, title: 'allowed origin', description: 'd', page_url: '/a' }, null, { Origin: 'https://shop.example' });
  assert.equal(ok.status, 200, 'allowed origin must succeed');
});

test('rate limit trips and reports Retry-After', async () => {
  _resetRateLimits();
  const created = createIngestionKey({ orgId: ORG, applicationId: APP, label: 'rate-test' });
  let sawLimit = false;
  for (let i = 0; i < 40; i++) {
    const res = await post('/api/v1/issues', {
      ingestion_key: created.key, title: `unique-${i}`, description: 'd', page_url: `/p${i}`
    });
    if (res.status === 429) { sawLimit = true; assert.ok(res.headers.get('retry-after')); break; }
  }
  assert.ok(sawLimit, 'burst of reports must eventually be rate limited');
  _resetRateLimits();
});

test('oversized payloads are refused', async () => {
  _resetRateLimits();
  const created = createIngestionKey({ orgId: ORG, applicationId: APP, label: 'size-test' });
  const res = await post('/api/v1/issues', {
    ingestion_key: created.key, title: 'big', description: 'x'.repeat(5000), page_url: '/big'
  });
  assert.equal(res.status, 413);
});

test('identical events are de-duplicated into one issue with an occurrence count', async () => {
  _resetRateLimits();
  const created = createIngestionKey({ orgId: ORG, applicationId: APP, label: 'dedupe-test' });
  // Unique per run, otherwise this collides with rows left by a previous run
  // (deduplication intentionally matches recent events for the same app).
  const marker = `run-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
  const payload = {
    ingestion_key: created.key, title: `Repeated error ${marker}`, description: 'same',
    page_url: `/same-${marker}`, stack_trace: `Err: boom ${marker}`
  };
  const first = await (await post('/api/v1/issues', payload)).json();
  assert.equal(first.status, 'RECEIVED');
  const second = await (await post('/api/v1/issues', payload)).json();
  assert.equal(second.status, 'DEDUPLICATED', 'identical event must be aggregated');
  assert.equal(second.issueId, first.issueId, 'must attach to the same issue');
  const row = db.prepare('SELECT occurrence_count FROM issues WHERE id = ?').get(first.issueId);
  assert.ok(row.occurrence_count >= 2, 'occurrence count must increase');
});

test('ingestion key admin endpoints are owner-scoped and return the key once', async () => {
  const cookie = await login();
  const created = await (await post(`/api/v1/apps/${APP}/ingestion-keys`, { label: 'via-api', allowedOrigins: ['https://x.example'] }, cookie)).json();
  assert.equal(created.success, true);
  assert.ok(created.key.key.startsWith('bsk_'));
  assert.equal(created.key.allowedOrigins[0], 'https://x.example');

  const list = await (await fetch(`${BASE}/api/v1/apps/${APP}/ingestion-keys`, { headers: { 'X-Requested-With': 'bugshield', Cookie: cookie } })).json();
  const entry = list.keys.find(k => k.id === created.key.id);
  assert.ok(entry, 'key must be listed');
  assert.equal(entry.key, undefined, 'listing must never expose the plaintext key');

  const del = await fetch(`${BASE}/api/v1/apps/${APP}/ingestion-keys/${created.key.id}`, {
    method: 'DELETE', headers: { 'X-Requested-With': 'bugshield', Cookie: cookie }
  });
  assert.equal(del.status, 200);
  assert.equal(verifyIngestionKey(created.key.key), null, 'revoked via API must not verify');
});

test('ingestion keys of one tenant are invisible to another', async () => {
  const cookie = await login();
  const res = await fetch(`${BASE}/api/v1/apps/APP-OTHER-ORG/ingestion-keys`, {
    headers: { 'X-Requested-With': 'bugshield', Cookie: cookie }
  });
  assert.equal(res.status, 404, 'cross-tenant key listing must 404');
});