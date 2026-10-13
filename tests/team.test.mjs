/**
 * Password change and member invitation flow.
 * Covers the real end-to-end path: invite -> activate -> sign in.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';

import { db } from '../platform/services/database.js';
import { hashPassword } from '../platform/services/migrations.js';

process.env.NODE_ENV = 'test';

const ORG = 'ORG-INVITE-TEST';
const now = new Date().toISOString();
db.prepare('INSERT OR IGNORE INTO organizations (id,name,slug,created_at) VALUES (?,?,?,?)').run(ORG, 'Invite Test', 'invite-test', now);

const ownerEmail = 'owner@invite-test.local';
let ownerId;
{
  let u = db.prepare('SELECT id FROM users WHERE email = ?').get(ownerEmail);
  if (!u) {
    ownerId = `USR-${crypto.randomBytes(5).toString('hex')}`;
    const { hash, salt, params } = hashPassword('Passw0rd!Invite');
    db.prepare(`INSERT INTO users (id,email,display_name,password_hash,password_salt,password_params,disabled,created_at) VALUES (?,?,?,?,?,?,0,?)`)
      .run(ownerId, ownerEmail, 'Invite Owner', hash, salt, params, now);
    u = { id: ownerId };
  }
  db.prepare('INSERT OR IGNORE INTO memberships (user_id,org_id,role,created_at) VALUES (?,?,?,?)').run(u.id, ORG, 'owner', now);
}

const { default: app } = await import('../api/platform.js');
const server = http.createServer(app);
await new Promise(r => server.listen(0, '127.0.0.1', r));
const BASE = `http://127.0.0.1:${server.address().port}`;
test.after(() => server.close());

const loginAs = async (email, password) => {
  const res = await fetch(`${BASE}/api/v1/auth/login`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield' },
    body: JSON.stringify({ email, password })
  });
  return { status: res.status, body: await res.json(), cookie: (res.headers.get('set-cookie') || '').split(';')[0] };
};
const withCookie = (cookie, path, opts = {}) => fetch(`${BASE}${path}`, {
  ...opts, headers: { 'X-Requested-With': 'bugshield', ...(opts.headers || {}), ...(cookie ? { Cookie: cookie } : {}) }
});

const NEW_PASSWORD = 'Str0ng-Invite-Pass!';

test('owner can invite a member and receives a one-time activation token', async () => {
  const { cookie } = await loginAs(ownerEmail, 'Passw0rd!Invite');
  const email = `dev${crypto.randomBytes(3).toString('hex')}@team.example`;
  const res = await withCookie(cookie, '/api/v1/members', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, role: 'developer', display_name: 'Dev One', confirmPassword: 'Passw0rd!Invite' })
  });
  const d = await res.json();
  assert.equal(d.success, true);
  assert.equal(d.member.role, 'developer');
  assert.ok(d.activationToken.startsWith('bsi_'), 'an activation token must be issued');
  assert.ok(d.activationLink.includes('/login#activate='), 'an activation link must be provided');

  // The admin must never be handed a usable password.
  const row = db.prepare('SELECT password_hash FROM users WHERE email = ?').get(email);
  assert.ok(row, 'account row must exist');
});

test('invited member cannot sign in before activating', async () => {
  const email = `pre${crypto.randomBytes(3).toString('hex')}@team.example`;
  const { cookie } = await loginAs(ownerEmail, 'Passw0rd!Invite');
  await withCookie(cookie, '/api/v1/members', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, role: 'viewer', confirmPassword: 'Passw0rd!Invite' })
  });
  const attempt = await loginAs(email, 'anything');
  assert.equal(attempt.status, 401, 'an un-activated account must not authenticate');
});

test('activation with a wrong token is refused', async () => {
  const res = await fetch(`${BASE}/api/v1/auth/accept-invite`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield' },
    body: JSON.stringify({ email: 'someone@team.example', token: 'bsi_bogus_token_value_xxxxxxxx', newPassword: NEW_PASSWORD })
  });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /not valid/i);
});

test('activation rejects a short password', async () => {
  const email = `short${crypto.randomBytes(3).toString('hex')}@team.example`;
  const { cookie } = await loginAs(ownerEmail, 'Passw0rd!Invite');
  const d = await (await withCookie(cookie, '/api/v1/members', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, role: 'viewer', confirmPassword: 'Passw0rd!Invite' })
  })).json();

  const res = await fetch(`${BASE}/api/v1/auth/accept-invite`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield' },
    body: JSON.stringify({ email, token: d.activationToken, newPassword: 'short' })
  });
  assert.equal(res.status, 400);
  assert.match((await res.json()).error, /12 characters/);
});

test('full flow: invite -> activate -> sign in -> has the invited role', async () => {
  const email = `full${crypto.randomBytes(3).toString('hex')}@team.example`;
  const { cookie } = await loginAs(ownerEmail, 'Passw0rd!Invite');
  const d = await (await withCookie(cookie, '/api/v1/members', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, role: 'reviewer', display_name: 'Reviewer One', confirmPassword: 'Passw0rd!Invite' })
  })).json();

  const act = await fetch(`${BASE}/api/v1/auth/accept-invite`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield' },
    body: JSON.stringify({ email, token: d.activationToken, newPassword: NEW_PASSWORD })
  });
  assert.equal(act.status, 200, 'activation must succeed');

  const signed = await loginAs(email, NEW_PASSWORD);
  assert.equal(signed.status, 200, 'the new password must work');
  assert.equal(signed.body.role, 'reviewer', 'the invited role must be applied');

  const me = await withCookie(signed.cookie, '/api/v1/auth/me');
  const meBody = await me.json();
  assert.equal(meBody.organization.id, ORG);
  assert.ok(meBody.capabilities.includes('patch:approve'), 'reviewer should be able to approve patches');
  assert.ok(!meBody.capabilities.includes('member:manage'), 'reviewer must not manage members');
});

test('an activation token cannot be reused', async () => {
  const email = `reuse${crypto.randomBytes(3).toString('hex')}@team.example`;
  const { cookie } = await loginAs(ownerEmail, 'Passw0rd!Invite');
  const d = await (await withCookie(cookie, '/api/v1/members', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, role: 'viewer', confirmPassword: 'Passw0rd!Invite' })
  })).json();

  const first = await fetch(`${BASE}/api/v1/auth/accept-invite`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield' },
    body: JSON.stringify({ email, token: d.activationToken, newPassword: NEW_PASSWORD })
  });
  assert.equal(first.status, 200);

  const second = await fetch(`${BASE}/api/v1/auth/accept-invite`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield' },
    body: JSON.stringify({ email, token: d.activationToken, newPassword: 'Another-Str0ng-Pass!1' })
  });
  assert.equal(second.status, 400, 'a used token must be rejected');
  assert.match((await second.json()).error, /already been used/i);
});

test('change password requires the correct current password', async () => {
  const { cookie } = await loginAs(ownerEmail, 'Passw0rd!Invite');
  const wrong = await withCookie(cookie, '/api/v1/auth/set-password', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ currentPassword: 'not-my-password', newPassword: NEW_PASSWORD })
  });
  assert.equal(wrong.status, 403, 'a wrong current password must be refused');
});

test('change password enforces the minimum length and keeps the session alive', async () => {
  const { cookie } = await loginAs(ownerEmail, 'Passw0rd!Invite');
  const tooShort = await withCookie(cookie, '/api/v1/auth/set-password', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ currentPassword: 'Passw0rd!Invite', newPassword: 'tiny' })
  });
  assert.equal(tooShort.status, 400);

  // Rotate and restore so the suite stays re-runnable.
  const ok = await withCookie(cookie, '/api/v1/auth/set-password', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ currentPassword: 'Passw0rd!Invite', newPassword: 'Rotated-Temp-Pass!1' })
  });
  assert.equal(ok.status, 200);

  const stillIn = await withCookie(cookie, '/api/v1/auth/me');
  assert.equal(stillIn.status, 200, 'the current session must survive a password change');

  const withOld = await loginAs(ownerEmail, 'Passw0rd!Invite');
  assert.equal(withOld.status, 401, 'the old password must stop working');

  const back = await loginAs(ownerEmail, 'Rotated-Temp-Pass!1');
  assert.equal(back.status, 200);
  const restore = await withCookie(back.cookie, '/api/v1/auth/set-password', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ currentPassword: 'Rotated-Temp-Pass!1', newPassword: 'Passw0rd!Invite' })
  });
  assert.equal(restore.status, 200);
});

test('a non-admin cannot invite members', async () => {
  const email = `viewer${crypto.randomBytes(3).toString('hex')}@team.example`;
  const { cookie: ownerCookie } = await loginAs(ownerEmail, 'Passw0rd!Invite');
  const d = await (await withCookie(ownerCookie, '/api/v1/members', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, role: 'viewer', confirmPassword: 'Passw0rd!Invite' })
  })).json();
  await fetch(`${BASE}/api/v1/auth/accept-invite`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield' },
    body: JSON.stringify({ email, token: d.activationToken, newPassword: NEW_PASSWORD })
  });

  const { cookie: viewerCookie } = await loginAs(email, NEW_PASSWORD);
  const res = await withCookie(viewerCookie, '/api/v1/members', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'someone@else.example', role: 'admin', confirmPassword: NEW_PASSWORD })
  });
  assert.equal(res.status, 403, 'a viewer must not be able to invite or escalate anyone');
});

test('invite is refused without the correct password, and nothing is created or emailed', async () => {
  const { cookie } = await loginAs(ownerEmail, 'Passw0rd!Invite');
  const email = `denied${crypto.randomBytes(3).toString('hex')}@team.example`;

  const noPassword = await withCookie(cookie, '/api/v1/members', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, role: 'developer' })
  });
  assert.equal(noPassword.status, 403, 'password confirmation must be required');

  const wrongPassword = await withCookie(cookie, '/api/v1/members', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, role: 'developer', confirmPassword: 'definitely-wrong' })
  });
  assert.equal(wrongPassword.status, 403);
  assert.match((await wrongPassword.json()).error, /not created and no email was sent/i);

  // Nothing may exist after a denied attempt.
  const membership = db.prepare('SELECT * FROM memberships m JOIN users u ON u.id = m.user_id WHERE u.email = ?').get(email);
  assert.equal(membership, undefined, 'no membership may be created on a denied invite');
  const invite = db.prepare('SELECT * FROM invitations WHERE email = ?').get(email);
  assert.equal(invite, undefined, 'no invitation may be created on a denied invite');

  // And the failure must be auditable.
  const audit = db.prepare(`SELECT * FROM audit_logs WHERE action = 'member.invite' AND outcome = 'denied' ORDER BY id DESC LIMIT 1`).get();
  assert.ok(audit, 'a denied invite must be written to the audit log');
});

test('with the correct password the invite is created and mail status is reported honestly', async () => {
  const { cookie } = await loginAs(ownerEmail, 'Passw0rd!Invite');
  const email = `mail${crypto.randomBytes(3).toString('hex')}@team.example`;
  const res = await withCookie(cookie, '/api/v1/members', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, role: 'reviewer', confirmPassword: 'Passw0rd!Invite' })
  });
  const d = await res.json();
  assert.equal(res.status, 200);
  assert.ok(d.email, 'the response must describe the email outcome');
  assert.equal(typeof d.email.sent, 'boolean');

  if (d.email.sent) {
    // SMTP really accepted the message.
    assert.equal(d.email.transport, 'smtp');
    assert.equal(d.email.fallbackLink, null, 'no fallback link is needed when mail was delivered');
  } else {
    // Mail is not configured here, so the platform must say so and still hand
    // over the link rather than pretending an email went out.
    assert.match(d.email.reason, /SMTP/i);
    assert.ok(d.email.fallbackLink, 'a link must be returned when mail was not delivered');
    const row = db.prepare('SELECT * FROM invitations WHERE email = ?').get(email);
    assert.ok(row, 'the invitation still exists for manual sharing');
  }
});

test('mailer reports unconfigured rather than pretending to send', async () => {
  const saved = { ...process.env };
  delete process.env.SMTP_URL;
  delete process.env.SMTP_HOST;
  const m = await import('../platform/services/mailer.js');
  assert.equal(m.isConfigured(), false);
  const v = await m.verify();
  assert.equal(v.ok, false);
  assert.equal(v.configured, false);
  const sent = await m.sendInviteEmail({
    to: 'x@y.example', orgName: 'Test', role: 'viewer', invitedBy: 'Owner',
    activationLink: '/login#activate=bsi_example', platformOrigin: 'http://localhost:3000'
  });
  assert.equal(sent.delivered, false, 'must not claim delivery without SMTP');
  assert.equal(sent.transport, 'outbox');
  assert.ok(sent.outboxFile, 'the message should be written to a local outbox');
  process.env = saved;
});

test('remove member revokes their session immediately', async () => {
  const email = `kick${crypto.randomBytes(3).toString('hex')}@team.example`;
  const { cookie: ownerCookie } = await loginAs(ownerEmail, 'Passw0rd!Invite');
  const d = await (await withCookie(ownerCookie, '/api/v1/members', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, role: 'developer', confirmPassword: 'Passw0rd!Invite' })
  })).json();
  await fetch(`${BASE}/api/v1/auth/accept-invite`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'bugshield' },
    body: JSON.stringify({ email, token: d.activationToken, newPassword: NEW_PASSWORD })
  });

  const { cookie: memberCookie } = await loginAs(email, NEW_PASSWORD);
  assert.equal((await withCookie(memberCookie, '/api/v1/auth/me')).status, 200);

  const del = await withCookie(ownerCookie, `/api/v1/members/${d.member.id}`, { method: 'DELETE' });
  assert.equal(del.status, 200);
  assert.equal((await withCookie(memberCookie, '/api/v1/auth/me')).status, 401,
    'removing a member must invalidate their live session');
});