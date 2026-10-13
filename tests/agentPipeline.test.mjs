/**
 * Self-hosted agent pipeline integration.
 * Proves the platform delegates analysis to a customer's agent when it cannot
 * see their source, and resumes correctly when the agent reports back.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';

import { db } from '../platform/services/database.js';
import { hashPassword, hashToken } from '../platform/services/migrations.js';

process.env.NODE_ENV = 'test';

const ORG = 'ORG-AGENT-PIPELINE';
const APP = 'APP-AGENT-PIPELINE';
const now = new Date().toISOString();

db.prepare('INSERT OR IGNORE INTO organizations (id,name,slug,created_at) VALUES (?,?,?,?)').run(ORG, 'Agent Pipeline', 'agent-pipe', now);
db.prepare(`INSERT OR IGNORE INTO applications (id,customer_id,name,type,port,repo_url,branch,status,sdk_key,permissions,jenkins_status,docker_status,canary_threshold,org_id,project_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
  .run(APP, ORG, 'Private Repo App', 'Web', 3000, 'https://github.invalid/private/repo', 'main', 'Connected',
       'sdk_agent_pipe_live', '{}', 'none', 'none', '99%', ORG, null);

// Register an agent whose secret we hold.
const agentSecret = `bsa_${crypto.randomBytes(32).toString('base64url')}`;
const agentId = `AGT-${crypto.randomBytes(6).toString('hex')}`;
db.prepare(`INSERT OR REPLACE INTO source_agents (id,org_id,application_id,name,secret_hash,fingerprint,roots,status,created_at)
            VALUES (?,?,?,?,?,NULL,?,'ACTIVE',?)`)
  .run(agentId, ORG, APP, 'on-prem agent', hashToken(agentSecret), JSON.stringify(['/srv/app']), now);

const { default: app } = await import('../api/platform.js');
const server = http.createServer(app);
await new Promise(r => server.listen(0, '127.0.0.1', r));
const BASE = `http://127.0.0.1:${server.address().port}`;
test.after(() => server.close());

const agentPost = (pathname, body) => fetch(`${BASE}${pathname}`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${agentSecret}` },
  body: JSON.stringify(body)
});

test('agent authenticates and receives its queued job', async () => {
  // Queue a job the way the orchestrator does when no source is visible.
  const jobId = `AJB-TEST-${Date.now()}`;
  db.prepare(`INSERT INTO agent_jobs (id,agent_id,org_id,issue_id,application_id,root,title,description,status,created_at)
              VALUES (?,?,?,?,?,NULL,?,?,'QUEUED',?)`)
    .run(jobId, agentId, ORG, 'ISSUE-AGENT-1', APP, 'checkout total is wrong', 'discount calculation error', now);

  const res = await agentPost('/api/agent/poll', { fingerprint: 'fp123', dirs: ['app'] });
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.success, true);
  assert.ok(Array.isArray(body.jobs) && body.jobs.length >= 1, 'queued job must be delivered');
  const job = body.jobs.find(j => j.id === jobId);
  assert.ok(job, 'our job must be present');
  assert.equal(job.issueId, 'ISSUE-AGENT-1');
  assert.equal(job.title, 'checkout total is wrong');
});

test('an unauthenticated caller cannot poll or post results', async () => {
  const poll = await fetch(`${BASE}/api/agent/poll`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}'
  });
  assert.equal(poll.status, 401);
  const result = await fetch(`${BASE}/api/agent/result`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ jobId: 'x' })
  });
  assert.equal(result.status, 401);
});

test('an agent cannot post a result for another agent\'s job', async () => {
  const jobId = `AJB-FOREIGN-${Date.now()}`;
  db.prepare(`INSERT INTO agent_jobs (id,agent_id,org_id,issue_id,application_id,root,title,description,status,created_at)
              VALUES (?,?,?,?,?,NULL,?,?,'QUEUED',?)`)
    .run(jobId, 'AGT-SOMEONE-ELSE', ORG, 'ISSUE-X', APP, 't', 'd', now);
  const res = await agentPost('/api/agent/result', { jobId, findings: [] });
  assert.equal(res.status, 404, 'a job owned by another agent must not be writable');
});

test('agent reports file references only: issue waits for source instead of pretending', async () => {
  const issueId = `ISSUE-AGENT-REF-${Date.now()}`;
  const jobId = `AJB-REF-${Date.now()}`;
  db.prepare(`INSERT INTO issues (id,application_id,title,description,page_url,status,root_cause,risk_level,risk_score,reported_at,org_id,occurrence_count,first_seen_at,last_seen_at)
              VALUES (?,?,?,?,'/x','AGENT_ANALYSIS_QUEUED','','',0,?,?,1,?,?)`)
    .run(issueId, APP, 'checkout total wrong', 'discount error', now, ORG, now, now);
  db.prepare(`INSERT INTO pipelines (id,issue_id,application_id,status,current_step,logs,started_at,completed_at,org_id)
              VALUES (?,?,?, 'AWAITING_AGENT','DETECTION','[]',?,NULL,?)`)
    .run(`PIPE-${Date.now()}`, issueId, APP, now, ORG);
  db.prepare(`INSERT INTO agent_jobs (id,agent_id,org_id,issue_id,application_id,root,title,description,status,created_at)
              VALUES (?,?,?,?,?,NULL,?,?,'QUEUED',?)`)
    .run(jobId, agentId, ORG, issueId, APP, 'checkout total wrong', 'discount error', now);

  const res = await agentPost('/api/agent/result', {
    jobId, issueId, scannedFiles: 42, root: '/srv/app',
    findings: [{ file: 'src/checkout.js', score: 9, size: 1200 }]   // no content
  });
  assert.equal(res.status, 200);

  const row = db.prepare('SELECT status FROM issues WHERE id = ?').get(issueId);
  assert.equal(row.status, 'AGENT_SOURCE_REQUIRED',
    'without content the platform must not claim to have analysed the code');
});

test('agent-supplied source is analysed with the real detectors', async () => {
  const issueId = `ISSUE-AGENT-OK-${Date.now()}`;
  const jobId = `AJB-OK-${Date.now()}`;
  db.prepare(`INSERT INTO issues (id,application_id,title,description,page_url,status,root_cause,risk_level,risk_score,reported_at,org_id,occurrence_count,first_seen_at,last_seen_at)
              VALUES (?,?,?,?,'/x','AGENT_ANALYSIS_QUEUED','','',0,?,?,1,?,?)`)
    .run(issueId, APP, 'checkout discount calculation error', 'discount is wrong', now, ORG, now, now);
  db.prepare(`INSERT INTO pipelines (id,issue_id,application_id,status,current_step,logs,started_at,completed_at,org_id)
              VALUES (?,?,?, 'AWAITING_AGENT','DETECTION','[]',?,NULL,?)`)
    .run(`PIPE-${Date.now()}`, issueId, APP, now, ORG);
  db.prepare(`INSERT INTO agent_jobs (id,agent_id,org_id,issue_id,application_id,root,title,description,status,created_at)
              VALUES (?,?,?,?,?,NULL,?,?,'QUEUED',?)`)
    .run(jobId, agentId, ORG, issueId, APP, 'checkout discount error', 'discount wrong', now);

  // A genuine division-by-zero defect, supplied by the customer's agent.
  const code = 'export function price(subtotal, percent) {\n  return (subtotal * percent) / (100 - (percent == 100 ? 100 : 0));\n}\n';

  const res = await agentPost('/api/agent/result', {
    jobId, issueId, scannedFiles: 42, root: '/srv/app',
    findings: [{ file: 'src/checkout.js', score: 9, content: code }]
  });
  assert.equal(res.status, 200);

  const row = db.prepare('SELECT status, root_cause, risk_level, risk_score FROM issues WHERE id = ?').get(issueId);
  assert.equal(row.status, 'AWAITING_AGENT_PATCH', 'a confirmed defect should proceed to patching on the customer side');
  assert.match(row.root_cause, /[Dd]enominator|zero/, 'root cause must come from the real detector');
  assert.ok(row.risk_score > 0, 'an explainable risk score must be recorded');
  assert.ok(['HIGH', 'MEDIUM', 'LOW'].includes(row.risk_level));
});

test('a clean file supplied by the agent yields no defect, not a false positive', async () => {
  const issueId = `ISSUE-AGENT-CLEAN-${Date.now()}`;
  const jobId = `AJB-CLEAN-${Date.now()}`;
  db.prepare(`INSERT INTO issues (id,application_id,title,description,page_url,status,root_cause,risk_level,risk_score,reported_at,org_id,occurrence_count,first_seen_at,last_seen_at)
              VALUES (?,?,?,?,'/x','AGENT_ANALYSIS_QUEUED','','',0,?,?,1,?,?)`)
    .run(issueId, APP, 'something looks odd', 'unsure', now, ORG, now, now);
  db.prepare(`INSERT INTO pipelines (id,issue_id,application_id,status,current_step,logs,started_at,completed_at,org_id)
              VALUES (?,?,?, 'AWAITING_AGENT','DETECTION','[]',?,NULL,?)`)
    .run(`PIPE-${Date.now()}`, issueId, APP, now, ORG);
  db.prepare(`INSERT INTO agent_jobs (id,agent_id,org_id,issue_id,application_id,root,title,description,status,created_at)
              VALUES (?,?,?,?,?,NULL,?,?,'QUEUED',?)`)
    .run(jobId, agentId, ORG, issueId, APP, 't', 'd', now);

  await agentPost('/api/agent/result', {
    jobId, issueId, scannedFiles: 10,
    findings: [{ file: 'src/clean.js', score: 2, content: 'export function sum(xs){return xs.reduce((a,b)=>a+b,0);}\n' }]
  });
  const row = db.prepare('SELECT status FROM issues WHERE id = ?').get(issueId);
  assert.equal(row.status, 'INVALID_REPORT', 'clean code must not produce a defect');
});