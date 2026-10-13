#!/usr/bin/env node
/**
 * BugShield self-hosted source agent.
 *
 * For customers whose source code must not leave their infrastructure. The agent
 * runs on the customer's machine, opens NO inbound port, and only ever makes
 * outbound HTTPS requests to the platform to poll for jobs and post results.
 *
 * Security properties:
 *  - Reads only from directories the customer explicitly allow-lists.
 *  - The platform never receives raw source by default; only file references,
 *    analysis findings and (optionally) explicit file content the customer opts
 *    into with --send-source.
 *  - Authenticated with a per-agent secret, sent as a bearer token.
 *  - Read-only: the agent never writes to the customer's filesystem.
 *
 * Usage:
 *   node agent/agent.js --platform https://bugs.example.com \
 *     --secret AGENT_SECRET --dir C:\projects\service-a --dir /srv/service-b
 */
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------- arguments
function parseArgs(argv) {
  const out = { dirs: [], pollMs: 15000 };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--platform') out.platform = argv[++i];
    else if (a === '--secret') out.secret = argv[++i];
    else if (a === '--dir') out.dirs.push(path.resolve(argv[++i]));
    else if (a === '--poll') out.pollMs = Number(argv[++i]) || out.pollMs;
    else if (a === '--once') out.once = true;
    else if (a === '--send-source') out.sendSource = true;
  }
  return out;
}

const args = parseArgs(process.argv);

if (!args.platform || !args.secret || !args.dirs.length) {
  console.error('Usage: node agent/agent.js --platform <url> --secret <agentSecret> --dir <path> [--dir <path>...] [--poll <ms>] [--once] [--send-source]');
  process.exit(2);
}

const ALLOWED_EXT = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.py', '.go', '.java', '.php', '.rb']);
const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', 'coverage', 'vendor', '__pycache__', '.venv']);
const MAX_FILE_BYTES = 400_000;
const MAX_FILES_PER_JOB = 500;

// ------------------------------------------------------------------ helpers
function withinAllowedDirs(target) {
  const resolved = path.resolve(target);
  return args.dirs.some(dir => {
    const rel = path.relative(dir, resolved);
    return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
  });
}

function listFiles(root) {
  const files = [];
  const walk = (dir) => {
    if (files.length >= MAX_FILES_PER_JOB) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (files.length >= MAX_FILES_PER_JOB) return;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (IGNORE_DIRS.has(e.name) || e.name.startsWith('.')) continue;
        walk(full);
      } else if (ALLOWED_EXT.has(path.extname(e.name).toLowerCase())) {
        let size = 0;
        try { size = fs.statSync(full).size; } catch { continue; }
        if (size > MAX_FILE_BYTES) continue;
        files.push({ abs: full, rel: path.relative(root, full).replace(/\\/g, '/'), size });
      }
    }
  };
  walk(root);
  return files;
}

/** Cheap local pre-filter: which files mention any of the report keywords. */
function rankFiles(root, keywords) {
  const files = listFiles(root);
  if (!keywords.length) return [];
  const scored = [];
  for (const f of files) {
    let content;
    try { content = fs.readFileSync(f.abs, 'utf-8'); } catch { continue; }
    const lower = content.toLowerCase();
    let score = 0;
    for (const k of keywords) {
      if (f.rel.toLowerCase().includes(k)) score += 4;
      if (lower.includes(k)) score += 1;
    }
    if (score > 0) scored.push({ ...f, score, content });
  }
  return scored.sort((a, b) => b.score - a.score).slice(0, 10);
}

const STOPWORDS = new Set(['the','and','for','with','that','this','from','have','has','was','were','are','but','not','you','your','when','what','where','which','while','into','out','get','set','use','using','used','can','could','would','should','there','their','them','then','than','they','been','being','does','did','doing','also','just','like','about','after','before','because','some','more','most','only','other','such','own','same','too','very','will','may','one','two','bug','issue','error','problem','page','user','users','please','help','report','failing','fails','fail','failed','broken','working','work','works','happens','happening','clicked','click','tried','trying']);

function keywords(text) {
  const words = String(text || '').toLowerCase().match(/[a-z][a-z0-9_]{2,}/g) || [];
  return [...new Set(words.filter(w => !STOPWORDS.has(w)))];
}

// ------------------------------------------------------------------- client
async function call(pathname, payload) {
  const res = await fetch(`${args.platform.replace(/\/$/, '')}${pathname}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${args.secret}` },
    body: JSON.stringify(payload || {})
  });
  const text = await res.text();
  let body;
  try { body = JSON.parse(text); } catch { body = { error: text.slice(0, 200) }; }
  return { status: res.status, body };
}

function fingerprint() {
  return crypto.createHash('sha256')
    .update(args.dirs.join('|'))
    .digest('hex').slice(0, 16);
}

async function pollOnce() {
  const res = await call('/api/agent/poll', { fingerprint: fingerprint(), dirs: args.dirs.map(d => path.basename(d)) });
  if (res.status !== 200 || !res.body?.success) {
    console.error(`[agent] poll failed (${res.status}): ${res.body?.error || 'unknown error'}`);
    return;
  }
  const jobs = res.body.jobs || [];
  if (!jobs.length) return;

  for (const job of jobs) {
    console.log(`[agent] job ${job.id} for issue ${job.issueId}`);
    const root = args.dirs.find(d => d === job.root) || args.dirs[0];
    if (!withinAllowedDirs(root)) {
      await call('/api/agent/result', { jobId: job.id, error: 'Requested root is outside the configured directories.' });
      continue;
    }

    const terms = keywords(`${job.title || ''} ${job.description || ''}`);
    const ranked = rankFiles(root, terms);
    const findings = ranked.map(f => ({
      file: f.rel,
      size: f.size,
      score: f.score,
      // Source content is sent only when the operator explicitly opted in.
      ...(args.sendSource ? { content: f.content } : {})
    }));

    await call('/api/agent/result', {
      jobId: job.id,
      issueId: job.issueId,
      root,
      scannedFiles: listFiles(root).length,
      findings
    });
    console.log(`[agent] reported ${findings.length} candidate file(s) for job ${job.id}`);
  }
}

async function main() {
  console.log(`[agent] BugShield source agent starting`);
  console.log(`[agent] platform : ${args.platform}`);
  console.log(`[agent] roots    : ${args.dirs.join(', ')}`);
  console.log(`[agent] source   : ${args.sendSource ? 'content will be transmitted' : 'references only (no source transmitted)'}`);

  if (args.once) { await pollOnce(); return; }

  // Long-lived outbound polling loop. No listening socket is ever opened.
  for (;;) {
    try { await pollOnce(); }
    catch (e) { console.error(`[agent] error: ${e.message}`); }
    await new Promise(r => setTimeout(r, args.pollMs));
  }
}

main().catch(e => { console.error('[agent] fatal:', e); process.exit(1); });