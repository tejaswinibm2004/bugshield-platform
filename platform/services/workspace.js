import fs from 'fs';
import path from 'path';
import { execFileSync } from 'child_process';
import { fileURLToPath } from 'url';
import { store } from './store.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT_DIR = path.join(__dirname, '../../');
// Cloned repositories must live on the same persistent volume as the database.
const DATA_DIR = process.env.BUGSHIELD_DATA_DIR
  ? path.resolve(process.env.BUGSHIELD_DATA_DIR)
  : path.join(ROOT_DIR, 'data');
const WORKSPACES_DIR = path.join(DATA_DIR, 'workspaces');
const SOURCES_FILE = path.join(DATA_DIR, 'sources.json');

const IGNORE_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'out', 'coverage', '.next', '.cache', 'vendor', '__pycache__', '.venv', 'venv']);
const SCAN_EXT = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.html', '.css', '.php', '.py', '.rb', '.go', '.java']);

/**
 * Directories that are not shipped product code. Static analysis must not target
 * test fixtures, benchmark generators or build tooling: such files often embed
 * sample source as string literals, which produces findings that do not correspond
 * to any running code path.
 */
export const NON_PRODUCT_DIRS = new Set([
  'test', 'tests', '__tests__', 'spec', 'specs', '__mocks__', 'mocks', 'fixtures',
  'benchmark', 'benchmarks', 'bench', 'e2e', 'cypress', 'playwright', '__snapshots__',
  'scripts', 'tools', 'examples', 'example', 'samples', 'docs', 'doc', '.github'
]);

/** True when a relative path should be excluded from defect analysis. */
export function isNonProductPath(relPath) {
  return String(relPath)
    .split(/[\\/]/)
    .some(seg => NON_PRODUCT_DIRS.has(seg.toLowerCase()) || /\.(test|spec)\.[cm]?[jt]sx?$/.test(seg));
}

function ensureDirs() {
  for (const d of [DATA_DIR, WORKSPACES_DIR]) {
    if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
  }
}

// Per-app source config, kept outside SQLite so the DB schema stays untouched.
export function readSources() {
  ensureDirs();
  if (!fs.existsSync(SOURCES_FILE)) return {};
  try { return JSON.parse(fs.readFileSync(SOURCES_FILE, 'utf-8')); } catch { return {}; }
}
export function writeSource(appId, entry) {
  ensureDirs();
  const all = readSources();
  all[appId] = { ...(all[appId] || {}), ...entry };
  fs.writeFileSync(SOURCES_FILE, JSON.stringify(all, null, 2));
  return all[appId];
}
export function clearSource(appId) {
  const all = readSources();
  delete all[appId];
  fs.writeFileSync(SOURCES_FILE, JSON.stringify(all, null, 2));
}

function localOriginUrl() {
  try {
    return execFileSync('git', ['-C', ROOT_DIR, 'remote', 'get-url', 'origin'], { encoding: 'utf-8', timeout: 8000 }).trim();
  } catch { return null; }
}
function sameRepo(a, b) {
  if (!a || !b) return false;
  const norm = s => s.trim().replace(/\.git$/, '').replace(/^git@github\.com:/, 'https://github.com/').toLowerCase();
  return norm(a) === norm(b);
}
function isLocalPath(p) {
  return !!p && !/^https?:\/\//i.test(p) && !/^git@/i.test(p);
}
export function isGitUrl(u) {
  return !!u && (/^https?:\/\/.*\.git$/i.test(u) || /^git@/i.test(u) || /^https?:\/\//i.test(u));
}

// Clone (once) the customer's repository into a private per-app workspace.
export function cloneRepo(appId, repoUrl) {
  ensureDirs();
  const dest = path.join(WORKSPACES_DIR, appId);
  const stampFile = path.join(dest, '.bugshield-cloned.json');
  if (fs.existsSync(stampFile)) return { ok: true, path: dest, cached: true };

  fs.rmSync(dest, { recursive: true, force: true });
  try {
    execFileSync('git', ['clone', '--depth', '1', repoUrl, dest], { stdio: 'pipe', timeout: 180000 });
    fs.writeFileSync(stampFile, JSON.stringify({ repoUrl, clonedAt: new Date().toISOString() }));
    return { ok: true, path: dest, cached: false };
  } catch (err) {
    fs.rmSync(dest, { recursive: true, force: true });
    return { ok: false, error: (err.stderr?.toString() || err.message || 'clone failed').split('\n').filter(Boolean).slice(-1)[0] };
  }
}

/**
 * Resolve the real source-code root for a registered application.
 * Order: explicit local path -> cloned workspace -> registered Git repo (clone on demand)
 *       -> the platform's own checkout when the app points at this same repository.
 */
export function resolveSourceRoot(app) {
  if (!app) return { root: null, via: null, error: 'Application not found' };
  const cfg = readSources()[app.id] || {};

  if (cfg.localPath && fs.existsSync(cfg.localPath)) {
    return { root: path.resolve(cfg.localPath), via: 'local-folder', detail: cfg.localPath };
  }
  if (cfg.workspace && fs.existsSync(cfg.workspace)) {
    return { root: path.resolve(cfg.workspace), via: 'git-clone', detail: cfg.repoUrl || cfg.workspace };
  }
  if (app.repoUrl && isGitUrl(app.repoUrl)) {
    const origin = localOriginUrl();
    if (sameRepo(app.repoUrl, origin)) {
      return { root: ROOT_DIR, via: 'this-repository', detail: app.repoUrl };
    }
    const res = cloneRepo(app.id, app.repoUrl);
    if (res.ok) {
      writeSource(app.id, { workspace: res.path, repoUrl: app.repoUrl });
      return { root: res.path, via: 'git-clone', detail: app.repoUrl };
    }
    return { root: null, via: null, error: `Could not clone ${app.repoUrl}: ${res.error}` };
  }
  if (isLocalPath(app.repoUrl) && fs.existsSync(app.repoUrl)) {
    return { root: path.resolve(app.repoUrl), via: 'local-folder', detail: app.repoUrl };
  }
  return { root: null, via: null, error: 'No source code registered. Provide a local folder path or a Git repository URL when connecting the website.' };
}

/** Connect / re-connect an application to its source code. */
export function connectSource(appId, { localPath, repoUrl } = {}) {
  const app = store.getApplication(appId);
  if (!app) return { ok: false, error: 'Application not found' };

  if (localPath && isLocalPath(localPath)) {
    if (!fs.existsSync(localPath) || !fs.statSync(localPath).isDirectory()) {
      return { ok: false, error: `Local path not found: ${localPath}` };
    }
    writeSource(appId, { localPath: path.resolve(localPath) });
    return { ok: true, ...resolveSourceRoot(app) };
  }
  if (repoUrl && isGitUrl(repoUrl)) {
    const res = cloneRepo(appId, repoUrl);
    if (!res.ok) return { ok: false, error: `Clone failed: ${res.error}` };
    writeSource(appId, { workspace: res.path, repoUrl });
    return { ok: true, ...resolveSourceRoot(app) };
  }
  if (repoUrl && isLocalPath(repoUrl)) {
    if (!fs.existsSync(repoUrl)) return { ok: false, error: `Path not found: ${repoUrl}` };
    writeSource(appId, { localPath: path.resolve(repoUrl) });
    return { ok: true, ...resolveSourceRoot(app) };
  }
  const resolved = resolveSourceRoot(app);
  return resolved.root
    ? { ok: true, ...resolved }
    : { ok: false, error: resolved.error || 'Provide localPath or repoUrl' };
}

/** Recursively index analysable source files under a root. */
export function indexSourceFiles(root, { maxFiles = 4000, maxBytes = 400000, includeNonProduct = false } = {}) {
  const files = [];
  if (!root || !fs.existsSync(root)) return files;
  const walk = (dir) => {
    if (files.length >= maxFiles) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (files.length >= maxFiles) return;
      if (e.name.startsWith('.') && e.name !== '.env.example') continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (IGNORE_DIRS.has(e.name)) continue;
        walk(full);
      } else if (SCAN_EXT.has(path.extname(e.name).toLowerCase())) {
        let size = 0;
        try { size = fs.statSync(full).size; } catch { continue; }
        if (size > maxBytes * 4) continue;
        const rel = path.relative(root, full).replace(/\\/g, '/');
        if (!includeNonProduct && isNonProductPath(rel)) continue;
        files.push({ abs: full, rel, size });
      }
    }
  };
  walk(root);
  return files;
}