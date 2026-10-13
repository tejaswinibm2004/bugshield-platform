import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { DatabaseSync } from 'node:sqlite';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_DATA_DIR = path.join(__dirname, '../../data');

// The data directory must be configurable so a persistent disk can be mounted
// (Render) or a writable location provided. On an ephemeral filesystem every
// deploy would silently destroy users, sessions, history and the audit trail.
const DATA_DIR = process.env.BUGSHIELD_DATA_DIR
  ? path.resolve(process.env.BUGSHIELD_DATA_DIR)
  : DEFAULT_DATA_DIR;
const LEGACY_JSON_PATH = path.join(DATA_DIR, 'db.json');

let DB_PATH = process.env.BUGSHIELD_DB_PATH
  ? path.resolve(process.env.BUGSHIELD_DB_PATH)
  : path.join(DATA_DIR, 'bugshield.db');

// Support Vercel Serverless environment (/tmp directory)
if (process.env.VERCEL) {
  DB_PATH = path.join('/tmp', 'bugshield.db');
} else {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    // Verify the location is actually writable rather than discovering it later.
    fs.accessSync(DATA_DIR, fs.constants.W_OK);
  } catch (e) {
    console.error(`[database] Data directory ${DATA_DIR} is not writable: ${e.message}`);
    if (process.env.NODE_ENV === 'production') {
      console.error('[database] Set BUGSHIELD_DATA_DIR to a persistent volume before running in production.');
    }
    DB_PATH = path.join(os.tmpdir(), 'bugshield.db');
  }
}

export const db = new DatabaseSync(DB_PATH);

// Enable WAL mode or memory journal mode for serverless
try {
  db.exec('PRAGMA journal_mode = WAL;');
} catch (e) {
  // Ignore journal mode errors in restricted environments
}

// Initialize Tables
export function initSchema() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS customers (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      api_key TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS applications (
      id TEXT PRIMARY KEY,
      customer_id TEXT NOT NULL,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      port INTEGER NOT NULL,
      repo_url TEXT,
      branch TEXT,
      status TEXT NOT NULL,
      sdk_key TEXT UNIQUE NOT NULL,
      permissions TEXT,
      jenkins_status TEXT,
      docker_status TEXT,
      canary_threshold TEXT
    );

    CREATE TABLE IF NOT EXISTS issues (
      id TEXT PRIMARY KEY,
      application_id TEXT NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      page_url TEXT,
      steps_to_reproduce TEXT,
      stack_trace TEXT,
      logs TEXT,
      browser_info TEXT,
      status TEXT NOT NULL,
      root_cause TEXT,
      risk_level TEXT,
      risk_score INTEGER,
      reported_at TEXT NOT NULL,
      resolved_at TEXT
    );

    CREATE TABLE IF NOT EXISTS patches (
      id TEXT PRIMARY KEY,
      issue_id TEXT NOT NULL,
      application_id TEXT NOT NULL,
      diff TEXT,
      description TEXT,
      status TEXT NOT NULL,
      patch_result TEXT,
      created_at TEXT NOT NULL,
      approved_at TEXT
    );

    CREATE TABLE IF NOT EXISTS pipelines (
      id TEXT PRIMARY KEY,
      issue_id TEXT NOT NULL,
      application_id TEXT NOT NULL,
      status TEXT NOT NULL,
      current_step TEXT NOT NULL,
      logs TEXT,
      started_at TEXT NOT NULL,
      completed_at TEXT
    );

    CREATE TABLE IF NOT EXISTS validation_runs (
      id TEXT PRIMARY KEY,
      issue_id TEXT NOT NULL,
      application_id TEXT NOT NULL,
      patch_applied INTEGER,
      syntax_passed INTEGER,
      tests_ran INTEGER,
      tests_passed INTEGER,
      test_counts TEXT,
      security_passed INTEGER,
      security_findings TEXT,
      dependency_audit TEXT,
      behaviour_verified INTEGER,
      validation_passed INTEGER,
      evidence TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS deployments (
      id TEXT PRIMARY KEY,
      issue_id TEXT NOT NULL,
      application_id TEXT NOT NULL,
      strategy TEXT,
      zero_downtime INTEGER,
      status TEXT NOT NULL,
      health TEXT,
      rolled_back INTEGER,
      backup_file TEXT,
      result TEXT,
      created_at TEXT NOT NULL
    );
  `);

  autoMigrateLegacyData();
}

function autoMigrateLegacyData() {
  // Check if customers table is empty
  const count = db.prepare('SELECT COUNT(*) as cnt FROM customers').get().cnt;
  if (count > 0) return; // Schema already populated

  console.log('[SQLite DB] Initializing tables with seed/legacy data...');

  let initialData = null;
  if (fs.existsSync(LEGACY_JSON_PATH)) {
    try {
      const content = fs.readFileSync(LEGACY_JSON_PATH, 'utf-8');
      initialData = JSON.parse(content);
    } catch (err) {
      console.error('[SQLite DB] Failed reading db.json for seed data:', err);
    }
  }

  if (!initialData || !initialData.applications || initialData.applications.length === 0) {
    initialData = {
      customers: [
        {
          id: 'CUST-001',
          name: 'Acme Software Labs',
          email: 'owner@acme.com',
          apiKey: 'sk_live_acme_89f123490abc',
          createdAt: new Date().toISOString()
        }
      ],
      applications: [
        {
          id: 'APP-SHOP-01',
          customerId: 'CUST-001',
          name: 'QuickShop E-Commerce Store',
          type: 'Node.js Web App',
          port: 3001,
          repoUrl: 'https://github.com/acme/quickshop-app',
          branch: 'main',
          status: 'Connected',
          sdkKey: 'sdk_app_shop_01_live',
          permissions: { issueAccess: true, repoAccess: true, deploymentAccess: true },
          jenkinsStatus: 'Connected & Verified',
          dockerStatus: 'Containerized (Active)',
          canaryThreshold: '99.5%'
        },
        {
          id: 'APP-FOOD-02',
          customerId: 'CUST-001',
          name: 'BiteDash Express Delivery',
          type: 'Node.js Web App',
          port: 3002,
          repoUrl: 'https://github.com/acme/bitedash-app',
          branch: 'main',
          status: 'Connected',
          sdkKey: 'sdk_app_food_02_live',
          permissions: { issueAccess: true, repoAccess: true, deploymentAccess: true },
          jenkinsStatus: 'Connected & Verified',
          dockerStatus: 'Containerized (Active)',
          canaryThreshold: '99.0%'
        }
      ],
      issues: [],
      patches: [],
      pipelines: []
    };
  }

  // Insert customers
  const insertCustomer = db.prepare('INSERT INTO customers (id, name, email, api_key, created_at) VALUES (?, ?, ?, ?, ?)');
  for (const c of initialData.customers || []) {
    insertCustomer.run(c.id, c.name, c.email, c.apiKey || c.api_key, c.createdAt || c.created_at || new Date().toISOString());
  }

  // Insert applications
  const insertApp = db.prepare(`
    INSERT INTO applications (id, customer_id, name, type, port, repo_url, branch, status, sdk_key, permissions, jenkins_status, docker_status, canary_threshold)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  for (const app of initialData.applications || []) {
    insertApp.run(
      app.id,
      app.customerId || app.customer_id,
      app.name,
      app.type,
      app.port,
      app.repoUrl || app.repo_url,
      app.branch,
      app.status,
      app.sdkKey || app.sdk_key,
      JSON.stringify(app.permissions || {}),
      app.jenkinsStatus || app.jenkins_status,
      app.dockerStatus || app.docker_status,
      app.canaryThreshold || app.canary_threshold
    );
  }

  // Note: issues, patches, and pipelines start empty (0 entries) until reported by end-users.
  console.log('[SQLite DB] Migration completed successfully with clean database schema.');
}

// Run schema setup on import
initSchema();

// Additive multi-tenancy / identity / audit migrations.
import { migrateTenancy } from './migrations.js';
migrateTenancy();
