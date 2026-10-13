/**
 * Primary entry point (long-running Node server).
 *
 * Responsibilities kept here: HTTP server, WebSocket fan-out, static assets.
 * Every /api route is defined once in platform/http/apiRouter.js and mounted
 * below, so this file and the serverless entry point cannot drift.
 */
import 'dotenv/config';
import express from 'express';
import http from 'http';
import path from 'path';
import cors from 'cors';
import fs from 'fs';
import { WebSocketServer } from 'ws';
import { fileURLToPath } from 'url';

import { createApiRouter } from './platform/http/apiRouter.js';
import { MultiAgentOrchestrator } from './platform/agents/orchestrator.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const platformApp = express();
// Render terminates TLS at its proxy and forwards plain HTTP + X-Forwarded-*.
// Without this, req.protocol is 'http' behind HTTPS (wrong activation links)
// and Secure cookies misbehave.
platformApp.set('trust proxy', 1);
platformApp.disable('x-powered-by');
const platformServer = http.createServer(platformApp);
const wss = new WebSocketServer({ server: platformServer });

const broadcast = (data) => {
  const json = JSON.stringify(data);
  wss.clients.forEach(client => { if (client.readyState === 1) client.send(json); });
};

const orchestrator = new MultiAgentOrchestrator(broadcast);

// Browsers post to the platform from the customer's own site (the SDK) and from
// the dashboard. Session APIs must never be reachable from an arbitrary origin
// with credentials, so CORS reflects only an explicitly allowed list.
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

const strictCors = cors({
  // Same-origin always; plus any extra origins the operator lists.
  origin(origin, cb) {
    if (!origin) return cb(null, true);                       // same-origin / non-browser
    if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    // In production, refuse anything not explicitly allowed.
    if (process.env.NODE_ENV === 'production') return cb(new Error('Origin not allowed'));
    return cb(null, true);                                     // development convenience
  },
  credentials: true
});
// Ingestion stays open: customer sites are unknown at deploy time and each key
// enforces its own origin allow-list inside the router.
const openIngestCors = cors({ origin: true });
platformApp.use((req, res, next) => {
  if (req.path === '/api/v1/issues' && (req.method === 'POST' || req.method === 'OPTIONS')) {
    return openIngestCors(req, res, next);
  }
  return strictCors(req, res, (err) => {
    if (err) return res.status(403).json({ success: false, error: 'Origin not allowed' });
    next();
  });
});
platformApp.use(createApiRouter({ orchestrator, baseDir: __dirname }));

platformApp.get('/sdk/bug-shield-sdk.js', (req, res) => {
  res.sendFile(path.join(__dirname, 'sdk/bug-shield-sdk.js'));
});

platformApp.use(express.static(path.join(__dirname, 'platform/public')));
platformApp.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'platform/public/login.html'));
});

// Demo storefronts shipped with the repository, served so a Viewer role has
// something real to open. Not required by the platform.
platformApp.use('/demo', express.static(path.join(__dirname, 'demo-apps')));

const PORT = Number(process.env.PORT) || 3000;
const HOST = process.env.HOST || '0.0.0.0'; // Render requires 0.0.0.0, not localhost.

// Fail fast with a Render-actionable message when the persistent disk is missing.
const DATA_DIR = process.env.BUGSHIELD_DATA_DIR || 'data';
try {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.accessSync(DATA_DIR, fs.constants.W_OK);
} catch (e) {
  console.error(`[startup] Data directory ${DATA_DIR} is not writable: ${e.message}`);
  if (process.env.NODE_ENV === 'production') {
    console.error('[startup] On Render, mount a disk at /var/data and set BUGSHIELD_DATA_DIR=/var/data.');
  }
}

platformServer.listen(PORT, HOST, () => {
  console.log(`\n================================================================`);
  console.log(` BUGSHIELD PLATFORM RUNNING AT: http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
  console.log(`   Dashboard requires sign-in: http://localhost:${PORT}/login`);
  console.log(`   Website SDK:  http://localhost:${PORT}/sdk/bug-shield-sdk.js`);
  console.log(`   Health check: GET /api/health`);
  console.log(`================================================================\n`);
});

// Render sends SIGTERM on redeploy/scale. Close cleanly so SQLite WAL checkpoints.
function shutdown(signal) {
  console.log(`[startup] Received ${signal}, closing server...`);
  platformServer.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 10000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));