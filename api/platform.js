/**
 * Serverless entry point (Vercel / Render-style).
 *
 * Historically this file duplicated every route from server.js, which allowed the
 * two entry points to drift and, more seriously, allowed an unauthenticated copy
 * of a route to shadow its secured counterpart. It now builds its own app but
 * mounts the SAME secured API router used by server.js, so there is exactly one
 * definition of each route and one set of authorisation rules.
 */
import 'dotenv/config';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

import { createApiRouter } from '../platform/http/apiRouter.js';
import { store } from '../platform/services/store.js';
import { MultiAgentOrchestrator } from '../platform/agents/orchestrator.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

// No websocket broadcaster in a serverless runtime; agents still persist to the DB.
const orchestrator = new MultiAgentOrchestrator(null);

// One router, both entry points.
app.use(createApiRouter({ orchestrator, baseDir: path.join(__dirname, '..') }));

// Static SDK + dashboard
app.get('/sdk/bug-shield-sdk.js', (req, res) => {
  res.sendFile(path.join(__dirname, '../sdk/bug-shield-sdk.js'));
});
app.use(express.static(path.join(__dirname, '../platform/public')));

// Dashboard shell for any non-API path (SPA routes).
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../platform/public/index.html'));
});

export default app;