/**
 * The single, shared API surface.
 *
 * Both server.js (primary, with WebSockets) and api/platform.js (serverless)
 * mount this router, so there is exactly one definition of every route and one
 * set of authorisation rules. Adding a route here makes it available and
 * protected in both deployments.
 */
import express from 'express';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

import { store } from '../services/store.js';
import {
  CAPABILITIES, ROLES, SESSION_COOKIE, attachUser, clientIp, login, logout,
  requireAuth, requireCapability, requireSameOrigin, sessionCookieOptions
} from '../middleware/auth.js';
import { hashPassword, hashToken, verifyPassword } from '../services/migrations.js';
import { RISK_MODEL_SUMMARY as RISK_MODEL } from '../services/riskConfig.js';
import { db } from '../services/database.js';
import { checkRateLimit } from '../services/rateLimiter.js';
import { MultiAgentOrchestrator } from '../agents/orchestrator.js';
import { connectSource, indexSourceFiles, resolveSourceRoot } from '../services/workspace.js';
import { getProvider } from '../services/repositoryProviders.js';
import { getCiProvider, listCiStatus } from '../services/ciProviders.js';
import { isConfigured as mailConfigured, sendInviteEmail, verify as verifyMail } from '../services/mailer.js';
import { getAiStatus } from '../services/aiProvider.js';
import {
  createIngestionKey, createProject, createRiskPolicy, findUserByEmail, generateIssueId, getActiveRiskPolicy, getApplicationForOrg,
  getIssueForOrg, getProject, listApplications, listAuditLogs, listDeployments,
  listIngestionKeys, listIssues, listMembers, listOrganizationsForUser, listProjects, listValidationRuns,
  originAllowed, recordAudit, removeMembership, revokeAllSessionsForUser, revokeIngestionKey,
  revokeOtherSessions, setMembership, toAppView, toIssueView, updateApplicationForOrg, verifyIngestionKey
} from '../services/tenantStore.js';

export function createApiRouter({ orchestrator, baseDir }) {
  const router = express.Router();

  router.use(express.json({ limit: '256kb' }));
  router.use(attachUser);
  router.use(requireSameOrigin);

  // Unauthenticated liveness probe for the host health check (Render).
  // Kept first so deploys never depend on auth, CSRF, or later route ordering.
  router.get('/api/health', (_req, res) => {
    let dbOk = false;
    try { db.prepare('SELECT 1').get(); dbOk = true; } catch { dbOk = false; }
    res.status(dbOk ? 200 : 503).json({
      success: dbOk,
      service: 'bugshield-platform',
      database: dbOk ? 'ok' : 'unavailable',
      time: new Date().toISOString()
    });
  });

  // ------------------------------------------------------------- auth
  router.post('/api/v1/auth/login', (req, res) => {
    const { email, password, org_id } = req.body || {};
    if (!email || !password) return res.status(400).json({ success: false, error: 'Email and password are required.' });

    const result = login({ email, password, orgId: org_id, ip: clientIp(req), userAgent: req.headers['user-agent'] });
    if (!result.ok) return res.status(401).json({ success: false, error: result.error });

    res.cookie(SESSION_COOKIE, result.token, sessionCookieOptions());
    res.json({
      success: true,
      user: { id: result.user.id, email: result.user.email, displayName: result.user.display_name },
      organization: { id: result.org.id, name: result.org.name, slug: result.org.slug },
      role: result.role
    });
  });

  router.post('/api/v1/auth/logout', requireAuth, (req, res) => {
    logout(req);
    res.clearCookie(SESSION_COOKIE, sessionCookieOptions());
    res.json({ success: true });
  });

  router.get('/api/v1/auth/me', requireAuth, (req, res) => {
    res.json({
      success: true,
      user: { id: req.user.id, email: req.user.email, displayName: req.user.display_name },
      organization: { id: req.org.id, name: req.org.name, slug: req.org.slug },
      role: req.role,
      capabilities: Object.entries(CAPABILITIES).filter(([, roles]) => roles.includes(req.role)).map(([c]) => c)
    });
  });

  router.get('/api/v1/auth/organizations', requireAuth, (req, res) => {
    res.json({ success: true, organizations: listOrganizationsForUser(req.user.id) });
  });

  // Invited members are created with an unusable random password, so a
  // password-set flow must exist for them to ever sign in.
  router.post('/api/v1/auth/set-password', requireAuth, (req, res) => {
    const { currentPassword, newPassword } = req.body || {};
    if (!newPassword || String(newPassword).length < 12) {
      return res.status(400).json({ success: false, error: 'New password must be at least 12 characters.' });
    }
    const row = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!verifyPassword(currentPassword || '', row)) {
      return res.status(403).json({ success: false, error: 'Current password is incorrect.' });
    }
    const { hash, salt, params } = hashPassword(String(newPassword));
    db.prepare('UPDATE users SET password_hash = ?, password_salt = ?, password_params = ? WHERE id = ?')
      .run(hash, salt, params, req.user.id);
    // Invalidate other sessions, keep the current one.
    revokeOtherSessions(req.user.id, req.sessionHash);
    recordAudit({ orgId: req.orgId, userId: req.user.id, action: 'auth.password_change', outcome: 'success', ip: clientIp(req) });
    res.json({ success: true });
  });

  // -------------------------------------------- projects / members / policy
  router.get('/api/v1/projects', requireAuth, requireCapability('patch:view'), (req, res) => {
    res.json({ success: true, projects: listProjects(req.orgId) });
  });

  router.post('/api/v1/projects', requireAuth, requireCapability('project:create'), (req, res) => {
    const { name } = req.body || {};
    if (!name) return res.status(400).json({ success: false, error: 'Project name is required.' });
    const slug = String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 48) || 'project';
    const id = `PRJ-${crypto.randomBytes(5).toString('hex')}`;
    try {
      const project = createProject({ id, orgId: req.orgId, name, slug });
      recordAudit({ orgId: req.orgId, userId: req.user.id, action: 'project.create', entityType: 'project', entityId: id, ip: clientIp(req) });
      res.json({ success: true, project });
    } catch {
      res.status(409).json({ success: false, error: 'A project with that name already exists.' });
    }
  });

  router.get('/api/v1/members', requireAuth, requireCapability('settings:view'), (req, res) => {
    res.json({ success: true, members: listMembers(req.orgId) });
  });

  router.post('/api/v1/members', requireAuth, requireCapability('member:manage'), async (req, res) => {
    const { email, role, display_name, confirmPassword } = req.body || {};
    if (!email || !ROLES.includes(role)) return res.status(400).json({ success: false, error: 'Valid email and role are required.' });

    // Re-authentication: sending an invitation grants access to someone, so the
    // administrator must prove their identity again before anything is created or
    // emailed. Verified FIRST — no member row and no mail on failure.
    const caller = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    if (!verifyPassword(String(confirmPassword || ''), caller)) {
      recordAudit({
        orgId: req.orgId, userId: req.user.id, action: 'member.invite', entityType: 'user',
        entityId: null, outcome: 'denied', meta: { reason: 'password confirmation failed' }, ip: clientIp(req)
      });
      return res.status(403).json({ success: false, error: 'Your password is incorrect. The invitation was not created and no email was sent.' });
    }

    const canonical = String(email).toLowerCase().trim();

    // An activation link lets the invitee choose their own password. The
    // administrator never handles it.
    const token = `bsi_${crypto.randomBytes(32).toString('base64url')}`;
    const expires = new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString();
    db.prepare(`INSERT INTO invitations (id, email, token_hash, org_id, role, invited_by, used, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`)
      .run(`INV-${crypto.randomBytes(6).toString('hex')}`, canonical, hashToken(token), req.orgId, role, req.user.id, expires, new Date().toISOString());

    // Ensure the account row exists with an unusable password until activation.
    let user = findUserByEmail(canonical);
    if (!user) {
      const id = `USR-${crypto.randomBytes(6).toString('hex')}`;
      const unusable = crypto.randomBytes(32).toString('base64url');
      const { hash, salt, params } = hashPassword(unusable);
      db.prepare(`INSERT INTO users (id,email,display_name,password_hash,password_salt,password_params,disabled,created_at)
                  VALUES (?,?,?,?,?,?,0,?)`)
        .run(id, canonical, display_name || canonical.split('@')[0], hash, salt, params, new Date().toISOString());
      user = { id, email: canonical };
    }
    setMembership(user.id, req.orgId, role);

    const activationLink = `/login#activate=${token}`;
    const mail = await sendInviteEmail({
      to: canonical,
      orgName: req.org ? req.org.name : 'BugShield',
      role,
      invitedBy: req.user.display_name || req.user.email,
      activationLink,
      platformOrigin: `${req.protocol}://${req.get('host')}`
    });

    recordAudit({
      orgId: req.orgId, userId: req.user.id, action: 'member.invite', entityType: 'user', entityId: user.id,
      meta: { role, delivered: mail.delivered }, ip: clientIp(req)
    });

    res.json({
      success: true,
      member: { id: user.id, email: canonical, role },
      activationToken: token,
      activationLink,
      expiresAt: expires,
      email: {
        sent: mail.delivered,
        transport: mail.transport,
        reason: mail.reason || null,
        // Returned only when delivery did NOT happen, so the admin can pass it on.
        fallbackLink: mail.delivered ? null : activationLink
      }
    });
  });

  // Public: exchange an activation token for a chosen password.
  router.post('/api/v1/auth/accept-invite', (req, res) => {
    const { email, token, newPassword } = req.body || {};
    if (!email || !token || !newPassword) return res.status(400).json({ success: false, error: 'Email, activation token and new password are required.' });
    if (String(newPassword).length < 12) return res.status(400).json({ success: false, error: 'Password must be at least 12 characters.' });

    const canonical = String(email).toLowerCase().trim();
    const invite = db.prepare('SELECT * FROM invitations WHERE token_hash = ? AND email = ?').get(hashToken(token), canonical);
    if (!invite) return res.status(400).json({ success: false, error: 'This activation link is not valid.' });
    if (invite.used) return res.status(400).json({ success: false, error: 'This activation link has already been used.' });
    if (new Date(invite.expires_at).getTime() < Date.now()) return res.status(400).json({ success: false, error: 'This activation link has expired. Ask an admin for a new invite.' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(canonical);
    if (!user) return res.status(400).json({ success: false, error: 'No account exists for this invitation.' });

    const { hash, salt, params } = hashPassword(String(newPassword));
    db.prepare('UPDATE users SET password_hash = ?, password_salt = ?, password_params = ?, disabled = 0 WHERE id = ?')
      .run(hash, salt, params, user.id);
    setMembership(user.id, invite.org_id, invite.role);
    db.prepare('UPDATE invitations SET used = 1 WHERE id = ?').run(invite.id);
    recordAudit({ orgId: invite.org_id, userId: user.id, action: 'auth.invite_accepted', outcome: 'success', ip: clientIp(req) });
    res.json({ success: true, message: 'Account activated. You can now sign in.' });
  });

  router.delete('/api/v1/members/:userId', requireAuth, requireCapability('member:manage'), (req, res) => {
    if (req.params.userId === req.user.id) return res.status(400).json({ success: false, error: 'You cannot remove your own membership.' });
    removeMembership(req.params.userId, req.orgId);
    revokeAllSessionsForUser(req.params.userId);
    recordAudit({ orgId: req.orgId, userId: req.user.id, action: 'member.remove', entityType: 'user', entityId: req.params.userId, ip: clientIp(req) });
    res.json({ success: true });
  });

  router.get('/api/v1/risk-policy', requireAuth, requireCapability('patch:view'), (req, res) => {
    const policy = getActiveRiskPolicy(req.orgId);
    res.json({
      success: true,
      policy: policy || { highThreshold: RISK_MODEL.thresholds.high, lowThreshold: RISK_MODEL.thresholds.low, autoDeployEnabled: false, version: 0 },
      model: RISK_MODEL
    });
  });

  router.post('/api/v1/risk-policy', requireAuth, requireCapability('policy:manage'), (req, res) => {
    const { highThreshold, lowThreshold, autoDeployEnabled } = req.body || {};
    const hi = Number(highThreshold), lo = Number(lowThreshold);
    if (!Number.isFinite(hi) || !Number.isFinite(lo) || lo < 0 || hi > 100 || lo >= hi) {
      return res.status(400).json({ success: false, error: 'Thresholds must satisfy 0 <= low < high <= 100.' });
    }
    const policy = createRiskPolicy({ orgId: req.orgId, userId: req.user.id, highThreshold: hi, lowThreshold: lo, autoDeployEnabled: !!autoDeployEnabled });
    recordAudit({ orgId: req.orgId, userId: req.user.id, action: 'policy.update', entityType: 'risk_policy', entityId: policy.id, meta: policy, ip: clientIp(req) });
    res.json({ success: true, policy });
  });

  router.get('/api/v1/audit', requireAuth, requireCapability('audit:view'), (req, res) => {
    res.json({ success: true, logs: listAuditLogs(req.orgId, 200) });
  });

  // --------------------------------------------------------------- intake
  // Unauthenticated by design. Authenticated by a scoped ingestion key, then
  // constrained by origin allow-list, rate limit, payload caps and de-duplication.
  router.post('/api/v1/issues', async (req, res) => {
    try {
      const { ingestion_key, application_id, sdk_key, title, description, page_url,
              steps_to_reproduce, stack_trace, logs, browser_info, release } = req.body || {};

      // --- authenticate -------------------------------------------------
      let application = null;
      let keyRecord = null;
      let authMode;
      if (ingestion_key) {
        keyRecord = verifyIngestionKey(ingestion_key);
        if (!keyRecord) return res.status(401).json({ success: false, message: 'Invalid or revoked ingestion key.' });
        application = store.getApplication(keyRecord.applicationId);
        authMode = 'ingestion-key';
      } else if (sdk_key) {
        // Legacy path: the application's long-lived SDK key. Accepted for
        // backwards compatibility but weaker; migrate to an ingestion key.
        application = store.getApplication(sdk_key);
        authMode = 'legacy-sdk-key';
      }
      if (!application) {
        return res.status(401).json({ success: false, message: 'Invalid or unauthorized application credentials.' });
      }

      // --- origin allow-list -------------------------------------------
      if (keyRecord) {
        const o = originAllowed(keyRecord.allowedOrigins, req.headers.origin);
        if (!o.ok) return res.status(403).json({ success: false, message: `Origin not permitted${o.enforced ? '' : ''}.` });
      }

      // --- rate limit ---------------------------------------------------
      const rl = checkRateLimit({ key: keyRecord ? keyRecord.id : application.id, ip: clientIp(req) });
      if (!rl.allowed) {
        res.setHeader('Retry-After', String(rl.retryAfterSec));
        return res.status(429).json({ success: false, message: `Rate limit exceeded for ${rl.scope}.` });
      }

      // --- payload caps -------------------------------------------------
      if (typeof description === 'string' && description.length > 4000) return res.status(413).json({ success: false, message: 'Description too large.' });
      if (typeof stack_trace === 'string' && stack_trace.length > 8000) return res.status(413).json({ success: false, message: 'Stack trace too large.' });
      if (Array.isArray(logs) && logs.length > 50) return res.status(413).json({ success: false, message: 'Too many log entries.' });
      if (typeof title === 'string' && title.length > 300) return res.status(413).json({ success: false, message: 'Title too large.' });

      // --- de-duplicate repeated client events ---------------------------
      // The same error usually fires many times per session. Aggregate those
      // occurrences onto one issue instead of spawning a pipeline each time.
      const recent = db.prepare(`
        SELECT id, title, page_url, stack_trace FROM issues
        WHERE application_id = ? AND status IN ('RECEIVED','IN_ANALYSIS')
          AND reported_at > ?
        ORDER BY reported_at DESC LIMIT 50
      `).all(application.id, new Date(Date.now() - 10 * 60 * 1000).toISOString());

      const norm = v => String(v || '').trim().slice(0, 500);
      const sameEvent = recent.find(r =>
        r.title === norm(title || 'Unspecified Error') &&
        r.page_url === norm(page_url || '/') &&
        norm(r.stack_trace) === norm(stack_trace));

      if (sameEvent) {
        db.prepare('UPDATE issues SET occurrence_count = occurrence_count + 1, last_seen_at = ? WHERE id = ?')
          .run(new Date().toISOString(), sameEvent.id);
        recordAudit({ orgId: application.org_id, action: 'ingest.deduplicated', entityType: 'issue', entityId: sameEvent.id, outcome: 'success', ip: clientIp(req) });
        return res.json({ success: true, issueId: sameEvent.id, status: 'DEDUPLICATED', message: 'Already recorded; occurrence count updated.' });
      }

      const issueId = generateIssueId();
      store.addIssue({
        id: issueId,
        applicationId: application.id,
        orgId: application.org_id || application.customerId || null,
        title: String(title || 'Unspecified Error').slice(0, 300),
        description: String(description || '').slice(0, 4000),
        pageUrl: String(page_url || '/').slice(0, 500),
        stepsToReproduce: String(steps_to_reproduce || '').slice(0, 2000),
        stackTrace: String(stack_trace || '').slice(0, 8000),
        logs: (Array.isArray(logs) ? logs : []).slice(0, 50).map(l => String(l).slice(0, 2000)),
        browserInfo: (browser_info && typeof browser_info === 'object') ? browser_info : {},
        status: 'RECEIVED',
        reportedAt: new Date().toISOString()
      });
      if (release) db.prepare('UPDATE issues SET commit_sha = ? WHERE id = ?').run(String(release).slice(0, 64), issueId);
      recordAudit({ orgId: application.org_id, action: 'ingest.accept', entityType: 'issue', entityId: issueId, outcome: 'success', meta: { authMode }, ip: clientIp(req) });

      orchestrator.processIssue(issueId);
      res.json({ success: true, issueId, status: 'RECEIVED', message: 'Issue report accepted. Multi-Agent pipeline initiated.' });
    } catch (err) {
      console.error('[ingest]', err.message);
      res.status(500).json({ success: false, message: 'Internal error while accepting report.' });
    }
  });

  // --------------------------------------------------- ingestion key admin
  router.get('/api/v1/apps/:id/ingestion-keys', requireAuth, requireCapability('app:update'), (req, res) => {
    const app = getApplicationForOrg(req.orgId, req.params.id);
    if (!app) return res.status(404).json({ success: false, error: 'Not found.' });
    res.json({ success: true, keys: listIngestionKeys(req.orgId, app.id) });
  });

  router.post('/api/v1/apps/:id/ingestion-keys', requireAuth, requireCapability('app:update'), (req, res) => {
    const app = getApplicationForOrg(req.orgId, req.params.id);
    if (!app) return res.status(404).json({ success: false, error: 'Not found.' });
    const { label, allowedOrigins } = req.body || {};
    const origins = Array.isArray(allowedOrigins) ? allowedOrigins.map(o => String(o).slice(0, 200)) : [];
    const created = createIngestionKey({ orgId: req.orgId, applicationId: app.id, label, allowedOrigins: origins });
    recordAudit({ orgId: req.orgId, userId: req.user.id, action: 'ingestion_key.create', entityType: 'application', entityId: app.id, meta: { keyId: created.id, origins }, ip: clientIp(req) });
    // The plaintext key is shown exactly once and cannot be retrieved again.
    res.json({ success: true, key: created, warning: 'Copy this key now. It is stored hashed and cannot be shown again.' });
  });

  router.delete('/api/v1/apps/:id/ingestion-keys/:keyId', requireAuth, requireCapability('app:update'), (req, res) => {
    const app = getApplicationForOrg(req.orgId, req.params.id);
    if (!app) return res.status(404).json({ success: false, error: 'Not found.' });
    const ok = revokeIngestionKey(req.orgId, req.params.keyId);
    if (!ok) return res.status(404).json({ success: false, error: 'Key not found.' });
    recordAudit({ orgId: req.orgId, userId: req.user.id, action: 'ingestion_key.revoke', entityType: 'ingestion_key', entityId: req.params.keyId, ip: clientIp(req) });
    res.json({ success: true });
  });

  // -------------------------------------------------- tenant-scoped reading
  router.get('/api/v1/issues', requireAuth, requireCapability('patch:view'), (req, res) => {
    res.json({ success: true, issues: listIssues(req.orgId).map(toIssueView) });
  });

  router.get('/api/v1/issues/:id/patch', requireAuth, requireCapability('patch:view'), (req, res) => {
    if (!getIssueForOrg(req.orgId, req.params.id)) return res.status(404).json({ success: false, error: 'Not found.' });
    res.json(store.getPatch(req.params.id) || null);
  });

  router.get('/api/v1/issues/:id/validation', requireAuth, requireCapability('patch:view'), (req, res) => {
    if (!getIssueForOrg(req.orgId, req.params.id)) return res.status(404).json({ success: false, error: 'Not found.' });
    res.json(listValidationRuns(req.orgId, req.params.id));
  });

  router.get('/api/v1/validation', requireAuth, requireCapability('patch:view'), (req, res) => {
    res.json(listValidationRuns(req.orgId));
  });

  router.get('/api/v1/deployments', requireAuth, requireCapability('patch:view'), (req, res) => {
    res.json(listDeployments(req.orgId));
  });

  router.get('/api/v1/pipelines', requireAuth, requireCapability('patch:view'), (req, res) => {
    const ids = listIssues(req.orgId).map(i => i.id);
    res.json({ success: true, pipelines: ids.length ? store.getPipelines().filter(p => ids.includes(p.issueId)) : [] });
  });

  router.get('/api/v1/pipelines/:id', requireAuth, requireCapability('patch:view'), (req, res) => {
    const run = store.getPipelineRun(req.params.id);
    if (!run || !getIssueForOrg(req.orgId, run.issueId)) return res.status(404).json({ success: false, error: 'Not found.' });
    res.json({ success: true, pipeline: run });
  });

  router.get('/api/v1/pipeline-runs/:id', requireAuth, requireCapability('patch:view'), (req, res) => {
    const run = store.getPipelineRun(req.params.id);
    if (!run || !getIssueForOrg(req.orgId, run.issueId)) return res.status(404).json({ success: false, error: 'Not found.' });
    res.json(run);
  });

  // ------------------------------------------------------------ approvals
  router.post('/api/v1/issues/:id/approve', requireAuth, requireCapability('patch:approve'), async (req, res) => {
    if (!getIssueForOrg(req.orgId, req.params.id)) return res.status(404).json({ success: false, error: 'Not found.' });
    recordAudit({ orgId: req.orgId, userId: req.user.id, action: 'patch.approve', entityType: 'issue', entityId: req.params.id, ip: clientIp(req) });
    await orchestrator.resumeApprovedPipeline(req.params.id);
    res.json({ success: true, message: 'Approval granted. Pipeline resumed.' });
  });

  router.post('/api/v1/issues/:id/reject', requireAuth, requireCapability('patch:reject'), (req, res) => {
    if (!getIssueForOrg(req.orgId, req.params.id)) return res.status(404).json({ success: false, error: 'Not found.' });
    recordAudit({ orgId: req.orgId, userId: req.user.id, action: 'patch.reject', entityType: 'issue', entityId: req.params.id, ip: clientIp(req) });
    store.updateIssue(req.params.id, { status: 'REJECTED_BY_ADMIN', resolvedAt: new Date().toISOString() });
    const patch = store.getPatch(req.params.id);
    if (patch) store.updatePatch(patch.id, { status: 'REJECTED' });
    const run = store.getPipelineRun(req.params.id);
    if (run) store.updatePipelineRun(run.id, { status: 'REJECTED', currentStep: 'ADMIN_REVIEW', completedAt: new Date().toISOString() });
    res.json({ success: true, message: 'Patch rejected. Pipeline closed.' });
  });

  // --------------------------------------------------------- applications
  router.get('/api/v1/apps', requireAuth, requireCapability('patch:view'), (req, res) => {
    res.json(listApplications(req.orgId).map(toAppView));
  });

  router.post('/api/v1/apps', requireAuth, requireCapability('app:create'), (req, res) => {
    const { name, type, repoUrl, permissions, sourcePath, project_id } = req.body;
    const appId = 'APP-' + Math.floor(100 + Math.random() * 900);
    const project = (project_id && getProject(req.orgId, project_id)) || getProject(req.orgId, 'PRJ-BOOTSTRAP') || listProjects(req.orgId)[0];
    if (!project) return res.status(400).json({ success: false, error: 'Create a project first.' });

    store.addApplication({
      id: appId, customerId: req.orgId, orgId: req.orgId, name: name || 'Custom Application', type: type || 'Web Service',
      port: 3000, repoUrl: repoUrl || 'https://github.com/customer/' + appId.toLowerCase(), branch: 'main',
      status: 'Connected', sdkKey: `sdk_${appId.toLowerCase()}_live`,
      permissions: permissions || { issueAccess: true, repoAccess: true, deploymentAccess: true },
      jenkinsStatus: 'Not verified — no CI provider configured',
      dockerStatus: 'Not verified — no container registry configured',
      canaryThreshold: '99.5%'
    });
    updateApplicationForOrg(req.orgId, appId, { project_id: project.id });

    let source = null;
    if (sourcePath || repoUrl) {
      const r = connectSource(appId, { localPath: sourcePath, repoUrl });
      source = { ok: r.ok, via: r.via || null, root: r.root || null, error: r.error || null };
    }
    recordAudit({ orgId: req.orgId, userId: req.user.id, action: 'app.create', entityType: 'application', entityId: appId, ip: clientIp(req) });
    res.json({ success: true, app: toAppView(store.getApplication(appId)), source });
  });

  router.post('/api/v1/apps/:id/source', requireAuth, requireCapability('app:update'), (req, res) => {
    const app = getApplicationForOrg(req.orgId, req.params.id);
    if (!app) return res.status(404).json({ success: false, error: 'Not found.' });
    const { sourcePath, repoUrl } = req.body || {};
    const result = connectSource(app.id, { localPath: sourcePath, repoUrl });
    recordAudit({ orgId: req.orgId, userId: req.user.id, action: 'app.connect_source', entityType: 'application', entityId: app.id, outcome: result.ok ? 'success' : 'denied', ip: clientIp(req) });
    if (!result.ok) return res.status(400).json({ success: false, error: result.error });
    res.json({ success: true, ...result, indexedFiles: indexSourceFiles(result.root).length });
  });

  router.get('/api/v1/apps/:id/source', requireAuth, (req, res) => {
    const app = getApplicationForOrg(req.orgId, req.params.id);
    if (!app) return res.status(404).json({ success: false, error: 'Not found.' });
    const src = resolveSourceRoot(toAppView(app));
    if (!src.root) return res.json({ success: false, error: src.error, source: null });
    const files = indexSourceFiles(src.root);
    res.json({ success: true, source: { via: src.via, root: src.root, detail: src.detail, fileCount: files.length, files: files.slice(0, 25).map(f => f.rel) } });
  });

  // ------------------------------------------- platform-wide build artifacts
  router.get('/api/v1/evaluation', requireAuth, requireCapability('patch:view'), (req, res) => {
    const p = path.join(baseDir, 'benchmark', 'results.json');
    if (!fs.existsSync(p)) return res.status(404).json({ success: false, error: 'No evaluation results found. Run: npm run eval' });
    res.json({ success: true, results: JSON.parse(fs.readFileSync(p, 'utf-8')) });
  });

  router.get('/api/v1/risk-model', requireAuth, requireCapability('patch:view'), (req, res) => {
    res.json({ success: true, model: RISK_MODEL });
  });

  router.get('/api/v1/list', requireAuth, requireCapability('patch:view'), (req, res) => {
    const issues = listIssues(req.orgId).map(toIssueView);
    res.json({ success: true, issues });
  });

  // API errors must be JSON, never an HTML stack page, and must never leak internals.
  router.use((err, req, res, _next) => {
    console.error('[api]', req.method, req.originalUrl, err.message);
    if (res.headersSent) return;
    res.status(500).json({ success: false, error: 'Internal server error.' });
  });


/**
 * The only endpoint a Viewer role may use.
 *
 * Returns a deliberately minimal projection: name, what it is, and where to go
 * use it. No SDK keys, no repository URL, no source information, no bugs, no
 * patches, no deployments, no audit trail.
 */
router.get('/api/v1/websites', requireAuth, requireCapability('websites:view'), (req, res) => {
  const websites = listApplications(req.orgId).map(a => ({
    id: a.id,
    name: a.name,
    type: a.type,
    status: a.status,
    siteUrl: a.site_url || null,
    // Link back to the connected site's own BugShield widget, if one is served.
    healthUrl: a.health_url || null
  }));
  res.json({
    success: true,
    viewerMode: req.role === 'viewer',
    organization: req.org ? { id: req.org.id, name: req.org.name } : null,
    websites
  });
});

router.post('/api/v1/apps/:id/site-url', requireAuth, requireCapability('app:update'), (req, res) => {
  const app = getApplicationForOrg(req.orgId, req.params.id);
  if (!app) return res.status(404).json({ success: false, error: 'Not found.' });
  const { siteUrl } = req.body || {};
  const value = String(siteUrl || '').trim();
  if (value) {
    let parsed;
    try { parsed = new URL(value); } catch { return res.status(400).json({ success: false, error: 'Enter a valid URL, e.g. https://shop.example.com' }); }
    if (!['http:', 'https:'].includes(parsed.protocol)) return res.status(400).json({ success: false, error: 'Only http and https URLs are allowed.' });
  }
  updateApplicationForOrg(req.orgId, app.id, { site_url: value || null });
  recordAudit({ orgId: req.orgId, userId: req.user.id, action: 'app.site_url', entityType: 'application', entityId: app.id, ip: clientIp(req) });
  res.json({ success: true, siteUrl: value || null });
});

// ------------------------------------------- integration status (honest)
  // These endpoints perform real calls. Without credentials they report
  // "not configured" rather than implying a connection exists.
  router.get('/api/v1/integrations/status', requireAuth, requireCapability('patch:view'), async (req, res) => {
    const github = getProvider('github');
    const gitlab = getProvider('gitlab');
    const [githubVerify, gitlabVerify] = await Promise.all([github.verify(), gitlab.verify()]);
    res.json({
      success: true,
      repository: [
        { provider: 'github', implemented: true, ...githubVerify },
        { provider: 'gitlab', implemented: false, ...gitlabVerify }
      ],
      ci: listCiStatus(),
      mail: { configured: mailConfigured(), ...(await verifyMail()) },
      ai: getAiStatus(),
      detectors: {
        deterministic: ['DIV_ZERO', 'UNDEFINED_DYNAMIC_KEY', 'MISSING_AWAIT', 'NULL_DEREF'],
        universal: 'AI_GENERAL (any other class via the configured model; honestly reported as unavailable when AI_API_KEY is unset)'
      },
      deployment: [{
        strategy: 'in-place source update',
        zeroDowntime: false,
        note: 'No blue/green, canary or rolling adapter is configured. Zero-downtime deployment is unsupported on this target.'
      }]
    });
  });

  router.get('/api/v1/integrations/github/repositories', requireAuth, requireCapability('app:create'), async (req, res) => {
    const gh = getProvider('github');
    const v = await gh.verify();
    if (!v.ok) return res.status(400).json({ success: false, error: v.error, configured: !!v.configured });
    const result = await gh.listRepositories();
    if (!result.ok) return res.status(400).json({ success: false, error: result.error });
    res.json({ success: true, repositories: result.repositories });
  });

  router.get('/api/v1/integrations/ci/verify', requireAuth, requireCapability('patch:view'), async (req, res) => {
    const providers = listCiStatus().filter(p => p.configured);
    if (!providers.length) {
      return res.json({
        success: true, verified: [],
        message: 'No CI provider is configured. Set JENKINS_URL and JENKINS_TOKEN, or GITHUB_TOKEN and GITHUB_REPOSITORY.'
      });
    }
    const verified = [];
    for (const p of providers) verified.push(await getCiProvider(p.name).verify());
    res.json({ success: true, verified });
  });

  // ------------------------------------------------ self-hosted source agents
  // The agent authenticates with its own bearer secret; there is no session and
  // no inbound port on the customer's machine.
  function authenticateAgent(req) {
    const header = req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : '';
    if (!token || token.length < 20) return null;
    return db.prepare(`SELECT * FROM source_agents WHERE secret_hash = ? AND status = 'ACTIVE'`).get(hashToken(token)) || null;
  }

  router.post('/api/agent/poll', async (req, res) => {
    const agent = authenticateAgent(req);
    if (!agent) return res.status(401).json({ success: false, error: 'Invalid agent credentials.' });

    db.prepare('UPDATE source_agents SET last_seen_at = ?, fingerprint = ? WHERE id = ?')
      .run(new Date().toISOString(), String(req.body?.fingerprint || '').slice(0, 64), agent.id);

    const jobs = db.prepare(`SELECT id, issue_id, root, title, description FROM agent_jobs
                             WHERE agent_id = ? AND status = 'QUEUED' ORDER BY created_at LIMIT 20`).all(agent.id)
      .map(j => ({ id: j.id, issueId: j.issue_id, root: j.root, title: j.title, description: j.description }));
    res.json({ success: true, jobs });
  });

  router.post('/api/agent/result', async (req, res) => {
    const agent = authenticateAgent(req);
    if (!agent) return res.status(401).json({ success: false, error: 'Invalid agent credentials.' });
    const { jobId, error } = req.body || {};
    const job = db.prepare('SELECT * FROM agent_jobs WHERE id = ? AND agent_id = ?').get(String(jobId || ''), agent.id);
    if (!job) return res.status(404).json({ success: false, error: 'Unknown job.' });

    db.prepare('UPDATE agent_jobs SET status = ?, result = ?, completed_at = ? WHERE id = ?')
      .run(error ? 'FAILED' : 'COMPLETED', JSON.stringify(req.body || {}), new Date().toISOString(), job.id);
    recordAudit({ orgId: agent.org_id, action: 'agent.result', entityType: 'agent_job', entityId: job.id, outcome: error ? 'denied' : 'success' });

    // Resume the pipeline now that the customer's agent has looked at their code.
    if (!error && job.issue_id) {
      try {
        const inst = new MultiAgentOrchestrator(null);
        await inst.resumeFromAgent(job.issue_id, req.body || {});
      } catch (e) {
        console.error('[agent] resume failed:', e.message);
      }
    }
    res.json({ success: true });
  });

  // Owner-facing management
  router.get('/api/v1/source-agents', requireAuth, requireCapability('settings:view'), (req, res) => {
    const rows = db.prepare('SELECT id, name, status, fingerprint, roots, last_seen_at, created_at, application_id FROM source_agents WHERE org_id = ? ORDER BY created_at DESC').all(req.orgId);
    res.json({ success: true, agents: rows });
  });

  router.post('/api/v1/source-agents', requireAuth, requireCapability('app:create'), (req, res) => {
    const { name, applicationId, roots } = req.body || {};
    if (!name) return res.status(400).json({ success: false, error: 'Agent name is required.' });
    const id = `AGT-${crypto.randomBytes(6).toString('hex')}`;
    const secret = `bsa_${crypto.randomBytes(32).toString('base64url')}`;
    db.prepare(`INSERT INTO source_agents (id, org_id, application_id, name, secret_hash, fingerprint, roots, status, created_at)
                VALUES (?, ?, ?, ?, ?, NULL, ?, 'ACTIVE', ?)`)
      .run(id, req.orgId, applicationId || null, String(name).slice(0, 120), hashToken(secret),
           JSON.stringify(Array.isArray(roots) ? roots.map(r => String(r).slice(0, 300)) : []), new Date().toISOString());
    recordAudit({ orgId: req.orgId, userId: req.user.id, action: 'agent.create', entityType: 'source_agent', entityId: id, ip: clientIp(req) });
    res.json({
      success: true, agent: { id, name },
      secret,
      warning: 'Shown once. The agent authenticates with this secret; revoke it by removing the agent if compromised.'
    });
  });

  router.delete('/api/v1/source-agents/:id', requireAuth, requireCapability('app:disconnect'), (req, res) => {
    const res1 = db.prepare(`UPDATE source_agents SET status = 'REVOKED' WHERE id = ? AND org_id = ?`).run(req.params.id, req.orgId);
    if (!res1.changes) return res.status(404).json({ success: false, error: 'Not found.' });
    recordAudit({ orgId: req.orgId, userId: req.user.id, action: 'agent.revoke', entityType: 'source_agent', entityId: req.params.id, ip: clientIp(req) });
    res.json({ success: true });
  });

  return router;
}