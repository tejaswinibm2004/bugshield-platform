/**
 * Authentication, session handling and role-based access control.
 *
 * Design decisions:
 *  - Passwords: scrypt with a per-user salt, constant-time comparison.
 *  - Sessions: opaque 256-bit token in an HttpOnly cookie. Only the SHA-256 hash
 *    is stored, so a database leak cannot be replayed as a valid session.
 *  - CSRF: SameSite=Strict cookie plus a required custom header on mutations,
 *    which blocks simple cross-site form and fetch posts.
 *  - RBAC: capability matrix rather than scattered role string checks, so a new
 *    role cannot accidentally inherit unintended powers.
 */
import { hashToken, newSessionToken, ROLE_RANK, ROLES, verifyPassword } from '../services/migrations.js';
import * as tenant from '../services/tenantStore.js';

export const SESSION_COOKIE = 'bs_session';

/**
 * Capability matrix. Rather than scattered role string checks, so a new role
 * cannot accidentally inherit unintended powers.
 *
 * Note `viewer`: it is a customer-stakeholder role, not a read-only engineer.
 * It may see the list of websites their organisation uses, and nothing else —
 * no bugs, no source, no patches, no deployments, no audit, no settings.
 */
export const CAPABILITIES = {
  'websites:view':    ['owner', 'admin', 'developer', 'reviewer', 'viewer'],
  'project:create':   ['owner', 'admin', 'developer'],
  'project:delete':   ['owner', 'admin'],
  'app:create':       ['owner', 'admin', 'developer'],
  'app:update':       ['owner', 'admin', 'developer'],
  'app:disconnect':   ['owner', 'admin'],
  'patch:view':       ['owner', 'admin', 'developer', 'reviewer'],
  'patch:approve':    ['owner', 'admin', 'reviewer'],
  'patch:reject':     ['owner', 'admin', 'reviewer'],
  'deploy:trigger':   ['owner', 'admin'],
  'policy:manage':    ['owner', 'admin'],
  'member:manage':    ['owner', 'admin'],
  'audit:view':       ['owner', 'admin'],
  'settings:view':    ['owner', 'admin', 'developer', 'reviewer']
};

export function roleCan(role, capability) {
  const allowed = CAPABILITIES[capability];
  if (!allowed) return false;
  return allowed.includes(role);
}

export function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  }
  return out;
}

export function sessionCookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  };
}

/** Resolve the caller from the session cookie. Never throws; leaves req.user null when anonymous. */
export function attachUser(req, _res, next) {
  req.user = null;
  req.org = null;
  req.role = null;
  const token = parseCookies(req.headers.cookie)[SESSION_COOKIE];
  if (!token) return next();
  const session = tenant.getSession(hashToken(token));
  if (!session) return next();
  const user = tenant.getUser(session.user_id);
  if (!user || user.disabled) return next();
  const membership = tenant.getMembership(user.id, session.org_id);
  if (!membership) return next();          // membership revoked -> session no longer valid
  tenant.touchSession(session.token_hash);
  req.user = user;
  req.org = tenant.getOrganization(session.org_id);
  req.orgId = session.org_id;
  req.role = membership.role;
  req.sessionHash = session.token_hash;
  next();
}

/** Hard gate: 401 when there is no authenticated session. */
export function requireAuth(req, res, next) {
  if (!req.user) {
    tenant.recordAudit({ action: 'auth.denied', entityType: 'route', entityId: req.originalUrl, outcome: 'denied', ip: clientIp(req) });
    return res.status(401).json({ success: false, error: 'Authentication required.' });
  }
  next();
}

/** Hard gate: 403 when the session's role lacks the capability. */
export function requireCapability(capability) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ success: false, error: 'Authentication required.' });
    if (!roleCan(req.role, capability)) {
      tenant.recordAudit({
        orgId: req.orgId, userId: req.user.id, action: 'authz.denied',
        entityType: 'capability', entityId: capability, outcome: 'denied', ip: clientIp(req)
      });
      return res.status(403).json({ success: false, error: `Your role (${req.role}) may not perform this action.` });
    }
    next();
  };
}

/**
 * CSRF defence for state-changing verbs. Requires a non-simple request header,
 * which a cross-site attacker cannot set without triggering a CORS preflight.
 */
export function requireSameOrigin(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();

  // The SDK ingestion endpoint is deliberately cross-origin: a widget running on
  // the customer's site must POST to the platform host. It is a public,
  // key-authenticated API and enforces its own origin allow-list per key, so the
  // session-CSRF check does not apply to it.
  if (req.method === 'POST' && req.path === '/api/v1/issues') return next();

  // Agent routes authenticate with a bearer token, which browsers never attach
  // automatically, so they are not CSRF-able and need no session-based guard.
  if (req.path.startsWith('/api/agent/')) return next();

  if (req.headers['x-requested-with'] !== 'bugshield') {
    return res.status(403).json({ success: false, error: 'Missing X-Requested-With header (CSRF protection).' });
  }
  const origin = req.headers.origin;
  if (origin) {
    const host = req.headers.host;
    try {
      if (new URL(origin).host !== host) {
        return res.status(403).json({ success: false, error: 'Cross-origin request rejected.' });
      }
    } catch {
      return res.status(403).json({ success: false, error: 'Malformed Origin header.' });
    }
  }
  next();
}

export function clientIp(req) {
  return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket?.remoteAddress || null;
}

/** Validate credentials and start a session. Returns the raw token for the cookie. */
export function login({ email, password, orgId, ip, userAgent }) {
  const user = tenant.findUserByEmail(email);
  // Always run a verification so timing does not reveal whether the email exists.
  const ok = verifyPassword(password, user);
  if (!user || !ok || user.disabled) return { ok: false, error: 'Invalid email or password.' };

  let targetOrg = orgId ? tenant.getOrganization(orgId) : null;
  if (orgId && !targetOrg) return { ok: false, error: 'Unknown organisation.' };

  if (!targetOrg) {
    const orgs = tenant.listOrganizationsForUser(user.id);
    if (!orgs.length) return { ok: false, error: 'This account has no organisation access.' };
    targetOrg = tenant.getOrganization(orgs[0].id);
  }
  const membership = tenant.getMembership(user.id, targetOrg.id);
  if (!membership) return { ok: false, error: 'You do not have access to that organisation.' };

  const token = newSessionToken();
  tenant.createSession({ tokenHash: hashToken(token), userId: user.id, orgId: targetOrg.id, ip, userAgent });
  tenant.recordAudit({ orgId: targetOrg.id, userId: user.id, action: 'auth.login', outcome: 'success', ip });
  return { ok: true, token, user, org: targetOrg, role: membership.role };
}

export function logout(req) {
  if (req.sessionHash) {
    tenant.deleteSession(req.sessionHash);
    tenant.recordAudit({ orgId: req.orgId, userId: req.user?.id, action: 'auth.logout', outcome: 'success', ip: clientIp(req) });
  }
}

export { ROLES, ROLE_RANK };