/**
 * Abuse protection for the unauthenticated ingestion endpoint.
 *
 * A fixed-window counter per key and per client address. Deliberately in-memory:
 * it protects a single running instance, and restarting clears counters, which is
 * the correct trade-off against persisting attacker-controlled write volume.
 */
const buckets = new Map();

function nowMs() { return Date.now(); }

function hit(key, limit, windowMs) {
  const t = nowMs();
  const entry = buckets.get(key);
  if (!entry || entry.resetAt <= t) {
    buckets.set(key, { count: 1, resetAt: t + windowMs });
    return { allowed: true, remaining: limit - 1, resetAt: t + windowMs };
  }
  entry.count += 1;
  return { allowed: entry.count <= limit, remaining: Math.max(0, limit - entry.count), resetAt: entry.resetAt };
}

/** Periodic sweep so the map cannot grow without bound. */
const sweeper = setInterval(() => {
  const t = nowMs();
  for (const [k, v] of buckets) if (v.resetAt <= t) buckets.delete(k);
}, 60_000);
sweeper.unref?.();

export const LIMITS = {
  perKey: { limit: 30, windowMs: 60_000 },
  perIp: { limit: 60, windowMs: 60_000 }
};

export function checkRateLimit({ key, ip }) {
  const byKey = key ? hit(`k:${key}`, LIMITS.perKey.limit, LIMITS.perKey.windowMs) : null;
  const byIp = ip ? hit(`i:${ip}`, LIMITS.perIp.limit, LIMITS.perIp.windowMs) : null;
  const allowed = (!byKey || byKey.allowed) && (!byIp || byIp.allowed);
  const resetAt = Math.max(byKey?.resetAt || 0, byIp?.resetAt || 0);
  return {
    allowed,
    scope: !byKey?.allowed ? 'key' : (!byIp?.allowed ? 'ip' : null),
    retryAfterSec: Math.max(1, Math.ceil((resetAt - nowMs()) / 1000))
  };
}

/** Test seam. */
export function _resetRateLimits() { buckets.clear(); }