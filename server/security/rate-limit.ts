import type { RequestHandler } from 'express';

type Bucket = { count: number; resetAt: number };
const buckets = new Map<string, Bucket>();
const WINDOW_MS = 60_000;
const MAX_REQUESTS = 60;
const MAX_BUCKETS = 10_000;
const CLEANUP_INTERVAL_MS = 60_000;
let lastCleanupAt = 0;

function cleanupExpiredBuckets(now: number): void {
  for (const [key, bucket] of buckets) {
    if (bucket.resetAt <= now) buckets.delete(key);
  }
  lastCleanupAt = now;
}

function cleanupIfDue(now: number): void {
  if (now - lastCleanupAt >= CLEANUP_INTERVAL_MS) {
    cleanupExpiredBuckets(now);
  }
}

/**
 * Dependency-free baseline limiter. Multi-instance production deployments
 * should use a shared/proxied limiter (for example Redis-backed) instead.
 * Active client buckets are never evicted when the bounded store is full;
 * this prevents high-cardinality traffic from clearing other clients' limits.
 */
export const rateLimit: RequestHandler = (req, res, next) => {
  const now = Date.now();
  cleanupIfDue(now);

  const key = req.ip || req.socket.remoteAddress || 'unknown';
  const current = buckets.get(key);

  if (!current || current.resetAt <= now) {
    if (!current && buckets.size >= MAX_BUCKETS) {
      // The periodic cleanup may have run recently; reclaim expired buckets
      // immediately before treating the store as genuinely full.
      cleanupExpiredBuckets(now);
      if (buckets.size >= MAX_BUCKETS) {
        res.setHeader('Retry-After', String(Math.max(1, Math.ceil(WINDOW_MS / 1000))));
        return res.status(503).json({ error: 'Rate limiter temporarily unavailable.' });
      }
    }

    buckets.set(key, { count: 1, resetAt: now + WINDOW_MS });
    return next();
  }

  current.count += 1;
  if (current.count > MAX_REQUESTS) {
    const retryAfter = Math.max(1, Math.ceil((current.resetAt - now) / 1000));
    res.setHeader('Retry-After', String(retryAfter));
    return res.status(429).json({ error: 'Too many requests. Please retry later.' });
  }

  return next();
};
