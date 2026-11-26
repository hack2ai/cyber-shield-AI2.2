import type { RequestHandler } from 'express';

/**
 * Baseline security headers.
 * API and health routes keep a locked-down policy; the static frontend gets a
 * policy that allows its own bundled scripts/styles and Firebase connections.
 */
const FRONTEND_CSP = [
  "default-src 'self'",
  "script-src 'self' https://apis.google.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob: https:",
  "font-src 'self' data:",
  "connect-src 'self' https://*.googleapis.com https://*.firebaseio.com wss://*.firebaseio.com https://*.firebaseapp.com",
  "frame-src 'self' https://*.firebaseapp.com https://accounts.google.com",
  "worker-src 'self' blob:",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "object-src 'none'",
].join('; ');

export const securityHeaders: RequestHandler = (req, res, next) => {
  const isApi = req.path.startsWith('/api') || req.path === '/health';

  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', isApi ? 'camera=(), microphone=(), geolocation=()' : 'camera=(self), microphone=(), geolocation=()');
  res.setHeader('Cross-Origin-Opener-Policy', isApi ? 'same-origin' : 'same-origin-allow-popups');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  res.setHeader('Origin-Agent-Cluster', '?1');
  res.setHeader('X-DNS-Prefetch-Control', 'off');

  res.setHeader(
    'Content-Security-Policy',
    isApi ? "default-src 'none'; frame-ancestors 'none'; base-uri 'none'" : FRONTEND_CSP,
  );

  if (req.secure || req.header('x-forwarded-proto') === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  next();
};
