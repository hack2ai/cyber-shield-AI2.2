import { describe, expect, it } from 'vitest';
import express from 'express';
import { securityHeaders } from './security-headers.js';

async function getHeaders() {
  const app = express();
  app.use(securityHeaders);
  app.get('/health', (_req, res) => res.status(200).json({ ok: true }));

  const server = app.listen(0);
  try {
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Unable to determine test server port');
    const response = await fetch(`http://127.0.0.1:${address.port}/health`);
    return response.headers;
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

describe('security headers', () => {
  it('sets the expected baseline headers', async () => {
    const headers = await getHeaders();

    expect(headers.get('x-content-type-options')).toBe('nosniff');
    expect(headers.get('x-frame-options')).toBe('DENY');
    expect(headers.get('referrer-policy')).toBe('strict-origin-when-cross-origin');
    expect(headers.get('permissions-policy')).toContain('camera=()');
    expect(headers.get('cross-origin-opener-policy')).toBe('same-origin');
    expect(headers.get('cross-origin-resource-policy')).toBe('same-origin');
    expect(headers.get('content-security-policy')).toContain("default-src 'none'");
    expect(headers.get('origin-agent-cluster')).toBe('?1');
    expect(headers.get('x-dns-prefetch-control')).toBe('off');
  });
});
