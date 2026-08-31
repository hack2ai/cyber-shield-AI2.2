import { afterEach, describe, expect, it, vi } from 'vitest';
import { createServer } from 'node:http';

const { mockAnalyzeUrlEnriched, mockValidateExternalUrl } = vi.hoisted(() => ({
  mockAnalyzeUrlEnriched: vi.fn(),
  mockValidateExternalUrl: vi.fn(),
}));

vi.mock('../analysis/enriched-analyzer.js', () => ({
  analyzeUrlEnriched: mockAnalyzeUrlEnriched,
}));

vi.mock('../security/index.js', () => ({
  requestContext: (_req: unknown, _res: unknown, next: () => void) => next(),
  rateLimit: (_req: unknown, _res: unknown, next: () => void) => next(),
  securityHeaders: (_req: unknown, _res: unknown, next: () => void) => next(),
  validateExternalUrl: mockValidateExternalUrl,
  isBlockedIp: vi.fn(() => false),
}));

import { createApp } from '../app.js';

describe('POST /api/analysis', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  async function startServer() {
    const server = createServer(createApp());
    await new Promise<void>((resolve) => server.listen(0, resolve));
    const address = server.address();
    if (!address || typeof address === 'string') {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      throw new Error('Unable to determine test server port');
    }
    return { server, baseUrl: `http://127.0.0.1:${address.port}` };
  }

  async function closeServer(server: ReturnType<typeof createServer>) {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }

  it('returns a versioned typed analysis response for a valid request', async () => {
    mockValidateExternalUrl.mockResolvedValue(new URL('https://example.com/'));
    mockAnalyzeUrlEnriched.mockResolvedValue({
      url: 'https://example.com/',
      normalizedUrl: 'https://example.com/',
      features: {},
      findings: [],
      assessment: { score: 0, level: 'LOW', confidence: 45, findings: [] },
      generatedAt: '2026-08-19T00:00:00.000Z',
      threatIntelligence: {
        hostname: 'example.com',
        dns: { hostname: 'example.com', ipv4: [], ipv6: [], cname: [], mx: [], txt: [], errors: [] },
        tls: {
          hostname: 'example.com', port: 443, authorized: true, protocol: 'TLSv1.3', cipher: null,
          issuer: null, subject: null, validFrom: null, validTo: null, fingerprint256: null,
        },
        whois: {
          domain: 'example.com', registrar: null, createdAt: null, expiresAt: null,
          updatedAt: null, nameServers: [], rawAvailable: false,
        },
        virusTotal: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0, timeout: false, status: 'ok' },
      },
      redirects: {
        originalUrl: 'https://example.com/', finalUrl: 'https://example.com/', hops: [],
        redirectCount: 0, hostnameChanged: false, timedOut: false,
      },
    });

    const { server, baseUrl } = await startServer();
    try {
      const response = await fetch(`${baseUrl}/api/analysis`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url: 'https://example.com' }),
      });
      const body = await response.json();

      expect(response.status).toBe(200);
      expect(body.success).toBe(true);
      expect(body.version).toBe('v1');
      expect(body.data.assessment.level).toBe('LOW');
      expect(body.data.threatIntelligence.hostname).toBe('example.com');
      expect(mockValidateExternalUrl).toHaveBeenCalledWith('https://example.com');
      expect(mockAnalyzeUrlEnriched).toHaveBeenCalledWith(expect.any(URL));
    } finally {
      await closeServer(server);
    }
  });

  it('rejects a malformed request with the v1 error envelope', async () => {
    const { server, baseUrl } = await startServer();
    try {
      const response = await fetch(`${baseUrl}/api/analysis`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url: '' }),
      });
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.success).toBe(false);
      expect(body.version).toBe('v1');
      expect(body.error.code).toBe('INVALID_REQUEST');
      expect(body.error.message).toBe('url is required');
      expect(mockValidateExternalUrl).not.toHaveBeenCalled();
      expect(mockAnalyzeUrlEnriched).not.toHaveBeenCalled();
    } finally {
      await closeServer(server);
    }
  });

  it('rejects a non-object JSON body with 400', async () => {
    const { server, baseUrl } = await startServer();
    try {
      const response = await fetch(`${baseUrl}/api/analysis`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(['https://example.com']),
      });
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.success).toBe(false);
      expect(body.version).toBe('v1');
      expect(body.error.code).toBe('INVALID_REQUEST');
      expect(body.error.message).toBe('Request body must be a JSON object');
      expect(mockValidateExternalUrl).not.toHaveBeenCalled();
      expect(mockAnalyzeUrlEnriched).not.toHaveBeenCalled();
    } finally {
      await closeServer(server);
    }
  });

  it('rejects a non-string URL with 400', async () => {
    const { server, baseUrl } = await startServer();
    try {
      const response = await fetch(`${baseUrl}/api/analysis`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url: 12345 }),
      });
      const body = await response.json();

      expect(response.status).toBe(400);
      expect(body.success).toBe(false);
      expect(body.version).toBe('v1');
      expect(body.error.code).toBe('INVALID_REQUEST');
      expect(body.error.message).toBe('url must be a string');
      expect(mockValidateExternalUrl).not.toHaveBeenCalled();
      expect(mockAnalyzeUrlEnriched).not.toHaveBeenCalled();
    } finally {
      await closeServer(server);
    }
  });
});
