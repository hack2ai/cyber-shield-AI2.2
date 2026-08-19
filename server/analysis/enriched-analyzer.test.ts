import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../services/threat-intelligence.service.js', () => ({
  collectThreatIntelligence: vi.fn(),
}));

vi.mock('../services/redirect.service.js', () => ({
  analyzeRedirects: vi.fn(),
}));

import { collectThreatIntelligence } from '../services/threat-intelligence.service.js';
import { analyzeRedirects } from '../services/redirect.service.js';
import { analyzeUrlEnriched } from './enriched-analyzer.js';

const mockedCollect = vi.mocked(collectThreatIntelligence);
const mockedRedirects = vi.mocked(analyzeRedirects);

const healthyIntelligence = {
  hostname: 'example.com',
  dns: { hostname: 'example.com', ipv4: ['93.184.216.34'], ipv6: [], cname: [], mx: [], txt: [], errors: [] },
  tls: {
    hostname: 'example.com', port: 443, authorized: true, protocol: 'TLSv1.3',
    cipher: 'TLS_AES_128_GCM_SHA256', issuer: { O: 'Example CA' }, subject: { CN: 'example.com' },
    validFrom: 'Jan 01 00:00:00 2026 GMT', validTo: 'Jan 01 00:00:00 2027 GMT', fingerprint256: 'AA:BB',
  },
  whois: {
    domain: 'example.com', registrar: 'Example Registrar', createdAt: '2000-01-01T00:00:00.000Z',
    expiresAt: '2030-01-01T00:00:00.000Z', updatedAt: '2026-01-01T00:00:00.000Z',
    nameServers: ['ns1.example.com'], rawAvailable: true,
  },
  virusTotal: { malicious: 0, suspicious: 0, harmless: 80, undetected: 10, timeout: false, status: 'ok' as const },
};

const noRedirects = {
  originalUrl: 'https://example.com/',
  finalUrl: 'https://example.com/',
  hops: [{ url: 'https://example.com/', status: 200, location: null }],
  redirectCount: 0,
  hostnameChanged: false,
  timedOut: false,
};

describe('analyzeUrlEnriched', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedCollect.mockResolvedValue(healthyIntelligence);
    mockedRedirects.mockResolvedValue(noRedirects);
  });

  it('combines local, threat-intelligence, and redirect results', async () => {
    const result = await analyzeUrlEnriched('https://example.com');

    expect(result.normalizedUrl).toBe('https://example.com/');
    expect(result.threatIntelligence.hostname).toBe('example.com');
    expect(result.redirects.redirectCount).toBe(0);
    expect(result.findings).toHaveLength(0);
    expect(result.assessment.level).toBe('LOW');
  });

  it('adds elevated findings for malicious VirusTotal results', async () => {
    mockedCollect.mockResolvedValue({
      ...healthyIntelligence,
      hostname: 'bad.example',
      dns: { ...healthyIntelligence.dns, hostname: 'bad.example' },
      tls: { ...healthyIntelligence.tls, hostname: 'bad.example', authorized: false, error: 'certificate failure' },
      whois: { ...healthyIntelligence.whois, domain: 'bad.example' },
      virusTotal: { malicious: 12, suspicious: 3, harmless: 20, undetected: 5, timeout: false, status: 'ok' },
    });

    const result = await analyzeUrlEnriched('https://bad.example');

    expect(result.findings.some((finding) => finding.id === 'vt-malicious')).toBe(true);
    expect(result.findings.some((finding) => finding.id === 'vt-suspicious')).toBe(true);
    expect(result.findings.some((finding) => finding.id === 'tls-error')).toBe(true);
    expect(result.assessment.score).toBeGreaterThan(0);
  });

  it('flags multiple and cross-domain redirects', async () => {
    mockedRedirects.mockResolvedValue({
      originalUrl: 'https://example.com/',
      finalUrl: 'https://other.example/',
      hops: [
        { url: 'https://example.com/', status: 302, location: 'https://a.example/' },
        { url: 'https://a.example/', status: 302, location: 'https://b.example/' },
        { url: 'https://b.example/', status: 302, location: 'https://other.example/' },
        { url: 'https://other.example/', status: 200, location: null },
      ],
      redirectCount: 3,
      hostnameChanged: true,
      timedOut: false,
    });

    const result = await analyzeUrlEnriched('https://example.com');

    expect(result.redirects.redirectCount).toBe(3);
    expect(result.findings.some((finding) => finding.id === 'many-redirects')).toBe(true);
    expect(result.findings.some((finding) => finding.id === 'cross-domain-redirect')).toBe(true);
  });

  it('continues when redirect analysis times out', async () => {
    mockedRedirects.mockResolvedValue({
      ...noRedirects,
      timedOut: true,
      error: 'Redirect analysis timed out',
    });

    const result = await analyzeUrlEnriched('https://example.com');

    expect(result.redirects.timedOut).toBe(true);
    expect(result.findings.some((finding) => finding.id === 'redirect-timeout')).toBe(true);
    expect(result.assessment.level).toBe('LOW');
  });

  it('continues when VirusTotal is unavailable', async () => {
    mockedCollect.mockResolvedValue({
      ...healthyIntelligence,
      virusTotal: {
        malicious: 0,
        suspicious: 0,
        harmless: 0,
        undetected: 0,
        timeout: true,
        status: 'unavailable',
        error: 'VirusTotal request timed out',
      },
    });

    const result = await analyzeUrlEnriched('https://example.com');

    expect(result.threatIntelligence.virusTotal.status).toBe('unavailable');
    expect(result.assessment.level).toBe('LOW');
  });
});
