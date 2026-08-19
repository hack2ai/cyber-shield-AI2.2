import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../services/threat-intelligence.service.js', () => ({
  collectThreatIntelligence: vi.fn(),
}));

import { collectThreatIntelligence } from '../services/threat-intelligence.service.js';
import { analyzeUrlEnriched } from './enriched-analyzer.js';

const mockedCollect = vi.mocked(collectThreatIntelligence);

describe('analyzeUrlEnriched', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('combines local findings with threat intelligence', async () => {
    mockedCollect.mockResolvedValue({
      hostname: 'example.com',
      dns: {
        hostname: 'example.com',
        ipv4: ['93.184.216.34'],
        ipv6: [],
        cname: [],
        mx: [],
        txt: [],
        errors: [],
      },
      tls: {
        hostname: 'example.com',
        port: 443,
        authorized: true,
        protocol: 'TLSv1.3',
        cipher: 'TLS_AES_128_GCM_SHA256',
        issuer: { O: 'Example CA' },
        subject: { CN: 'example.com' },
        validFrom: 'Jan 01 00:00:00 2026 GMT',
        validTo: 'Jan 01 00:00:00 2027 GMT',
        fingerprint256: 'AA:BB',
      },
      whois: {
        domain: 'example.com',
        registrar: 'Example Registrar',
        createdAt: '2000-01-01T00:00:00.000Z',
        expiresAt: '2030-01-01T00:00:00.000Z',
        updatedAt: '2026-01-01T00:00:00.000Z',
        nameServers: ['ns1.example.com'],
        rawAvailable: true,
      },
      virusTotal: {
        malicious: 0,
        suspicious: 0,
        harmless: 80,
        undetected: 10,
        timeout: false,
        status: 'ok',
      },
    });

    const result = await analyzeUrlEnriched('https://example.com');

    expect(result.normalizedUrl).toBe('https://example.com/');
    expect(result.threatIntelligence.hostname).toBe('example.com');
    expect(result.findings).toHaveLength(0);
    expect(result.assessment.level).toBe('LOW');
  });

  it('adds elevated findings for malicious VirusTotal results', async () => {
    mockedCollect.mockResolvedValue({
      hostname: 'bad.example',
      dns: {
        hostname: 'bad.example', ipv4: [], ipv6: [], cname: [], mx: [], txt: [], errors: [],
      },
      tls: {
        hostname: 'bad.example', port: 443, authorized: false, protocol: null, cipher: null,
        issuer: null, subject: null, validFrom: null, validTo: null, fingerprint256: null,
        error: 'certificate failure',
      },
      whois: {
        domain: 'bad.example', registrar: null, createdAt: null, expiresAt: null,
        updatedAt: null, nameServers: [], rawAvailable: false,
      },
      virusTotal: {
        malicious: 12,
        suspicious: 3,
        harmless: 20,
        undetected: 5,
        timeout: false,
        status: 'ok',
      },
    });

    const result = await analyzeUrlEnriched('https://bad.example');

    expect(result.findings.some((finding) => finding.id === 'vt-malicious')).toBe(true);
    expect(result.findings.some((finding) => finding.id === 'vt-suspicious')).toBe(true);
    expect(result.findings.some((finding) => finding.id === 'tls-error')).toBe(true);
    expect(result.assessment.score).toBeGreaterThan(0);
  });

  it('continues when VirusTotal is unavailable', async () => {
    mockedCollect.mockResolvedValue({
      hostname: 'example.com',
      dns: {
        hostname: 'example.com', ipv4: [], ipv6: [], cname: [], mx: [], txt: [], errors: [],
      },
      tls: {
        hostname: 'example.com', port: 443, authorized: true, protocol: 'TLSv1.3', cipher: null,
        issuer: null, subject: null, validFrom: null, validTo: null, fingerprint256: null,
      },
      whois: {
        domain: 'example.com', registrar: null, createdAt: null, expiresAt: null,
        updatedAt: null, nameServers: [], rawAvailable: false,
      },
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
