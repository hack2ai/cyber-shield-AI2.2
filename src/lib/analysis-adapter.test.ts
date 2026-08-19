import { describe, expect, it } from 'vitest';
import { adaptAnalysisResult } from './analysis-adapter';
import type { AnalysisResult } from './analysis-api';

function makeResult(overrides: Partial<AnalysisResult> = {}): AnalysisResult {
  return {
    url: 'https://example.com/',
    normalizedUrl: 'https://example.com/',
    features: {},
    findings: [],
    assessment: {
      score: 12,
      level: 'LOW',
      confidence: 55,
      findings: [],
    },
    generatedAt: '2026-08-19T00:00:00.000Z',
    threatIntelligence: {
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
        cipher: null,
        issuer: null,
        subject: null,
        validFrom: null,
        validTo: null,
        fingerprint256: null,
      },
      whois: {
        domain: 'example.com',
        registrar: 'Example Registrar',
        createdAt: '2000-01-01T00:00:00.000Z',
        expiresAt: null,
        updatedAt: null,
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
    },
    redirects: {
      originalUrl: 'https://example.com/',
      finalUrl: 'https://example.com/',
      hops: [],
      redirectCount: 0,
      hostnameChanged: false,
      timedOut: false,
    },
    ...overrides,
  };
}

describe('adaptAnalysisResult', () => {
  it('maps LOW risk to the legacy Safe classification', () => {
    const adapted = adaptAnalysisResult(makeResult());

    expect(adapted.threatScore).toBe(12);
    expect(adapted.classification).toBe('Safe');
    expect(adapted.type).toBe('url');
    expect(adapted.target).toBe('https://example.com/');
    expect(adapted.technicalSummary.dns).toContain('1 IP address');
    expect(adapted.technicalSummary.threatIntel).toContain('0 malicious');
  });

  it('maps HIGH and CRITICAL to phishing and malicious', () => {
    expect(adaptAnalysisResult(makeResult({ assessment: { score: 72, level: 'HIGH', confidence: 80, findings: [] } })).classification).toBe('Phishing');
    expect(adaptAnalysisResult(makeResult({ assessment: { score: 95, level: 'CRITICAL', confidence: 95, findings: [] } })).classification).toBe('Malicious');
  });

  it('preserves evidence and adds redirect indicators', () => {
    const adapted = adaptAnalysisResult(makeResult({
      findings: [{
        id: 'cross-domain-redirect',
        label: 'Cross-domain redirect',
        severity: 3,
        weight: 10,
        description: 'The URL redirected to a different hostname.',
      }],
      assessment: {
        score: 35,
        level: 'MEDIUM',
        confidence: 65,
        findings: [{
          id: 'cross-domain-redirect',
          label: 'Cross-domain redirect',
          severity: 3,
          weight: 10,
          description: 'The URL redirected to a different hostname.',
        }],
      },
      redirects: {
        originalUrl: 'https://example.com/',
        finalUrl: 'https://other.example/',
        hops: [
          { url: 'https://example.com/', status: 302, location: 'https://other.example/' },
          { url: 'https://other.example/', status: 200, location: null },
        ],
        redirectCount: 1,
        hostnameChanged: true,
        timedOut: false,
      },
    }));

    expect(adapted.classification).toBe('Suspicious');
    expect(adapted.riskIndicators.some((indicator) => indicator.includes('Cross-domain redirect'))).toBe(true);
    expect(adapted.riskIndicators.some((indicator) => indicator.includes('CROSS_DOMAIN_REDIRECT'))).toBe(true);
    expect(adapted.raw.heuristics.hostnameChanged).toBe(true);
  });
});
