import { describe, expect, it } from 'vitest';
import { calculateRisk } from './scoring.js';
import { extractUrlFeatures, findingsFromUrlFeatures } from './features.js';

describe('URL feature extraction', () => {
  it('detects common suspicious URL indicators', () => {
    const url = new URL('http://xn--example-9db.com/login@account.example.zip');
    const features = extractUrlFeatures(url);

    expect(features.isHttps).toBe(false);
    expect(features.hasPunycode).toBe(true);
    expect(features.hasAtSymbol).toBe(true);
    expect(features.hasSuspiciousTld).toBe(true);
  });

  it('does not flag a normal HTTPS hostname for basic indicators', () => {
    const url = new URL('https://example.com/');
    const features = extractUrlFeatures(url);

    expect(features.isHttps).toBe(true);
    expect(features.hasIpHost).toBe(false);
    expect(features.hasAtSymbol).toBe(false);
    expect(features.hasPunycode).toBe(false);
  });
});

describe('risk scoring', () => {
  it('returns LOW for no findings', () => {
    const result = calculateRisk([]);
    expect(result.score).toBe(0);
    expect(result.level).toBe('LOW');
  });

  it('returns a higher risk when multiple findings are present', () => {
    const url = new URL('http://127.0.0.1/login@foo.zip');
    const findings = findingsFromUrlFeatures(extractUrlFeatures(url));
    const result = calculateRisk(findings);

    expect(findings.length).toBeGreaterThan(0);
    expect(result.score).toBeGreaterThan(0);
    expect(result.findings).toEqual(findings);
  });

  it('caps the score at 100', () => {
    const findings = Array.from({ length: 20 }, (_, index) => ({
      id: `finding-${index}`,
      label: 'Synthetic finding',
      severity: 5 as const,
      weight: 20,
      description: 'Test finding',
    }));

    expect(calculateRisk(findings).score).toBe(100);
  });
});
