import { describe, expect, it } from 'vitest';
import { calculateRisk } from './scoring.js';
import { extractUrlFeatures, findingsFromUrlFeatures } from './features.js';

describe('URL feature extraction', () => {
  it('detects common suspicious URL indicators', () => {
    const url = new URL('http://xn--e1afmkfd.xn--p1ai/login@account.example.zip');
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

const finding = (id: string, weight: number, severity: 1 | 2 | 3 | 4 | 5 = 2) => ({
  id,
  label: id,
  severity,
  weight,
  description: 'test finding',
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

  it('does not let duplicate finding IDs inflate the score', () => {
    const result = calculateRisk([
      finding('duplicate', 20, 4),
      finding('duplicate', 20, 4),
    ]);

    expect(result.findings).toHaveLength(1);
    expect(result.score).toBeLessThan(50);
  });

  it('caps an individual finding weight at 40', () => {
    const result = calculateRisk([finding('oversized', 500, 5)]);

    expect(result.score).toBeLessThanOrEqual(50);
    expect(result.findings[0].weight).toBe(40);
  });

  it('adds controlled corroboration for multiple high-severity findings', () => {
    const result = calculateRisk([
      finding('high-a', 20, 4),
      finding('high-b', 20, 4),
      finding('low-a', 5, 2),
    ]);

    expect(result.score).toBeGreaterThan(45);
    expect(result.confidence).toBeGreaterThan(45);
  });

  it('reaches CRITICAL only with sufficiently strong combined evidence', () => {
    const findings = [
      finding('malicious-a', 40, 5),
      finding('malicious-b', 40, 5),
      finding('malicious-c', 40, 5),
    ];

    const result = calculateRisk(findings);

    expect(result.score).toBe(100);
    expect(result.level).toBe('CRITICAL');
    expect(result.confidence).toBeGreaterThan(70);
  });

  it('caps the final score at 100', () => {
    const findings = Array.from({ length: 20 }, (_, index) => finding(`finding-${index}`, 40, 5));

    expect(calculateRisk(findings).score).toBe(100);
  });
});
