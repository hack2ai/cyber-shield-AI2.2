import type { SecurityFinding } from './scoring.js';

export interface UrlFeatures {
  isHttps: boolean;
  urlLength: number;
  hostnameLength: number;
  hasIpHost: boolean;
  hasAtSymbol: boolean;
  hasPunycode: boolean;
  subdomainCount: number;
  hasShortenerPattern: boolean;
  hasSuspiciousTld: boolean;
}

const SHORTENERS = new Set(['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'cutt.ly']);
const SUSPICIOUS_TLDS = new Set(['zip', 'mov', 'click', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq']);

export function extractUrlFeatures(input: URL): UrlFeatures {
  const hostname = input.hostname.toLowerCase();
  const labels = hostname.split('.').filter(Boolean);
  const tld = labels.at(-1) ?? '';

  return {
    isHttps: input.protocol === 'https:',
    urlLength: input.href.length,
    hostnameLength: hostname.length,
    hasIpHost: /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname),
    hasAtSymbol: input.href.includes('@'),
    hasPunycode: labels.some((label) => label.startsWith('xn--')),
    subdomainCount: Math.max(0, labels.length - 2),
    hasShortenerPattern: SHORTENERS.has(hostname),
    hasSuspiciousTld: SUSPICIOUS_TLDS.has(tld),
  };
}

export function findingsFromUrlFeatures(features: UrlFeatures): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  if (!features.isHttps) {
    findings.push({ id: 'no-https', label: 'No HTTPS', severity: 3, weight: 15, description: 'The URL does not use HTTPS.' });
  }
  if (features.hasIpHost) {
    findings.push({ id: 'ip-host', label: 'IP address host', severity: 4, weight: 25, description: 'The destination uses a raw IP address instead of a domain name.' });
  }
  if (features.hasAtSymbol) {
    findings.push({ id: 'at-symbol', label: '@ symbol in URL', severity: 4, weight: 20, description: 'The URL contains an @ delimiter that can obscure the actual destination.' });
  }
  if (features.hasPunycode) {
    findings.push({ id: 'punycode', label: 'Punycode hostname', severity: 3, weight: 15, description: 'The hostname contains an internationalized/punycode label.' });
  }
  if (features.hasShortenerPattern) {
    findings.push({ id: 'shortener', label: 'URL shortener', severity: 2, weight: 10, description: 'The hostname is a known URL-shortening service.' });
  }
  if (features.hasSuspiciousTld) {
    findings.push({ id: 'suspicious-tld', label: 'Suspicious TLD', severity: 3, weight: 15, description: 'The top-level domain is commonly associated with abuse reports.' });
  }
  if (features.urlLength > 180) {
    findings.push({ id: 'long-url', label: 'Unusually long URL', severity: 2, weight: 8, description: 'The URL is unusually long and may contain obfuscated parameters.' });
  }
  if (features.subdomainCount >= 4) {
    findings.push({ id: 'deep-subdomains', label: 'Deep subdomain chain', severity: 2, weight: 8, description: 'The hostname contains an unusually deep subdomain structure.' });
  }

  return findings;
}
