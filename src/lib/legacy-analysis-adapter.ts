import type { AnalysisResult as EnrichedAnalysisResult, RiskLevel } from './analysis-api';

export interface LegacyAnalysisResult {
  threatScore: number;
  classification: 'Safe' | 'Suspicious' | 'Phishing' | 'Malicious';
  explanation: string;
  recommendation: string;
  riskIndicators: string[];
  type: 'url' | 'ip' | 'email' | 'domain';
  target: string;
  brandImpersonated?: string;
  visualIndicators?: string[];
  technicalSummary: {
    dns: string;
    ssl: string;
    whois: string;
    threatIntel: string;
  };
  raw: {
    dns: {
      ips: string[];
      records: {
        mx: Array<{ exchange: string; priority: number }>;
        txt: string[][];
      };
    };
    ssl: {
      authorized: boolean;
      issuer: Record<string, unknown> | null;
      valid_from: string | null;
      valid_to: string | null;
      fingerprint: string | null;
      bits: number;
    };
    ct: unknown[];
    whois: {
      creationDate: string | null;
      expiryDate: string | null;
      registrar: string | null;
    };
    heuristics: Record<string, unknown>;
  };
  enriched: EnrichedAnalysisResult;
}

function classificationFor(level: RiskLevel, score: number): LegacyAnalysisResult['classification'] {
  if (level === 'CRITICAL' || score >= 80) return 'Malicious';
  if (level === 'HIGH' || score >= 60) return 'Phishing';
  if (level === 'MEDIUM' || score >= 30) return 'Suspicious';
  return 'Safe';
}

function buildExplanation(result: EnrichedAnalysisResult, classification: LegacyAnalysisResult['classification']): string {
  if (result.findings.length === 0) {
    return 'The analyzed target did not produce suspicious findings from the current deterministic and threat-intelligence checks.';
  }
  const topFindings = result.findings
    .slice()
    .sort((a, b) => b.severity - a.severity || b.weight - a.weight)
    .slice(0, 3)
    .map((finding) => finding.description);
  return `${classification} risk assessment based on ${result.findings.length} evidence item(s). ${topFindings.join(' ')}`;
}

function buildRecommendation(classification: LegacyAnalysisResult['classification']): string {
  switch (classification) {
    case 'Malicious':
      return 'Do not open or authenticate to this resource. Block or report it according to your security workflow.';
    case 'Phishing':
      return 'Avoid credentials or sensitive-data entry and verify the destination through a trusted channel.';
    case 'Suspicious':
      return 'Treat the destination cautiously and verify its ownership, certificate, and intended purpose before proceeding.';
    default:
      return 'No immediate action is indicated by the current evidence, but the score is not a guarantee of safety.';
  }
}

function buildTechnicalSummary(result: EnrichedAnalysisResult) {
  const { dns, tls, whois, virusTotal } = result.threatIntelligence;
  return {
    dns: `IPv4: ${dns.ipv4.length}; IPv6: ${dns.ipv6.length}; MX: ${dns.mx.length}; DNS issues: ${dns.errors.length}.`,
    ssl: tls.error ? `TLS issue: ${tls.error}` : `Authorized: ${tls.authorized ? 'yes' : 'no'}; Protocol: ${tls.protocol ?? 'unknown'}; Cipher: ${tls.cipher ?? 'unknown'}.`,
    whois: `Registrar: ${whois.registrar ?? 'unavailable'}; Created: ${whois.createdAt ?? 'unavailable'}; Expires: ${whois.expiresAt ?? 'unavailable'}.`,
    threatIntel: `VirusTotal status: ${virusTotal.status}; malicious: ${virusTotal.malicious}; suspicious: ${virusTotal.suspicious}; undetected: ${virusTotal.undetected}.`,
  };
}

export function toLegacyAnalysisResult(result: EnrichedAnalysisResult): LegacyAnalysisResult {
  const score = result.assessment.score;
  const classification = classificationFor(result.assessment.level, score);
  const hostname = result.threatIntelligence.hostname;
  const tls = result.threatIntelligence.tls;
  const whois = result.threatIntelligence.whois;
  const dns = result.threatIntelligence.dns;

  return {
    threatScore: score,
    classification,
    explanation: buildExplanation(result, classification),
    recommendation: buildRecommendation(classification),
    riskIndicators: result.findings.map((finding) => finding.label),
    type: 'url',
    target: result.normalizedUrl,
    technicalSummary: buildTechnicalSummary(result),
    raw: {
      dns: {
        ips: [...dns.ipv4, ...dns.ipv6],
        records: { mx: dns.mx, txt: dns.txt },
      },
      ssl: {
        authorized: tls.authorized,
        issuer: tls.issuer,
        valid_from: tls.validFrom,
        valid_to: tls.validTo,
        fingerprint: tls.fingerprint256,
        bits: 0,
      },
      ct: [],
      whois: {
        creationDate: whois.createdAt,
        expiryDate: whois.expiresAt,
        registrar: whois.registrar,
      },
      heuristics: {
        hostname,
        redirectCount: result.redirects.redirectCount,
        finalUrl: result.redirects.finalUrl,
        hostnameChanged: result.redirects.hostnameChanged,
      },
    },
    enriched: result,
  };
}
