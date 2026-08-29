import type { AnalysisResult as ApiAnalysisResult, SecurityFinding as ApiFinding } from './analysis-api';

export type LegacyClassification = 'Safe' | 'Suspicious' | 'Phishing' | 'Malicious';

export interface LegacyAnalysisResult {
  threatScore: number;
  classification: LegacyClassification;
  explanation: string;
  recommendation: string;
  riskIndicators: string[];
  type?: 'url' | 'ip' | 'email' | 'domain' | 'keyword' | 'phone' | 'message';
  target?: string;
  brandImpersonated?: string;
  visualIndicators?: string[];
  technicalSummary: {
    dns: string;
    ssl: string;
    whois: string;
    threatIntel: string;
  };
  raw: {
    dns: Record<string, unknown>;
    ssl: Record<string, unknown>;
    ct: unknown[];
    whois: Record<string, unknown>;
    heuristics: Record<string, unknown>;
  };
}

function classificationFromLevel(level: ApiAnalysisResult['assessment']['level']): LegacyClassification {
  switch (level) {
    case 'CRITICAL': return 'Malicious';
    case 'HIGH': return 'Phishing';
    case 'MEDIUM': return 'Suspicious';
    default: return 'Safe';
  }
}

function findingToText(finding: ApiFinding): string {
  return `${finding.label}: ${finding.description}`;
}

export function adaptAnalysisResult(result: ApiAnalysisResult): LegacyAnalysisResult {
  const { assessment, threatIntelligence, redirects } = result;
  const findings = assessment.findings.length > 0 ? assessment.findings : result.findings;

  const riskIndicators = findings.map((finding) => findingToText(finding));
  if (redirects.redirectCount > 0) {
    riskIndicators.push(`REDIRECT_CHAIN: ${redirects.redirectCount} redirect(s)`);
  }
  if (redirects.hostnameChanged) {
    riskIndicators.push('CROSS_DOMAIN_REDIRECT: final hostname differs from original hostname');
  }

  const recommendation = assessment.level === 'CRITICAL' || assessment.level === 'HIGH'
    ? 'Do not submit credentials or sensitive information. Block or report the destination and investigate the supporting evidence.'
    : assessment.level === 'MEDIUM'
      ? 'Exercise caution and verify the destination through an independent trusted channel before sharing sensitive information.'
      : 'No high-confidence malicious indicators were identified by the current analysis. Continue normal security hygiene.';

  const explanation = findings.length === 0
    ? `No suspicious findings were recorded for ${result.normalizedUrl}. The result is based on deterministic analysis and available threat-intelligence evidence.`
    : `The analysis produced ${findings.length} security finding(s). The current risk assessment is ${assessment.level} with ${assessment.confidence}% confidence.`;

  return {
    threatScore: assessment.score,
    classification: classificationFromLevel(assessment.level),
    explanation,
    recommendation,
    riskIndicators,
    type: 'url',
    target: result.normalizedUrl,
    brandImpersonated: 'None',
    visualIndicators: [],
    technicalSummary: {
      dns: `${threatIntelligence.dns.ipv4.length + threatIntelligence.dns.ipv6.length} IP address(es) resolved; ${threatIntelligence.dns.errors.length} DNS error(s).`,
      ssl: threatIntelligence.tls.error
        ? `TLS analysis error: ${threatIntelligence.tls.error}`
        : `${threatIntelligence.tls.protocol ?? 'Unknown protocol'}; certificate ${threatIntelligence.tls.authorized ? 'authorized' : 'not authorized'}.`,
      whois: threatIntelligence.whois.createdAt
        ? `Registered ${threatIntelligence.whois.createdAt}${threatIntelligence.whois.registrar ? ` via ${threatIntelligence.whois.registrar}` : ''}.`
        : 'WHOIS registration date unavailable.',
      threatIntel: `VirusTotal: ${threatIntelligence.virusTotal.malicious} malicious, ${threatIntelligence.virusTotal.suspicious} suspicious, status ${threatIntelligence.virusTotal.status}. Redirects: ${redirects.redirectCount}.`,
    },
    raw: {
      dns: {
        hostname: threatIntelligence.dns.hostname,
        ipv4Count: threatIntelligence.dns.ipv4.length,
        ipv6Count: threatIntelligence.dns.ipv6.length,
        errorCount: threatIntelligence.dns.errors.length,
      },
      ssl: {
        hostname: threatIntelligence.tls.hostname,
        port: threatIntelligence.tls.port,
        authorized: threatIntelligence.tls.authorized,
        protocol: threatIntelligence.tls.protocol,
        error: threatIntelligence.tls.error,
      },
      ct: [],
      whois: {
        domain: threatIntelligence.whois.domain,
        registrar: threatIntelligence.whois.registrar,
        createdAt: threatIntelligence.whois.createdAt,
        expiresAt: threatIntelligence.whois.expiresAt,
        updatedAt: threatIntelligence.whois.updatedAt,
      },
      heuristics: {
        redirectCount: redirects.redirectCount,
        hostnameChanged: redirects.hostnameChanged,
      },
    },
  };
}
