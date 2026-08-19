import { analyzeUrl, type UrlAnalysisResult } from './index.js';
import { collectThreatIntelligence, type ThreatIntelligenceResult } from '../services/threat-intelligence.service.js';
import { calculateRisk, type SecurityFinding } from './scoring.js';

export interface EnrichedUrlAnalysisResult extends UrlAnalysisResult {
  threatIntelligence: ThreatIntelligenceResult;
}

function intelligenceFindings(intel: ThreatIntelligenceResult): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  const malicious = intel.virusTotal.malicious;
  const suspicious = intel.virusTotal.suspicious;

  if (malicious > 0) {
    findings.push({
      id: 'vt-malicious',
      label: 'VirusTotal malicious detections',
      severity: 5,
      weight: Math.min(40, 25 + malicious * 2),
      description: `${malicious} VirusTotal engines reported the domain as malicious.`,
    });
  }

  if (suspicious > 0) {
    findings.push({
      id: 'vt-suspicious',
      label: 'VirusTotal suspicious detections',
      severity: 3,
      weight: Math.min(20, 8 + suspicious),
      description: `${suspicious} VirusTotal engines reported suspicious activity.`,
    });
  }

  if (intel.tls.error) {
    findings.push({
      id: 'tls-error',
      label: 'TLS connection issue',
      severity: 3,
      weight: 8,
      description: intel.tls.error,
    });
  }

  if (!intel.tls.authorized && !intel.tls.error && intel.tls.validTo) {
    findings.push({
      id: 'tls-unauthorized',
      label: 'Certificate not authorized',
      severity: 4,
      weight: 15,
      description: 'The TLS certificate chain was not authorized by the local trust store.',
    });
  }

  if (intel.whois.createdAt) {
    const created = Date.parse(intel.whois.createdAt);
    const ageDays = Number.isNaN(created) ? null : Math.floor((Date.now() - created) / 86_400_000);
    if (ageDays !== null && ageDays >= 0 && ageDays < 30) {
      findings.push({
        id: 'new-domain',
        label: 'Recently registered domain',
        severity: 4,
        weight: 18,
        description: `WHOIS indicates the domain is approximately ${ageDays} days old.`,
      });
    }
  }

  if (intel.dns.errors.length > 0) {
    findings.push({
      id: 'dns-errors',
      label: 'DNS resolution anomalies',
      severity: 2,
      weight: 5,
      description: `${intel.dns.errors.length} DNS lookups failed or timed out.`,
    });
  }

  return findings;
}

/** Combines deterministic URL features with external security intelligence. */
export async function analyzeUrlEnriched(input: string | URL): Promise<EnrichedUrlAnalysisResult> {
  const base = analyzeUrl(input);
  const hostname = new URL(base.normalizedUrl).hostname;
  const threatIntelligence = await collectThreatIntelligence(hostname);
  const combinedFindings = [...base.findings, ...intelligenceFindings(threatIntelligence)];
  const assessment = calculateRisk(combinedFindings);

  return {
    ...base,
    findings: combinedFindings,
    assessment,
    threatIntelligence,
  };
}
