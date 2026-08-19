import { analyzeUrl, type UrlAnalysisResult } from './index.js';
import { collectThreatIntelligence, type ThreatIntelligenceResult } from '../services/threat-intelligence.service.js';
import { analyzeRedirects, type RedirectAnalysisResult } from '../services/redirect.service.js';
import { calculateRisk, type SecurityFinding } from './scoring.js';

export interface EnrichedUrlAnalysisResult extends UrlAnalysisResult {
  threatIntelligence: ThreatIntelligenceResult;
  redirects: RedirectAnalysisResult;
}

function intelligenceFindings(intel: ThreatIntelligenceResult): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const malicious = intel.virusTotal.malicious;
  const suspicious = intel.virusTotal.suspicious;

  if (malicious > 0) {
    findings.push({ id: 'vt-malicious', label: 'VirusTotal malicious detections', severity: 5, weight: Math.min(40, 25 + malicious * 2), description: `${malicious} VirusTotal engines reported the domain as malicious.` });
  }
  if (suspicious > 0) {
    findings.push({ id: 'vt-suspicious', label: 'VirusTotal suspicious detections', severity: 3, weight: Math.min(20, 8 + suspicious), description: `${suspicious} VirusTotal engines reported suspicious activity.` });
  }
  if (intel.tls.error) {
    findings.push({ id: 'tls-error', label: 'TLS connection issue', severity: 3, weight: 8, description: intel.tls.error });
  }
  if (!intel.tls.authorized && !intel.tls.error && intel.tls.validTo) {
    findings.push({ id: 'tls-unauthorized', label: 'Certificate not authorized', severity: 4, weight: 15, description: 'The TLS certificate chain was not authorized by the local trust store.' });
  }
  if (intel.whois.createdAt) {
    const created = Date.parse(intel.whois.createdAt);
    const ageDays = Number.isNaN(created) ? null : Math.floor((Date.now() - created) / 86_400_000);
    if (ageDays !== null && ageDays >= 0 && ageDays < 30) {
      findings.push({ id: 'new-domain', label: 'Recently registered domain', severity: 4, weight: 18, description: `WHOIS indicates the domain is approximately ${ageDays} days old.` });
    }
  }
  if (intel.dns.errors.length > 0) {
    findings.push({ id: 'dns-errors', label: 'DNS resolution anomalies', severity: 2, weight: 5, description: `${intel.dns.errors.length} DNS lookups failed or timed out.` });
  }
  return findings;
}

function redirectFindings(redirects: RedirectAnalysisResult): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  if (redirects.redirectCount >= 3) {
    findings.push({ id: 'many-redirects', label: 'Multiple redirects', severity: 3, weight: Math.min(15, 5 + redirects.redirectCount * 2), description: `The URL followed ${redirects.redirectCount} redirects.` });
  }
  if (redirects.hostnameChanged) {
    findings.push({ id: 'cross-domain-redirect', label: 'Cross-domain redirect', severity: 3, weight: 10, description: 'The URL redirected to a different hostname.' });
  }
  if (redirects.timedOut) {
    findings.push({ id: 'redirect-timeout', label: 'Redirect analysis timeout', severity: 2, weight: 4, description: 'Redirect analysis exceeded the configured timeout.' });
  }
  if (redirects.error && !redirects.timedOut) {
    findings.push({ id: 'redirect-error', label: 'Redirect analysis issue', severity: 2, weight: 4, description: redirects.error });
  }
  return findings;
}

/** Combines deterministic URL checks, threat intelligence, and redirect evidence. */
export async function analyzeUrlEnriched(input: string | URL): Promise<EnrichedUrlAnalysisResult> {
  const base = analyzeUrl(input);
  const safeUrl = new URL(base.normalizedUrl);
  const hostname = safeUrl.hostname;
  const [threatIntelligence, redirects] = await Promise.all([
    collectThreatIntelligence(hostname),
    analyzeRedirects(safeUrl),
  ]);

  const combinedFindings = [
    ...base.findings,
    ...intelligenceFindings(threatIntelligence),
    ...redirectFindings(redirects),
  ];

  return {
    ...base,
    findings: combinedFindings,
    assessment: calculateRisk(combinedFindings),
    threatIntelligence,
    redirects,
  };
}
