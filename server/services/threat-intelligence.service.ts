import { analyzeDns, type DnsAnalysisResult } from './dns.service.js';
import { analyzeTls, type TlsAnalysisResult } from './tls.service.js';
import { analyzeWhois, type WhoisAnalysisResult } from './whois.service.js';
import { getDomainReputation, type VirusTotalStats } from './virustotal.service.js';

export interface ThreatIntelligenceResult {
  hostname: string;
  dns: DnsAnalysisResult;
  tls: TlsAnalysisResult;
  whois: WhoisAnalysisResult;
  virusTotal: VirusTotalStats;
}

/**
 * Runs external threat-intelligence providers concurrently.
 * Individual provider failures are captured by each service so one provider
 * does not prevent the rest of the security report from being generated.
 */
export async function collectThreatIntelligence(hostname: string): Promise<ThreatIntelligenceResult> {
  const [dns, tls, whois, virusTotal] = await Promise.all([
    analyzeDns(hostname),
    analyzeTls(hostname),
    analyzeWhois(hostname),
    getDomainReputation(hostname),
  ]);

  return {
    hostname: hostname.trim().toLowerCase().replace(/\.$/, ''),
    dns,
    tls,
    whois,
    virusTotal,
  };
}
