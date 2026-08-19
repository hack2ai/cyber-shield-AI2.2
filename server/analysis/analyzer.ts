import { extractUrlFeatures, findingsFromUrlFeatures } from './features.js';
import { calculateRisk } from './scoring.js';
import type { UrlAnalysisResult } from './types.js';

/**
 * Runs the deterministic local analysis layer.
 * Network enrichment (DNS/TLS/WHOIS/VirusTotal/Puppeteer) can be composed
 * around this function without coupling the scoring engine to transport code.
 */
export function analyzeUrl(input: string | URL): UrlAnalysisResult {
  const url = input instanceof URL ? input : new URL(input.trim());
  const features = extractUrlFeatures(url);
  const findings = findingsFromUrlFeatures(features);
  const assessment = calculateRisk(findings);

  return {
    url: url.href,
    normalizedUrl: url.href,
    features,
    findings,
    assessment,
    generatedAt: new Date().toISOString(),
  };
}
