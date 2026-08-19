import type { RiskAssessment, SecurityFinding } from './scoring.js';
import type { UrlFeatures } from './features.js';

export interface UrlAnalysisResult {
  url: string;
  normalizedUrl: string;
  features: UrlFeatures;
  findings: SecurityFinding[];
  assessment: RiskAssessment;
  generatedAt: string;
}
