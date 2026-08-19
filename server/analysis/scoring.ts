export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface SecurityFinding {
  id: string;
  label: string;
  severity: 1 | 2 | 3 | 4 | 5;
  weight: number;
  description: string;
}

export interface RiskAssessment {
  score: number;
  level: RiskLevel;
  confidence: number;
  findings: SecurityFinding[];
}

const MAX_SCORE = 100;

/**
 * Deterministic, explainable risk aggregation. AI output can enrich the report,
 * but the baseline score remains reproducible from security evidence.
 */
export function calculateRisk(findings: SecurityFinding[]): RiskAssessment {
  const totalWeight = findings.reduce((sum, finding) => sum + Math.max(0, finding.weight), 0);
  const rawScore = Math.min(MAX_SCORE, Math.round(totalWeight));
  const score = Math.max(0, rawScore);

  const level: RiskLevel =
    score >= 80 ? 'CRITICAL' :
    score >= 60 ? 'HIGH' :
    score >= 30 ? 'MEDIUM' :
    'LOW';

  const evidenceCount = findings.length;
  const confidence = Math.min(98, Math.round(45 + Math.min(45, evidenceCount * 8)));

  return { score, level, confidence, findings };
}
