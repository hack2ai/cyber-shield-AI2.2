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
const MAX_FINDING_WEIGHT = 40;
const MAX_CONFIDENCE = 98;
const BASE_CONFIDENCE = 45;

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}

/**
 * Deterministic and explainable risk aggregation.
 * Duplicate finding IDs are collapsed so repeated evidence cannot inflate risk.
 * A single finding is capped, while corroborating findings can increase the score.
 */
export function calculateRisk(findings: SecurityFinding[]): RiskAssessment {
  const unique = new Map<string, SecurityFinding>();
  for (const finding of findings) {
    const normalizedWeight = clamp(Number.isFinite(finding.weight) ? finding.weight : 0, 0, MAX_FINDING_WEIGHT);
    const current = unique.get(finding.id);
    if (!current || normalizedWeight > current.weight) {
      unique.set(finding.id, { ...finding, weight: normalizedWeight });
    }
  }

  const normalizedFindings = [...unique.values()];
  const totalWeight = normalizedFindings.reduce((sum, finding) => sum + finding.weight, 0);

  const severity5 = normalizedFindings.filter((finding) => finding.severity === 5).length;
  const severity4Plus = normalizedFindings.filter((finding) => finding.severity >= 4).length;
  const corroborationBonus = Math.min(12, Math.max(0, severity4Plus - 1) * 3 + Math.max(0, normalizedFindings.length - 2));
  const criticalEvidenceBonus = severity5 > 0 ? Math.min(10, severity5 * 2) : 0;

  const score = clamp(Math.round(totalWeight + corroborationBonus + criticalEvidenceBonus), 0, MAX_SCORE);

  const level: RiskLevel =
    score >= 80 ? 'CRITICAL' :
    score >= 60 ? 'HIGH' :
    score >= 30 ? 'MEDIUM' :
    'LOW';

  const evidenceConfidence = Math.min(35, normalizedFindings.length * 5);
  const corroborationConfidence = Math.min(18, Math.max(0, severity4Plus - 1) * 6);
  const confidence = clamp(
    Math.round(BASE_CONFIDENCE + evidenceConfidence + corroborationConfidence),
    0,
    MAX_CONFIDENCE,
  );

  return {
    score,
    level,
    confidence,
    findings: normalizedFindings,
  };
}
