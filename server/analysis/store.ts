import type { EnrichedUrlAnalysisResult } from './enriched-analyzer.js';

export interface StoredAnalysis {
  id: string;
  url: string;
  status: 'safe' | 'suspicious' | 'phishing' | 'malicious';
  score: number;
  threatType: string;
  createdAt: string;
}

const analyses: StoredAnalysis[] = [];

function statusFromRisk(level: EnrichedUrlAnalysisResult['assessment']['level']): StoredAnalysis['status'] {
  switch (level) {
    case 'CRITICAL':
      return 'malicious';
    case 'HIGH':
      return 'phishing';
    case 'MEDIUM':
      return 'suspicious';
    case 'LOW':
    default:
      return 'safe';
  }
}

function threatTypeFromResult(result: EnrichedUrlAnalysisResult): string {
  const firstFinding = result.findings[0]?.label?.trim();
  return firstFinding || result.assessment.level;
}

export function addAnalysis(result: EnrichedUrlAnalysisResult): StoredAnalysis {
  const entry: StoredAnalysis = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    url: result.normalizedUrl || result.url,
    status: statusFromRisk(result.assessment.level),
    score: result.assessment.score,
    threatType: threatTypeFromResult(result),
    createdAt: result.generatedAt || new Date().toISOString(),
  };

  analyses.push(entry);
  return entry;
}

export function getAllAnalyses(): StoredAnalysis[] {
  return [...analyses];
}

export function clearAnalyses(): void {
  analyses.length = 0;
}
