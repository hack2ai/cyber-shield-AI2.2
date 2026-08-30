import fs from 'node:fs';
import path from 'node:path';
import type { EnrichedUrlAnalysisResult } from './enriched-analyzer.js';

export interface StoredAnalysis {
  id: string;
  url: string;
  status: 'safe' | 'suspicious' | 'phishing' | 'malicious';
  score: number;
  threatType: string;
  createdAt: string;
}

const MAX_ANALYSIS_HISTORY = 5000;
const dataDirectory = path.join(process.cwd(), 'data');
const storageFile = path.join(dataDirectory, 'analysis-history.json');

function loadAnalyses(): StoredAnalysis[] {
  try {
    if (!fs.existsSync(storageFile)) return [];

    const raw = fs.readFileSync(storageFile, 'utf8');
    if (!raw.trim()) return [];

    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];

    const valid = parsed.filter((item): item is StoredAnalysis => {
      if (!item || typeof item !== 'object') return false;
      const value = item as Record<string, unknown>;
      return (
        typeof value.id === 'string' &&
        typeof value.url === 'string' &&
        typeof value.status === 'string' &&
        typeof value.score === 'number' &&
        typeof value.threatType === 'string' &&
        typeof value.createdAt === 'string'
      );
    });

    return valid.slice(-MAX_ANALYSIS_HISTORY);
  } catch (error) {
    console.error('Failed to load analysis history:', error);
    return [];
  }
}

let analyses: StoredAnalysis[] = loadAnalyses();

function persistAnalyses(): void {
  try {
    fs.mkdirSync(dataDirectory, { recursive: true });
    const temporaryFile = `${storageFile}.tmp`;
    fs.writeFileSync(temporaryFile, `${JSON.stringify(analyses, null, 2)}\n`, 'utf8');
    fs.renameSync(temporaryFile, storageFile);
  } catch (error) {
    console.error('Failed to persist analysis history:', error);
  }
}

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
  if (analyses.length > MAX_ANALYSIS_HISTORY) {
    analyses = analyses.slice(-MAX_ANALYSIS_HISTORY);
  }
  persistAnalyses();
  return entry;
}

export function getAllAnalyses(): StoredAnalysis[] {
  return [...analyses];
}

export function clearAnalyses(): void {
  analyses = [];
  persistAnalyses();
}
