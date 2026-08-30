import { getAllAnalyses } from '../analysis/store.js';

export interface DashboardStats {
  totalScans: number;
  safeUrls: number;
  maliciousUrls: number;
  averageRisk: number;
  threatDistribution: { name: string; value: number }[];
  recentScans: {
    url: string;
    status: string;
    score: number;
    date: string;
  }[];
}

function sanitizeDashboardUrl(value: string): string {
  try {
    const url = new URL(value);
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.toString();
  } catch {
    return '[redacted]';
  }
}

export function getDashboardStats(): DashboardStats {
  const scans = getAllAnalyses();
  const totalScans = scans.length;
  const safeUrls = scans.filter((item) => item.status === 'safe').length;
  const maliciousUrls = scans.filter(
    (item) => item.status === 'malicious' || item.status === 'phishing'
  ).length;

  const averageRisk = totalScans === 0
    ? 0
    : Math.round(scans.reduce((total, item) => total + item.score, 0) / totalScans);

  const threats: Record<string, number> = {};
  for (const item of scans) {
    const type = item.threatType || item.status || 'Unknown';
    threats[type] = (threats[type] || 0) + 1;
  }

  const threatDistribution = Object.entries(threats).map(([name, value]) => ({ name, value }));

  const recentScans = [...scans]
    .sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt))
    .slice(0, 10)
    .map((item) => ({
      url: sanitizeDashboardUrl(item.url),
      status: item.status,
      score: item.score,
      date: item.createdAt,
    }));

  return {
    totalScans,
    safeUrls,
    maliciousUrls,
    averageRisk,
    threatDistribution,
    recentScans,
  };
}
