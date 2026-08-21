interface DashboardRecentScan {
  url: string;
  status: string;
  score: number;
  date: string;
}

interface DashboardStats {
  totalScans: number;
  safeUrls: number;
  maliciousUrls: number;
  averageRisk: number;
  threatDistribution: Array<{ name: string; value: number }>;
  recentScans: DashboardRecentScan[];
}

function getBaseUrl(): string {
  const configured = import.meta.env.VITE_ANALYSIS_API_BASE_URL?.trim();
  if (configured) return configured.replace(/\/$/, '');

  // The local API binds to IPv4. Using localhost can resolve to ::1 on Windows,
  // where another listener may answer or reject the request.
  if (typeof window !== 'undefined' && window.location.hostname === 'localhost') {
    return 'http://127.0.0.1:3000';
  }

  if (typeof window !== 'undefined') {
    return `${window.location.protocol}//${window.location.hostname}:3000`;
  }

  return 'http://127.0.0.1:3000';
}

function toLegacyClassification(status: string): 'Safe' | 'Suspicious' | 'Phishing' | 'Malicious' {
  switch (status.toLowerCase()) {
    case 'malicious':
      return 'Malicious';
    case 'phishing':
      return 'Phishing';
    case 'suspicious':
      return 'Suspicious';
    default:
      return 'Safe';
  }
}

function buildMockScanReports(stats: DashboardStats): unknown[] {
  const reports = stats.recentScans.map((scan) => ({
    classification: toLegacyClassification(scan.status),
    target: scan.url,
    threatScore: scan.score,
    createdAt: scan.date,
  }));

  const representedSafe = reports.filter((report: any) => report.classification === 'Safe').length;
  const representedMalicious = reports.filter((report: any) =>
    report.classification === 'Malicious' || report.classification === 'Phishing'
  ).length;

  const missingSafe = Math.max(0, stats.safeUrls - representedSafe);
  const missingMalicious = Math.max(0, stats.maliciousUrls - representedMalicious);
  const missingTotal = Math.max(0, stats.totalScans - reports.length - missingSafe - missingMalicious);

  for (let index = 0; index < missingSafe; index += 1) {
    reports.push({
      classification: 'Safe',
      target: `stored-safe-scan-${index + 1}`,
      threatScore: 0,
      createdAt: new Date(0).toISOString(),
    });
  }

  for (let index = 0; index < missingMalicious; index += 1) {
    reports.push({
      classification: 'Malicious',
      target: `stored-malicious-scan-${index + 1}`,
      threatScore: 100,
      createdAt: new Date(0).toISOString(),
    });
  }

  for (let index = 0; index < missingTotal; index += 1) {
    reports.push({
      classification: 'Safe',
      target: `stored-scan-${index + 1}`,
      threatScore: 0,
      createdAt: new Date(0).toISOString(),
    });
  }

  return reports;
}

async function fetchDashboardStats(): Promise<DashboardStats> {
  const response = await fetch(`${getBaseUrl()}/api/dashboard/stats`, {
    headers: { accept: 'application/json' },
  });

  if (!response.ok) {
    throw new Error(`Dashboard API failed with HTTP ${response.status}`);
  }

  return response.json() as Promise<DashboardStats>;
}

export async function syncDashboardToLegacyAnalytics(): Promise<void> {
  try {
    const stats = await fetchDashboardStats();
    const reports = buildMockScanReports(stats);

    localStorage.setItem('cyber_shield_mock_scan_reports', JSON.stringify(reports));
    localStorage.setItem('cyber_shield_mock_file_scan_reports', JSON.stringify([]));

    window.dispatchEvent(new Event('cyber_shield_new_report'));
  } catch (error) {
    console.warn('Dashboard API sync unavailable:', error);
  }
}

export function startDashboardSync(intervalMs = 5000): () => void {
  void syncDashboardToLegacyAnalytics();

  const intervalId = window.setInterval(() => {
    void syncDashboardToLegacyAnalytics();
  }, intervalMs);

  return () => window.clearInterval(intervalId);
}
