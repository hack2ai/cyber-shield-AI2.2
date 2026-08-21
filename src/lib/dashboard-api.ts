export interface DashboardRecentScan {
  url: string;
  status: string;
  score: number;
  date: string;
}

export interface DashboardThreatDistribution {
  name: string;
  value: number;
}

export interface DashboardStats {
  totalScans: number;
  safeUrls: number;
  maliciousUrls: number;
  averageRisk: number;
  threatDistribution: DashboardThreatDistribution[];
  recentScans: DashboardRecentScan[];
}

function getApiBaseUrl(): string {
  const configured = import.meta.env.VITE_ANALYSIS_API_BASE_URL?.trim();
  return configured ? configured.replace(/\/$/, '') : '';
}

export async function getDashboardStats(signal?: AbortSignal): Promise<DashboardStats> {
  const response = await fetch(`${getApiBaseUrl()}/api/dashboard/stats`, {
    method: 'GET',
    headers: { accept: 'application/json' },
    signal,
  });

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`Dashboard API returned invalid JSON (HTTP ${response.status})`);
  }

  if (!response.ok) {
    const message = typeof payload === 'object' && payload !== null && 'error' in payload
      ? String((payload as { error?: unknown }).error ?? 'Dashboard request failed')
      : `Dashboard request failed (HTTP ${response.status})`;
    throw new Error(message);
  }

  if (typeof payload !== 'object' || payload === null) {
    throw new Error('Dashboard API returned an invalid response shape');
  }

  const data = payload as Partial<DashboardStats>;
  if (
    typeof data.totalScans !== 'number' ||
    typeof data.safeUrls !== 'number' ||
    typeof data.maliciousUrls !== 'number' ||
    typeof data.averageRisk !== 'number' ||
    !Array.isArray(data.threatDistribution) ||
    !Array.isArray(data.recentScans)
  ) {
    throw new Error('Dashboard API returned an invalid response shape');
  }

  return {
    totalScans: data.totalScans,
    safeUrls: data.safeUrls,
    maliciousUrls: data.maliciousUrls,
    averageRisk: data.averageRisk,
    threatDistribution: data.threatDistribution,
    recentScans: data.recentScans,
  };
}
