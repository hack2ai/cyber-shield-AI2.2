import { env } from '../config/env.js';

export interface VirusTotalStats {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout: boolean;
  status: 'ok' | 'unavailable' | 'not-configured' | 'error';
  error?: string;
}

const VT_BASE_URL = 'https://www.virustotal.com/api/v3';
const REQUEST_TIMEOUT_MS = 8000;

function emptyStats(status: VirusTotalStats['status'], error?: string): VirusTotalStats {
  return {
    malicious: 0,
    suspicious: 0,
    harmless: 0,
    undetected: 0,
    timeout: false,
    status,
    ...(error ? { error } : {}),
  };
}

async function getJson<T>(url: string): Promise<T> {
  if (!env.virusTotalApiKey) {
    throw new Error('VirusTotal API key is not configured');
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'x-apikey': env.virusTotalApiKey,
        accept: 'application/json',
      },
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(`VirusTotal API responded with HTTP ${response.status}`);
    }

    return await response.json() as T;
  } finally {
    clearTimeout(timer);
  }
}

interface VirusTotalResponse {
  data?: {
    attributes?: {
      last_analysis_stats?: Partial<Record<keyof Pick<VirusTotalStats, 'malicious' | 'suspicious' | 'harmless' | 'undetected'>, number>>;
    };
  };
}

export async function getDomainReputation(domain: string): Promise<VirusTotalStats> {
  const normalized = domain.trim().toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
  if (!normalized || normalized.length > 253 || normalized.includes('/')) {
    return emptyStats('error', 'Invalid domain');
  }

  if (!env.virusTotalApiKey) {
    return emptyStats('not-configured');
  }

  try {
    const result = await getJson<VirusTotalResponse>(
      `${VT_BASE_URL}/domains/${encodeURIComponent(normalized)}`,
    );
    const stats = result.data?.attributes?.last_analysis_stats ?? {};

    return {
      malicious: Number(stats.malicious ?? 0),
      suspicious: Number(stats.suspicious ?? 0),
      harmless: Number(stats.harmless ?? 0),
      undetected: Number(stats.undetected ?? 0),
      timeout: false,
      status: 'ok',
    };
  } catch (error) {
    const timeout = error instanceof DOMException && error.name === 'AbortError';
    return {
      ...emptyStats(timeout ? 'unavailable' : 'error', timeout ? 'VirusTotal request timed out' : error instanceof Error ? error.message : 'VirusTotal request failed'),
      timeout,
    };
  }
}
