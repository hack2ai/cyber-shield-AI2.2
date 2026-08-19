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

export interface DnsResult {
  hostname: string;
  ipv4: string[];
  ipv6: string[];
  cname: string[];
  mx: Array<{ exchange: string; priority: number }>;
  txt: string[][];
  errors: string[];
}

export interface TlsResult {
  hostname: string;
  port: number;
  authorized: boolean;
  protocol: string | null;
  cipher: string | null;
  issuer: Record<string, unknown> | null;
  subject: Record<string, unknown> | null;
  validFrom: string | null;
  validTo: string | null;
  fingerprint256: string | null;
  error?: string;
}

export interface WhoisResult {
  domain: string;
  registrar: string | null;
  createdAt: string | null;
  expiresAt: string | null;
  updatedAt: string | null;
  nameServers: string[];
  rawAvailable: boolean;
  error?: string;
}

export interface VirusTotalResult {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
  timeout: boolean;
  status: 'ok' | 'unavailable' | 'not-configured' | 'error';
  error?: string;
}

export interface ThreatIntelligenceResult {
  hostname: string;
  dns: DnsResult;
  tls: TlsResult;
  whois: WhoisResult;
  virusTotal: VirusTotalResult;
}

export interface RedirectHop {
  url: string;
  status: number;
  location: string | null;
}

export interface RedirectResult {
  originalUrl: string;
  finalUrl: string;
  hops: RedirectHop[];
  redirectCount: number;
  hostnameChanged: boolean;
  timedOut: boolean;
  error?: string;
}

export interface AnalysisResult {
  url: string;
  normalizedUrl: string;
  features: Record<string, unknown>;
  findings: SecurityFinding[];
  assessment: RiskAssessment;
  generatedAt: string;
  threatIntelligence: ThreatIntelligenceResult;
  redirects: RedirectResult;
}

export interface AnalysisSuccessResponse {
  success: true;
  version: 'v1';
  data: AnalysisResult;
}

export interface AnalysisErrorResponse {
  success: false;
  version: 'v1';
  error: { code: string; message: string };
}

export type AnalysisResponse = AnalysisSuccessResponse | AnalysisErrorResponse;

const API_VERSION = 'v1' as const;

function getApiBaseUrl(): string {
  const configured = import.meta.env.VITE_ANALYSIS_API_BASE_URL?.trim();
  return configured ? configured.replace(/\/$/, '') : '';
}

export async function analyzeUrl(url: string, signal?: AbortSignal): Promise<AnalysisResult> {
  const response = await fetch(`${getApiBaseUrl()}/api/analysis`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url }),
    signal,
  });

  let payload: AnalysisResponse;
  try {
    payload = await response.json() as AnalysisResponse;
  } catch {
    throw new Error(`Analysis API returned invalid JSON (HTTP ${response.status})`);
  }

  if (payload.version !== API_VERSION) {
    throw new Error(`Unsupported analysis API version: ${String(payload.version)}`);
  }

  if (!response.ok || !payload.success) {
    throw new Error(payload.success ? `Analysis request failed (HTTP ${response.status})` : payload.error.message);
  }

  return payload.data;
}
