import whois from 'whois-json';

export interface WhoisAnalysisResult {
  domain: string;
  registrar: string | null;
  createdAt: string | null;
  expiresAt: string | null;
  updatedAt: string | null;
  nameServers: string[];
  rawAvailable: boolean;
  error?: string;
}

const WHOIS_TIMEOUT_MS = 10000;

function firstString(value: unknown): string | null {
  if (typeof value === 'string' && value.trim()) return value.trim();
  if (Array.isArray(value)) {
    const item = value.find((entry) => typeof entry === 'string' && entry.trim().length > 0);
    return typeof item === 'string' ? item.trim() : null;
  }
  return null;
}

function firstDate(value: unknown): string | null {
  const text = firstString(value);
  if (!text) return null;
  const timestamp = Date.parse(text);
  return Number.isNaN(timestamp) ? text : new Date(timestamp).toISOString();
}

function stringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value
      .filter((item): item is string => typeof item === 'string' && item.trim().length > 0)
      .map((item) => item.trim());
  }
  const single = firstString(value);
  return single ? [single] : [];
}

export async function analyzeWhois(domain: string): Promise<WhoisAnalysisResult> {
  const normalized = domain.trim().toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
  if (!normalized || normalized.length > 253 || normalized.includes('/')) {
    throw new Error('Invalid WHOIS domain');
  }

  try {
    const lookup = whois(normalized) as Promise<Record<string, unknown>>;
    const data = await Promise.race([
      lookup,
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('WHOIS lookup timed out')), WHOIS_TIMEOUT_MS)),
    ]);

    return {
      domain: normalized,
      registrar: firstString(data.registrar ?? data.registrarName ?? data.registryDomainName),
      createdAt: firstDate(data.creationDate ?? data.createdDate ?? data.registeredOn),
      expiresAt: firstDate(data.expirationDate ?? data.expiryDate ?? data.registryExpiryDate),
      updatedAt: firstDate(data.updatedDate ?? data.lastUpdatedDate),
      nameServers: stringArray(data.nameServer ?? data.nameServers ?? data.nserver),
      rawAvailable: Object.keys(data).length > 0,
    };
  } catch (error) {
    return {
      domain: normalized,
      registrar: null,
      createdAt: null,
      expiresAt: null,
      updatedAt: null,
      nameServers: [],
      rawAvailable: false,
      error: error instanceof Error ? error.message : 'WHOIS lookup failed',
    };
  }
}
