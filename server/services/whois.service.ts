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
const MAX_CONCURRENT_WHOIS = 8;
const MAX_QUEUED_WHOIS = 32;
let activeWhois = 0;
const whoisQueue: Array<() => void> = [];

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

async function runWithWhoisSlot<T>(operation: () => Promise<T>): Promise<T> {
  if (activeWhois >= MAX_CONCURRENT_WHOIS && whoisQueue.length >= MAX_QUEUED_WHOIS) {
    throw new Error('WHOIS lookup capacity is temporarily exhausted');
  }

  await new Promise<void>((resolve) => {
    if (activeWhois < MAX_CONCURRENT_WHOIS) {
      activeWhois += 1;
      resolve();
      return;
    }
    whoisQueue.push(() => {
      activeWhois += 1;
      resolve();
    });
  });

  try {
    return await operation();
  } finally {
    activeWhois -= 1;
    const next = whoisQueue.shift();
    if (next) next();
  }
}

async function lookupWhois(domain: string): Promise<Record<string, unknown>> {
  return runWithWhoisSlot(async () => {
    const lookup = whois(domain) as Promise<Record<string, unknown>>;
    let timer: NodeJS.Timeout | undefined;
    try {
      return await Promise.race([
        lookup,
        new Promise<never>((_, reject) => {
          timer = setTimeout(() => reject(new Error('WHOIS lookup timed out')), WHOIS_TIMEOUT_MS);
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
    }
  });
}

export async function analyzeWhois(domain: string): Promise<WhoisAnalysisResult> {
  const normalized = domain.trim().toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
  if (!normalized || normalized.length > 253 || normalized.includes('/')) {
    throw new Error('Invalid WHOIS domain');
  }

  try {
    const data = await lookupWhois(normalized);

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
