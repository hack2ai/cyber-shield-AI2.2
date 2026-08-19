import dns from 'node:dns/promises';

export interface DnsAnalysisResult {
  hostname: string;
  ipv4: string[];
  ipv6: string[];
  cname: string[];
  mx: Array<{ exchange: string; priority: number }>;
  txt: string[][];
  errors: string[];
}

const DNS_TIMEOUT_MS = 5000;

async function withTimeout<T>(promise: Promise<T>, label: string): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} lookup timed out`)), DNS_TIMEOUT_MS);
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function analyzeDns(hostname: string): Promise<DnsAnalysisResult> {
  const normalized = hostname.trim().toLowerCase().replace(/\.$/, '');
  if (!normalized || normalized.length > 253) {
    throw new Error('Invalid hostname');
  }

  const result: DnsAnalysisResult = {
    hostname: normalized,
    ipv4: [],
    ipv6: [],
    cname: [],
    mx: [],
    txt: [],
    errors: [],
  };

  const lookups: Array<[string, () => Promise<unknown>, (value: unknown) => void]> = [
    ['A', () => dns.resolve4(normalized), (value) => { result.ipv4 = value as string[]; }],
    ['AAAA', () => dns.resolve6(normalized), (value) => { result.ipv6 = value as string[]; }],
    ['CNAME', () => dns.resolveCname(normalized), (value) => { result.cname = value as string[]; }],
    ['MX', () => dns.resolveMx(normalized), (value) => { result.mx = value as DnsAnalysisResult['mx']; }],
    ['TXT', () => dns.resolveTxt(normalized), (value) => { result.txt = value as string[][]; }],
  ];

  await Promise.all(lookups.map(async ([type, lookup, assign]) => {
    try {
      assign(await withTimeout(lookup(), `${type} DNS`));
    } catch (error) {
      result.errors.push(`${type}: ${error instanceof Error ? error.message : 'lookup failed'}`);
    }
  }));

  return result;
}
