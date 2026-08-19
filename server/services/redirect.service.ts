import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import { validateExternalUrl, isBlockedIp } from '../security/index.js';

export interface RedirectHop {
  url: string;
  status: number;
  location: string | null;
}

export interface RedirectAnalysisResult {
  originalUrl: string;
  finalUrl: string;
  hops: RedirectHop[];
  redirectCount: number;
  hostnameChanged: boolean;
  timedOut: boolean;
  error?: string;
}

export interface RedirectRequestResult {
  status: number;
  location: string | null;
}

export type RedirectRequester = (url: URL, ip: string, family: 4 | 6) => Promise<RedirectRequestResult>;

const REQUEST_TIMEOUT_MS = 8000;
const MAX_REDIRECTS = 5;

async function resolvePinnedAddress(hostname: string): Promise<{ address: string; family: 4 | 6 }> {
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  const safe = records.find((record) => !isBlockedIp(record.address));
  if (!safe || (safe.family !== 4 && safe.family !== 6)) {
    throw new Error('Destination did not resolve to a public address');
  }
  return { address: safe.address, family: safe.family };
}

export function requestRedirectHead(url: URL, ip: string, family: 4 | 6): Promise<RedirectRequestResult> {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http;
    const request = transport.request({
      protocol: url.protocol,
      hostname: url.hostname,
      port: url.port || undefined,
      path: `${url.pathname}${url.search}`,
      method: 'HEAD',
      headers: {
        host: url.host,
        'user-agent': 'Cyber-Shield-AI-Security-Scanner/1.0',
        connection: 'close',
      },
      lookup: (_hostname, _options, callback) => callback(null, ip, family),
      servername: url.hostname,
      rejectUnauthorized: true,
    }, (response) => {
      response.resume();
      resolve({
        status: response.statusCode ?? 0,
        location: response.headers.location ?? null,
      });
    });

    request.setTimeout(REQUEST_TIMEOUT_MS, () => {
      request.destroy(new Error('Redirect analysis timed out'));
    });
    request.once('error', reject);
    request.end();
  });
}

/**
 * Analyze redirect chains while pinning each request to a freshly resolved public IP.
 * Redirect destinations are validated and resolved again before each subsequent hop.
 */
export async function analyzeRedirects(
  input: string | URL,
  request: RedirectRequester = requestRedirectHead,
): Promise<RedirectAnalysisResult> {
  const original = await validateExternalUrl(input instanceof URL ? input.href : input);
  const hops: RedirectHop[] = [];
  let current = original;
  let timedOut = false;

  try {
    for (let i = 0; i <= MAX_REDIRECTS; i += 1) {
      const pinned = await resolvePinnedAddress(current.hostname);
      const response = await request(current, pinned.address, pinned.family);

      hops.push({
        url: current.href,
        status: response.status,
        location: response.location,
      });

      if (!response.location || response.status < 300 || response.status >= 400) {
        break;
      }

      current = await validateExternalUrl(new URL(response.location, current.href).href);
    }
  } catch (error) {
    timedOut = error instanceof Error && error.message === 'Redirect analysis timed out';
    return {
      originalUrl: original.href,
      finalUrl: current.href,
      hops,
      redirectCount: Math.max(0, hops.length - 1),
      hostnameChanged: new URL(original.href).hostname !== new URL(current.href).hostname,
      timedOut,
      error: timedOut ? 'Redirect analysis timed out' : error instanceof Error ? error.message : 'Redirect analysis failed',
    };
  }

  return {
    originalUrl: original.href,
    finalUrl: current.href,
    hops,
    redirectCount: Math.max(0, hops.length - 1),
    hostnameChanged: new URL(original.href).hostname !== new URL(current.href).hostname,
    timedOut,
  };
}
