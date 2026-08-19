/**
 * Defensive URL validation for server-side fetchers.
 * Rejects non-web schemes and destinations that commonly represent
 * local/private infrastructure or cloud metadata services.
 */
import dns from 'node:dns/promises';
import net from 'node:net';

const BLOCKED_HOSTNAMES = new Set([
  'localhost',
  'localhost.localdomain',
  'metadata.google.internal',
  'metadata.google.com',
  'instance-data.ec2.internal',
]);

function isPrivateIPv4(address: string): boolean {
  const parts = address.split('.').map(Number);
  if (parts.length !== 4 || parts.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = parts;
  return (
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 0
  );
}

function isPrivateIPv6(address: string): boolean {
  const value = address.toLowerCase();
  return value === '::1' || value === '::' || value.startsWith('fc') || value.startsWith('fd') || value.startsWith('fe80:');
}

export function isBlockedIp(address: string): boolean {
  const family = net.isIP(address);
  if (family === 4) return isPrivateIPv4(address);
  if (family === 6) return isPrivateIPv6(address);
  return true;
}

export async function validateExternalUrl(input: string): Promise<URL> {
  if (typeof input !== 'string' || input.length === 0 || input.length > 4096) {
    throw new Error('Invalid URL input');
  }

  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    throw new Error('Invalid URL');
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Only HTTP and HTTPS URLs are supported');
  }

  const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
  if (!hostname || BLOCKED_HOSTNAMES.has(hostname)) {
    throw new Error('Destination is not allowed');
  }

  if (net.isIP(hostname) && isBlockedIp(hostname)) {
    throw new Error('Private or local destinations are not allowed');
  }

  // Resolve hostnames before server-side fetching to reject obvious DNS targets.
  const records = await dns.lookup(hostname, { all: true, verbatim: true });
  if (records.length === 0 || records.some((record) => isBlockedIp(record.address))) {
    throw new Error('Destination resolves to a private or local address');
  }

  url.hostname = hostname;
  return url;
}
