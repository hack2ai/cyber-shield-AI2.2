import dns from 'node:dns/promises';
import tls from 'node:tls';
import { isBlockedIp } from '../security/index.js';

export interface TlsAnalysisResult {
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

const TLS_TIMEOUT_MS = 7000;

export async function analyzeTls(hostname: string, port = 443): Promise<TlsAnalysisResult> {
  const normalized = hostname.trim().toLowerCase().replace(/\.$/, '');
  if (!normalized || normalized.length > 253) {
    throw new Error('Invalid TLS hostname');
  }

  let resolvedAddress: { address: string; family: 4 | 6 };
  try {
    const records = await dns.lookup(normalized, { all: true, verbatim: true });
    const safe = records.find((record) => !isBlockedIp(record.address) && (record.family === 4 || record.family === 6));
    if (!safe || (safe.family !== 4 && safe.family !== 6)) {
      throw new Error('Destination did not resolve to a public address');
    }
    resolvedAddress = { address: safe.address, family: safe.family };
  } catch (error) {
    return {
      hostname: normalized,
      port,
      authorized: false,
      protocol: null,
      cipher: null,
      issuer: null,
      subject: null,
      validFrom: null,
      validTo: null,
      fingerprint256: null,
      error: error instanceof Error ? error.message : 'TLS DNS resolution failed',
    };
  }

  return new Promise((resolve) => {
    let settled = false;
    const socket = tls.connect({
      host: normalized,
      port,
      servername: normalized,
      rejectUnauthorized: false,
      timeout: TLS_TIMEOUT_MS,
      lookup: (_hostname, _options, callback) => callback(null, resolvedAddress.address, resolvedAddress.family),
    });

    const finish = (result: TlsAnalysisResult) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };

    socket.once('secureConnect', () => {
      const certificate = socket.getPeerCertificate();
      const cipherInfo = socket.getCipher();

      finish({
        hostname: normalized,
        port,
        authorized: socket.authorized,
        protocol: socket.getProtocol() ?? null,
        cipher: cipherInfo?.name ?? null,
        issuer: certificate?.issuer ? { ...certificate.issuer } : null,
        subject: certificate?.subject ? { ...certificate.subject } : null,
        validFrom: certificate?.valid_from ?? null,
        validTo: certificate?.valid_to ?? null,
        fingerprint256: certificate?.fingerprint256 ?? null,
      });
    });

    socket.once('timeout', () => {
      finish({ hostname: normalized, port, authorized: false, protocol: null, cipher: null, issuer: null, subject: null, validFrom: null, validTo: null, fingerprint256: null, error: 'TLS connection timed out' });
    });

    socket.once('error', (error) => {
      finish({ hostname: normalized, port, authorized: false, protocol: null, cipher: null, issuer: null, subject: null, validFrom: null, validTo: null, fingerprint256: null, error: error.message });
    });
  });
}
