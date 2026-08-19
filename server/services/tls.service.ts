import tls from 'node:tls';

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

export function analyzeTls(hostname: string, port = 443): Promise<TlsAnalysisResult> {
  const normalized = hostname.trim().toLowerCase().replace(/\.$/, '');
  if (!normalized || normalized.length > 253) {
    return Promise.reject(new Error('Invalid TLS hostname'));
  }

  return new Promise((resolve) => {
    let settled = false;
    const socket = tls.connect({
      host: normalized,
      port,
      servername: normalized,
      rejectUnauthorized: false,
      timeout: TLS_TIMEOUT_MS,
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
