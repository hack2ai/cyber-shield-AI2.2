import 'dotenv/config';

function optional(name: string): string | undefined {
  const value = process.env[name]?.trim();
  return value || undefined;
}

function positiveInt(name: string, fallback: number): number {
  const raw = process.env[name];
  if (!raw) return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${name} must be a positive integer`);
  }
  return value;
}

const nodeEnv = process.env.NODE_ENV?.trim() || 'development';
if (!['development', 'test', 'production'].includes(nodeEnv)) {
  throw new Error('NODE_ENV must be development, test, or production');
}

export const env = Object.freeze({
  nodeEnv,
  port: positiveInt('PORT', 3000),
  allowedOrigins: optional('ALLOWED_ORIGINS')?.split(',').map((origin) => origin.trim()).filter(Boolean) ?? [],
  geminiApiKey: optional('GEMINI_API_KEY'),
  virusTotalApiKey: optional('VIRUSTOTAL_API_KEY'),
  abuseIpDbApiKey: optional('ABUSEIPDB_API_KEY'),
  hibpApiKey: optional('HIBP_API_KEY'),
  dehashedEmail: optional('DEHASHED_EMAIL'),
  dehashedApiKey: optional('DEHASHED_API_KEY'),
  lyzrApiKey: optional('LYZR_API_KEY'),
});
