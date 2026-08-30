import { Router, type Request, type Response } from 'express';
import { createHash } from 'node:crypto';
import { rateLimit } from '../security/index.js';
import { env } from '../config/env.js';

export const compatRouter = Router();
compatRouter.use(rateLimit);

const MAX_ASSISTANT_MESSAGE_LENGTH = 4_000;
const MAX_FILE_BYTES = 10 * 1024 * 1024;
const MAX_ANALYTICS_COUNT = 1_000_000_000;

function text(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function jsonError(res: Response, status: number, error: string): void {
  res.status(status).json({ error });
}

function assistantFallback(message: string): string {
  const lower = message.toLowerCase();
  if (lower.includes('sql injection') || lower.includes('sqli')) return 'SQL injection is an application-layer vulnerability caused by unsafe construction of database queries. Use parameterized queries, least-privilege database accounts, input validation, and security testing.';
  if (lower.includes('ransomware')) return 'Ransomware is malware that disrupts access to data or systems and demands payment. Defensive controls include offline backups, endpoint protection, network segmentation, patching, and tested incident-response procedures.';
  if (lower.includes('phishing') || lower.includes('email')) return 'For phishing triage, inspect the sender domain, authentication results, link destinations, urgency language, attachment types, and whether the request matches a trusted workflow. Do not disclose credentials from unsolicited messages.';
  if (lower.includes('password')) return 'Defensively, protect passwords with unique credentials, a password manager, phishing-resistant MFA, rate limiting, secure password hashing, and credential monitoring.';
  if (lower.includes('safe') && lower.includes('website')) return 'A website assessment should combine URL structure, DNS, TLS, redirects, domain age, reputation feeds, and observed content. A clean result is evidence, not a guarantee of safety.';
  return `ThreatGPT local advisor: ${message}\n\nUse the scanner for technical evidence, then base the final decision on the returned risk indicators and threat-intelligence results.`;
}

compatRouter.post('/assistant', (req: Request, res: Response) => {
  const message = text(req.body?.message);
  if (!message) return jsonError(res, 400, 'message is required');
  if (message.length > MAX_ASSISTANT_MESSAGE_LENGTH) return jsonError(res, 413, 'message is too long');
  res.status(200).json({ reply: assistantFallback(message), provider: 'local-advisor' });
});

compatRouter.post('/breach-check', async (req: Request, res: Response) => {
  const identity = text(req.body?.identity).toLowerCase();
  if (!identity || identity.length > 320) return jsonError(res, 400, 'identity is required');
  if (!env.hibpApiKey) {
    return res.status(200).json({ identity, breachCount: 0, breaches: [], compromisedCategories: [], passwordExposure: 'not-checked', recommendations: ['HIBP_API_KEY is not configured, so no external breach database query was performed.', 'Configure a breach-intelligence provider before treating this result as evidence of no exposure.'], providerStatus: 'not-configured' });
  }
  try {
    const endpoint = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(identity)}?truncateResponse=false`;
    const response = await fetch(endpoint, { headers: { 'hibp-api-key': env.hibpApiKey, 'user-agent': 'Cyber-Shield-AI2.2/1.0', accept: 'application/json' } });
    if (response.status === 404) return res.status(200).json({ identity, breachCount: 0, breaches: [], compromisedCategories: [], passwordExposure: 'unknown', recommendations: ['No breach records were returned by the configured provider. Continue using MFA and unique credentials.'], providerStatus: 'ok' });
    if (!response.ok) return jsonError(res, 502, `Breach provider returned HTTP ${response.status}`);
    const records = await response.json() as Array<Record<string, unknown>>;
    const categories = Array.from(new Set(records.flatMap((record) => String(record.DataClasses ?? '').split(',').map((item) => item.trim()).filter(Boolean))));
    return res.status(200).json({ identity, breachCount: records.length, breaches: records.map((record) => ({ name: String(record.Name ?? 'Unknown'), title: String(record.Title ?? record.Name ?? 'Unknown breach'), domain: String(record.Domain ?? ''), breachDate: String(record.BreachDate ?? ''), addedDate: String(record.AddedDate ?? ''), dataClasses: Array.isArray(record.DataClasses) ? record.DataClasses : String(record.DataClasses ?? '').split(',').map((item) => item.trim()).filter(Boolean) })), compromisedCategories: categories, passwordExposure: categories.some((item) => item.toLowerCase().includes('password')) ? 'exposed-in-records' : 'not-indicated', recommendations: ['Reset passwords associated with exposed accounts and do not reuse them.', 'Enable phishing-resistant MFA on affected services.', 'Review session tokens and recovery channels for unexpected changes.'], providerStatus: 'ok' });
  } catch {
    return jsonError(res, 502, 'Breach provider request failed');
  }
});

function parseHeaderValue(headers: string, name: string): string {
  const regex = new RegExp(`^${name}:\\s*(.+)$`, 'im');
  const match = headers.match(regex);
  return match?.[1]?.trim() ?? '';
}

compatRouter.post('/email-header-check', (req: Request, res: Response) => {
  const rawHeaders = text(req.body?.headers);
  if (!rawHeaders) return jsonError(res, 400, 'headers are required');
  if (rawHeaders.length > 200_000) return jsonError(res, 413, 'headers payload is too large');
  const normalized = rawHeaders.replace(/\r\n[ \t]+/g, ' ');
  const authenticationResults = parseHeaderValue(normalized, 'Authentication-Results');
  const from = parseHeaderValue(normalized, 'From');
  const returnPath = parseHeaderValue(normalized, 'Return-Path');
  const senderIp = normalized.match(/\b(?:client-ip|sender-ip)=?\[?((?:\d{1,3}\.){3}\d{1,3})\]?/i)?.[1] ?? '';
  const receivedHops = normalized.match(/^Received:/gim)?.length ?? 0;
  const indicators: string[] = [];
  if (/spf=(fail|softfail|neutral)/i.test(authenticationResults)) indicators.push('SPF authentication is not clean');
  if (/dkim=(fail|neutral)/i.test(authenticationResults)) indicators.push('DKIM authentication is not clean');
  if (/dmarc=(fail|quarantine|none)/i.test(authenticationResults)) indicators.push('DMARC is not passing');
  if (from && returnPath && !from.toLowerCase().includes(returnPath.toLowerCase().replace(/^<|>$/g, ''))) indicators.push('From and Return-Path identities differ');
  if (receivedHops > 8) indicators.push('Unusually long mail relay chain');
  if (!authenticationResults) indicators.push('Authentication-Results header is missing');
  let threatScore = Math.min(100, indicators.length * 18);
  if (indicators.some((item) => item.toLowerCase().includes('dmarc'))) threatScore = Math.min(100, threatScore + 10);
  const classification = threatScore >= 70 ? 'Malicious' : threatScore >= 35 ? 'Suspicious' : 'Safe';
  return res.status(200).json({ spf: /spf=pass/i.test(authenticationResults) ? 'PASS' : /spf=fail|softfail/i.test(authenticationResults) ? 'FAIL' : 'UNKNOWN', dkim: /dkim=pass/i.test(authenticationResults) ? 'PASS' : /dkim=fail/i.test(authenticationResults) ? 'FAIL' : 'UNKNOWN', dmarc: /dmarc=pass/i.test(authenticationResults) ? 'PASS' : /dmarc=fail/i.test(authenticationResults) ? 'FAIL' : 'UNKNOWN', senderIp, hopsCount: receivedHops, hops: (normalized.match(/^Received:.+$/gim) ?? []).map((line) => line.replace(/^Received:\s*/i, '').trim()), threatScore, classification, explanation: indicators.length === 0 ? 'Header authentication indicators did not reveal a high-confidence spoofing pattern in the supplied headers.' : `Header analysis identified ${indicators.length} warning indicator(s). Review the authentication chain before trusting the message.`, spoofingIndicators: indicators, recommendations: indicators.length === 0 ? ['Verify the sender through an independent trusted channel before acting on sensitive requests.'] : ['Do not trust links or attachments until the sender is verified.', 'Review SPF, DKIM, and DMARC alignment at the mail gateway.'] });
});

function isCanonicalBase64(value: string): boolean {
  return value.length > 0 && value.length % 4 === 0 && /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value);
}

compatRouter.post('/analyze-file', (req: Request, res: Response) => {
  const fileData = text(req.body?.fileData);
  const fileName = text(req.body?.fileName) || 'unknown.bin';
  const fileType = text(req.body?.fileType) || 'application/octet-stream';
  const fileSize = Number(req.body?.fileSize ?? 0);
  if (!fileData) return jsonError(res, 400, 'fileData is required');
  if (!isCanonicalBase64(fileData)) return jsonError(res, 400, 'fileData must be valid base64');
  if (fileName.length > 256) return jsonError(res, 400, 'fileName is too long');
  if (fileType.length > 128) return jsonError(res, 400, 'fileType is too long');
  if (!Number.isSafeInteger(fileSize) || fileSize < 0 || fileSize > MAX_FILE_BYTES) return jsonError(res, 413, 'file exceeds 10MB limit');
  try {
    const bytes = Buffer.from(fileData, 'base64');
    if (bytes.byteLength > MAX_FILE_BYTES) return jsonError(res, 413, 'decoded file exceeds 10MB limit');
    if (fileSize !== 0 && fileSize !== bytes.byteLength) return jsonError(res, 400, 'fileSize does not match decoded payload');
    const normalizedSize = bytes.byteLength;
    const sha256 = createHash('sha256').update(bytes).digest('hex');
    let threatScore = 5;
    const indicators: string[] = [];
    const lower = fileName.toLowerCase();
    const extension = lower.split('.').pop() || '';
    if (['exe', 'scr', 'dll', 'ps1', 'bat', 'cmd', 'js', 'vbs'].includes(extension)) { threatScore += 30; indicators.push(`Executable/script payload detected: .${extension}`); }
    if (/invoice|urgent|update|patch|crack|keygen|loader|payload|dropper/.test(lower)) { threatScore += 20; indicators.push('Filename contains a high-risk delivery keyword'); }
    if (/\.(pdf|doc|docx|xls|xlsx)\.(exe|scr|js|cmd|bat)$/i.test(fileName)) { threatScore += 35; indicators.push('Double-extension masquerading pattern detected'); }
    const classification = threatScore >= 70 ? 'Malicious' : threatScore >= 35 ? 'Suspicious' : 'Safe';
    return res.status(200).json({ id: `local-file-${Date.now()}`, threatScore: Math.min(100, threatScore), classification, malwareFamily: classification === 'Malicious' ? 'Heuristic-Detected' : 'None', explanation: indicators.length ? `${indicators.join('. ')}.` : 'No high-confidence static indicators were detected by the local analyzer.', recommendation: classification === 'Safe' ? 'Continue with normal controls and verify the file source.' : 'Quarantine the file and verify it with your enterprise malware-analysis stack before execution.', fileName, fileSize: normalizedSize, fileType, sha256, detectionStats: { malicious: classification === 'Malicious' ? 1 : 0, harmless: classification === 'Safe' ? 1 : 0, suspicious: classification === 'Suspicious' ? 1 : 0, undetected: 0 }, iocIndicators: indicators, timeline: [{ time: '0.0s', event: 'Payload received', status: 'success' }, { time: '0.1s', event: 'SHA256 checksum calculated', status: 'info' }, { time: '0.2s', event: 'Static filename and extension heuristics evaluated', status: indicators.length ? 'warning' : 'success' }], providerStatus: 'local-static-analysis' });
  } catch { return jsonError(res, 400, 'fileData is not valid base64'); }
});

function parseAnalyticsCount(value: unknown, field: string): number | null {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > MAX_ANALYTICS_COUNT) {
    return null;
  }
  return value;
}

compatRouter.post('/threat-analytics/predict', (req: Request, res: Response) => {
  const metrics = req.body?.metrics;
  if (!metrics || typeof metrics !== 'object' || Array.isArray(metrics)) return jsonError(res, 400, 'metrics object is required');

  const total = parseAnalyticsCount(metrics.totalScans, 'totalScans');
  const malicious = parseAnalyticsCount(metrics.maliciousCount, 'maliciousCount');
  const suspicious = parseAnalyticsCount(metrics.suspiciousCount, 'suspiciousCount');
  if (total === null || malicious === null || suspicious === null) {
    return jsonError(res, 400, 'analytics metrics must be non-negative safe integers within the supported range');
  }
  if (malicious + suspicious > total) return jsonError(res, 400, 'maliciousCount plus suspiciousCount cannot exceed totalScans');

  const risk = total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0;
  const baseline = Math.max(5, Math.min(95, Math.round((total + malicious * 3 + suspicious * 2) / 2)));
  return res.status(200).json({ insights: [`Current telemetry contains ${total} recorded scan(s) with a ${risk}% combined suspicious/malicious ratio.`, malicious === 0 ? 'No malicious classifications are currently present in the synchronized local dataset.' : `${malicious} malicious classification(s) require prioritization.`, suspicious === 0 ? 'No suspicious classifications are currently present in the synchronized local dataset.' : `${suspicious} suspicious classification(s) warrant follow-up review.`], recommendations: ['Continue validating new findings against independent threat-intelligence sources.', 'Keep browser, endpoint, and mail security controls patched and monitored.'], predictions: [0, 1, 2, 3, 4, 5, 6].map((offset) => Math.max(0, baseline + offset * Math.max(1, Math.round((malicious + suspicious) / Math.max(1, total))))), threatScoreForecast: baseline, provider: 'local-heuristic-predictor' });
});