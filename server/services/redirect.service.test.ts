import { afterEach, describe, expect, it, vi } from 'vitest';
import dns from 'node:dns/promises';
import { isBlockedIp, validateExternalUrl } from '../security/index.js';
import { analyzeRedirects, type RedirectRequestResult } from './redirect.service.js';

vi.mock('node:dns/promises', () => ({ default: { lookup: vi.fn() } }));
vi.mock('../security/index.js', () => ({ validateExternalUrl: vi.fn(), isBlockedIp: vi.fn() }));

const mockedLookup = vi.mocked(dns.lookup);
const mockedValidate = vi.mocked(validateExternalUrl);
const mockedBlocked = vi.mocked(isBlockedIp);

describe('analyzeRedirects', () => {
  afterEach(() => vi.clearAllMocks());

  it('resolves a public destination and performs one request', async () => {
    mockedValidate.mockImplementation(async (input: string) => new URL(input));
    mockedLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }] as never);
    mockedBlocked.mockReturnValue(false);
    const request = vi.fn<(_url: URL, _ip: string, _family: 4 | 6) => Promise<RedirectRequestResult>>().mockResolvedValue({ status: 200, location: null });

    const result = await analyzeRedirects('https://example.com', request);

    expect(result.originalUrl).toBe('https://example.com/');
    expect(result.redirectCount).toBe(0);
    expect(result.hops).toHaveLength(1);
    expect(request).toHaveBeenCalledWith(new URL('https://example.com/'), '93.184.216.34', 4);
    expect(mockedLookup).toHaveBeenCalledWith('example.com', { all: true, verbatim: true });
  });

  it('rejects a destination that resolves only to a blocked address', async () => {
    mockedValidate.mockImplementation(async (input: string) => new URL(input));
    mockedLookup.mockResolvedValue([{ address: '127.0.0.1', family: 4 }] as never);
    mockedBlocked.mockReturnValue(true);
    const request = vi.fn();

    const result = await analyzeRedirects('https://attacker.example', request);

    expect(result.error).toBe('Destination did not resolve to a public address');
    expect(request).not.toHaveBeenCalled();
  });

  it('revalidates and re-resolves every redirect destination', async () => {
    mockedValidate.mockResolvedValueOnce(new URL('https://example.com/')).mockResolvedValueOnce(new URL('https://safe.example/'));
    mockedLookup.mockResolvedValueOnce([{ address: '93.184.216.34', family: 4 }] as never).mockResolvedValueOnce([{ address: '93.184.216.35', family: 4 }] as never);
    mockedBlocked.mockReturnValue(false);
    const request = vi.fn<(_url: URL, _ip: string, _family: 4 | 6) => Promise<RedirectRequestResult>>()
      .mockResolvedValueOnce({ status: 302, location: 'https://safe.example/' })
      .mockResolvedValueOnce({ status: 200, location: null });

    const result = await analyzeRedirects('https://example.com', request);

    expect(mockedValidate).toHaveBeenCalledTimes(2);
    expect(mockedLookup).toHaveBeenCalledTimes(2);
    expect(request).toHaveBeenNthCalledWith(1, new URL('https://example.com/'), '93.184.216.34', 4);
    expect(request).toHaveBeenNthCalledWith(2, new URL('https://safe.example/'), '93.184.216.35', 4);
    expect(result.redirectCount).toBe(1);
    expect(result.hostnameChanged).toBe(true);
  });

  it('stops after the configured redirect limit', async () => {
    mockedValidate.mockImplementation(async (input: string) => new URL(input));
    mockedLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }] as never);
    mockedBlocked.mockReturnValue(false);
    const request = vi.fn<(_url: URL, _ip: string, _family: 4 | 6) => Promise<RedirectRequestResult>>()
      .mockResolvedValue({ status: 302, location: 'https://example.com/next' });

    const result = await analyzeRedirects('https://example.com', request);

    expect(result.redirectCount).toBe(5);
    expect(result.hops).toHaveLength(6);
    expect(request).toHaveBeenCalledTimes(6);
  });
});
