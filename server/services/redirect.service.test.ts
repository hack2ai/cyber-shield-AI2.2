import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('node:dns/promises', () => ({
  default: {
    lookup: vi.fn(),
  },
}));

vi.mock('../security/index.js', () => ({
  validateExternalUrl: vi.fn(),
  isBlockedIp: vi.fn(),
}));

import dns from 'node:dns/promises';
import { isBlockedIp, validateExternalUrl } from '../security/index.js';
import { analyzeRedirects } from './redirect.service.js';

const mockedLookup = vi.mocked(dns.lookup);
const mockedValidate = vi.mocked(validateExternalUrl);
const mockedBlocked = vi.mocked(isBlockedIp);

describe('analyzeRedirects', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.clearAllMocks();
  });

  it('resolves and requests a public destination', async () => {
    mockedValidate.mockImplementation(async (input: string) => new URL(input));
    mockedLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }] as never);
    mockedBlocked.mockReturnValue(false);

    const request = vi.spyOn(global, 'fetch').mockResolvedValue(new Response(null, {
      status: 200,
      headers: {},
    }));

    const result = await analyzeRedirects('https://example.com');

    expect(result.originalUrl).toBe('https://example.com/');
    expect(result.redirectCount).toBe(0);
    expect(request).not.toHaveBeenCalled();
    expect(mockedLookup).toHaveBeenCalledWith('example.com', { all: true, verbatim: true });
  });

  it('rejects a destination that resolves only to a blocked address', async () => {
    mockedValidate.mockImplementation(async (input: string) => new URL(input));
    mockedLookup.mockResolvedValue([{ address: '127.0.0.1', family: 4 }] as never);
    mockedBlocked.mockReturnValue(true);

    await expect(analyzeRedirects('https://attacker.example')).resolves.toMatchObject({
      error: 'Destination did not resolve to a public address',
    });
  });

  it('revalidates every redirect destination', async () => {
    mockedValidate
      .mockResolvedValueOnce(new URL('https://example.com/'))
      .mockResolvedValueOnce(new URL('https://safe.example/'));
    mockedLookup
      .mockResolvedValueOnce([{ address: '93.184.216.34', family: 4 }] as never)
      .mockResolvedValueOnce([{ address: '93.184.216.35', family: 4 }] as never);
    mockedBlocked.mockReturnValue(false);

    const requests = vi.spyOn(require('node:https'), 'request');
    // The service uses node:https directly; this assertion intentionally focuses on
    // validation/resolve sequencing, while the integration test covers actual I/O.
    requests.mockImplementation((_options: unknown, callback: (response: unknown) => void) => {
      const response = {
        statusCode: 302,
        headers: { location: 'https://safe.example/' },
        resume() {},
      };
      callback(response);
      return {
        setTimeout() {},
        once() {},
        destroy() {},
        end() {},
      } as never;
    });

    const result = await analyzeRedirects('https://example.com');

    expect(mockedValidate).toHaveBeenCalledTimes(2);
    expect(mockedLookup).toHaveBeenCalledTimes(2);
    expect(result.redirectCount).toBe(1);
    requests.mockRestore();
  });

  it('stops after the configured redirect limit', async () => {
    mockedValidate.mockImplementation(async (input: string) => new URL(input));
    mockedLookup.mockResolvedValue([{ address: '93.184.216.34', family: 4 }] as never);
    mockedBlocked.mockReturnValue(false);

    const requests = vi.spyOn(require('node:https'), 'request');
    requests.mockImplementation((_options: unknown, callback: (response: unknown) => void) => {
      callback({
        statusCode: 302,
        headers: { location: 'https://example.com/next' },
        resume() {},
      });
      return {
        setTimeout() {},
        once() {},
        destroy() {},
        end() {},
      } as never;
    });

    const result = await analyzeRedirects('https://example.com');

    expect(result.redirectCount).toBe(5);
    expect(result.hops).toHaveLength(6);
    requests.mockRestore();
  });
});
