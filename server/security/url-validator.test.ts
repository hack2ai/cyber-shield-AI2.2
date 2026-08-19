import { describe, expect, it } from 'vitest';
import { isBlockedIp } from './url-validator.js';

describe('SSRF IP protection', () => {
  it('blocks loopback and private IPv4 addresses', () => {
    expect(isBlockedIp('127.0.0.1')).toBe(true);
    expect(isBlockedIp('10.0.0.8')).toBe(true);
    expect(isBlockedIp('172.16.0.5')).toBe(true);
    expect(isBlockedIp('192.168.1.10')).toBe(true);
    expect(isBlockedIp('169.254.169.254')).toBe(true);
  });

  it('blocks local IPv6 addresses', () => {
    expect(isBlockedIp('::1')).toBe(true);
    expect(isBlockedIp('fc00::1')).toBe(true);
    expect(isBlockedIp('fe80::1')).toBe(true);
  });

  it('allows a normal public IPv4 address', () => {
    expect(isBlockedIp('8.8.8.8')).toBe(false);
  });
});
