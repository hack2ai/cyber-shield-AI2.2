import { describe, expect, it } from 'vitest';
import express from 'express';
import { requestContext, REQUEST_ID_HEADER } from './request-context.js';

async function getRequestId(incoming?: string) {
  const app = express();
  app.use(requestContext);
  app.get('/health', (_req, res) => res.json({ requestId: res.locals.requestId }));

  const server = app.listen(0);
  try {
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Unable to determine test server port');
    const headers: Record<string, string> = {};
    if (incoming) headers[REQUEST_ID_HEADER] = incoming;
    const response = await fetch(`http://127.0.0.1:${address.port}/health`, { headers });
    return { header: response.headers.get(REQUEST_ID_HEADER), body: await response.json() as { requestId: string } };
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

describe('request context', () => {
  it('generates and exposes a request id', async () => {
    const result = await getRequestId();
    expect(result.header).toMatch(/^[0-9a-f-]{36}$/i);
    expect(result.body.requestId).toBe(result.header);
  });

  it('preserves a safe bounded incoming request id', async () => {
    const result = await getRequestId('trace-123:abc_1');
    expect(result.header).toBe('trace-123:abc_1');
    expect(result.body.requestId).toBe('trace-123:abc_1');
  });

  it('replaces unsafe incoming request ids', async () => {
    const result = await getRequestId('trace value\nforged-log-entry');
    expect(result.header).toMatch(/^[0-9a-f-]{36}$/i);
    expect(result.body.requestId).toBe(result.header);
  });
});
