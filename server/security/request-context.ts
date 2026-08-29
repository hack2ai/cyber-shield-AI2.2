import { randomUUID } from 'node:crypto';
import type { RequestHandler } from 'express';

export const REQUEST_ID_HEADER = 'X-Request-ID';
const SAFE_REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/;

export function normalizeRequestId(incoming?: string): string {
  const trimmed = incoming?.trim();
  return trimmed && SAFE_REQUEST_ID.test(trimmed) ? trimmed : randomUUID();
}

export const requestContext: RequestHandler = (req, res, next) => {
  const requestId = normalizeRequestId(req.header(REQUEST_ID_HEADER));

  res.setHeader(REQUEST_ID_HEADER, requestId);
  res.locals.requestId = requestId;

  next();
};
