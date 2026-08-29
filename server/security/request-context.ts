import { randomUUID } from 'node:crypto';
import type { RequestHandler } from 'express';

export const REQUEST_ID_HEADER = 'X-Request-ID';
const SAFE_REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/;

export const requestContext: RequestHandler = (req, res, next) => {
  const incoming = req.header(REQUEST_ID_HEADER)?.trim();
  const requestId = incoming && SAFE_REQUEST_ID.test(incoming) ? incoming : randomUUID();

  res.setHeader(REQUEST_ID_HEADER, requestId);
  res.locals.requestId = requestId;

  next();
};
