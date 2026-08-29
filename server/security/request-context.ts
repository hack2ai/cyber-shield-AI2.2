import { randomUUID } from 'node:crypto';
import type { RequestHandler } from 'express';

export const REQUEST_ID_HEADER = 'X-Request-ID';

export const requestContext: RequestHandler = (req, res, next) => {
  const incoming = req.header(REQUEST_ID_HEADER)?.trim();
  const requestId = incoming && incoming.length <= 128 ? incoming : randomUUID();

  res.setHeader(REQUEST_ID_HEADER, requestId);
  res.locals.requestId = requestId;

  next();
};
