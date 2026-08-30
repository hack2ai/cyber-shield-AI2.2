import express from 'express';
import cors from 'cors';
import { apiRouter } from './api/index.js';
import { env } from './config/env.js';
import { logger } from './logging/logger.js';
import { rateLimit, requestContext, securityHeaders } from './security/index.js';

/**
 * Express application factory.
 * Keep startup concerns (Vite, ports, process lifecycle) outside this module.
 */
export function createApp() {
  const app = express();

  app.disable('x-powered-by');
  app.use(requestContext);
  app.use(securityHeaders);
  app.use(rateLimit);
  app.use(cors({
    origin: env.allowedOrigins.length > 0 ? env.allowedOrigins : false,
  }));
  // JSON-encoded files use base64, which expands a 10 MB binary payload to
  // roughly 13.34 MB before JSON framing. Keep a narrow envelope above that
  // documented file limit; individual routes still enforce their own limits.
  app.use(express.json({ limit: '14mb' }));

  app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok', service: 'cyber-shield-ai' });
  });

  app.use('/api', apiRouter);

  app.use('/api', (_req, res) => {
    res.status(404).json({ error: 'API route not found' });
  });

  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    const errorType = error && typeof error === 'object' && 'type' in error
      ? String((error as { type?: unknown }).type)
      : '';
    const statusCode = error && typeof error === 'object' && 'status' in error
      && Number.isInteger((error as { status?: unknown }).status)
      ? Number((error as { status: number }).status)
      : 0;

    if (errorType === 'entity.too.large' || statusCode === 413) {
      res.status(413).json({ error: 'Request payload is too large.' });
      return;
    }

    if (errorType === 'entity.parse.failed' || statusCode === 400) {
      res.status(400).json({ error: 'Malformed JSON request body.' });
      return;
    }

    logger.error('Unhandled API error', {
      requestId: res.locals.requestId,
      error: error instanceof Error ? error.message : String(error),
    });
    if (res.headersSent) return;
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}
