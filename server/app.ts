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
  app.use(express.json({ limit: '10mb' }));

  app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok', service: 'cyber-shield-ai' });
  });

  app.use('/api', apiRouter);

  app.use('/api', (_req, res) => {
    res.status(404).json({ error: 'API route not found' });
  });

  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    logger.error('Unhandled API error', {
      requestId: res.locals.requestId,
      error: error instanceof Error ? error.message : String(error),
    });
    if (res.headersSent) return;
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}
