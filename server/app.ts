import express from 'express';
import cors from 'cors';
import { apiRouter } from './api/index.js';
import { env } from './config/env.js';
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

  // Keep unknown API failures JSON-only and predictable for clients.
  app.use('/api', (_req, res) => {
    res.status(404).json({ error: 'API route not found' });
  });

  app.use((error: unknown, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error('Unhandled API error:', error);
    if (res.headersSent) return;

    // Do not expose internal exception messages, stack traces, provider errors,
    // database details, or implementation-specific paths to remote clients.
    res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}
