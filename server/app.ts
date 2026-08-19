import express from 'express';
import cors from 'cors';
import { apiRouter } from './api/index.js';
import { rateLimit, securityHeaders } from './security/index.js';

/**
 * Express application factory.
 * Keep startup concerns (Vite, ports, process lifecycle) outside this module.
 */
export function createApp() {
  const app = express();

  app.disable('x-powered-by');
  app.use(securityHeaders);
  app.use(rateLimit);
  app.use(cors());
  app.use(express.json({ limit: '1mb' }));

  app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'ok', service: 'cyber-shield-ai' });
  });

  app.use('/api', apiRouter);

  return app;
}
