import { fileURLToPath } from 'node:url';
import { createApp } from './app.js';
import { env } from './config/env.js';
import { logger } from './logging/logger.js';

/** Process entry point for the modular Express API. */
export function startServer() {
  const app = createApp();

  return app.listen(env.port, '0.0.0.0', () => {
    logger.info('Cyber Shield AI API started', {
      port: env.port,
      environment: env.nodeEnv,
    });
  });
}

const currentFile = fileURLToPath(import.meta.url);
const invokedFile = process.argv[1] ? fileURLToPath(new URL(`file://${process.argv[1].replace(/\\/g, '/')}`)) : '';

if (currentFile === invokedFile) {
  startServer();
}
