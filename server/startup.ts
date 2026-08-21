import { fileURLToPath } from 'node:url';
import { createApp } from './app.js';
import { env } from './config/env.js';

/** Process entry point for the modular Express API. */
export function startServer() {
  const app = createApp();

  return app.listen(env.port, '0.0.0.0', () => {
    console.log(`Cyber Shield AI API listening on port ${env.port}`);
  });
}

const currentFile = fileURLToPath(import.meta.url);
const invokedFile = process.argv[1] ? fileURLToPath(new URL(`file://${process.argv[1].replace(/\\/g, '/')}`)) : '';

if (currentFile === invokedFile) {
  startServer();
}
