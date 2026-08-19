import { createApp } from './app.js';
import { env } from './config/env.js';

/** Process entry point for the modular Express API. */
export function startServer() {
  const app = createApp();

  return app.listen(env.port, () => {
    console.log(`Cyber Shield AI API listening on port ${env.port}`);
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startServer();
}
