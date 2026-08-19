import 'dotenv/config';
import { createApp } from './app.js';

/** Process entry point for the modular Express API. */
export function startServer() {
  const app = createApp();
  const port = Number(process.env.PORT || 3000);

  return app.listen(port, () => {
    console.log(`Cyber Shield AI API listening on port ${port}`);
  });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  startServer();
}
