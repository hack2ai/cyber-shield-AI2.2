import { validateExternalUrl } from '../security/index.js';

export interface RedirectHop {
  url: string;
  status: number;
  location: string | null;
}

export interface RedirectAnalysisResult {
  originalUrl: string;
  finalUrl: string;
  hops: RedirectHop[];
  redirectCount: number;
  hostnameChanged: boolean;
  timedOut: boolean;
  error?: string;
}

const REQUEST_TIMEOUT_MS = 8000;
const MAX_REDIRECTS = 5;

export async function analyzeRedirects(input: string | URL): Promise<RedirectAnalysisResult> {
  const original = await validateExternalUrl(input instanceof URL ? input.href : input);
  const hops: RedirectHop[] = [];
  let current = original;
  let timedOut = false;

  try {
    for (let i = 0; i <= MAX_REDIRECTS; i += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

      let response: Response;
      try {
        response = await fetch(current, {
          method: 'HEAD',
          redirect: 'manual',
          signal: controller.signal,
          headers: {
            'user-agent': 'Cyber-Shield-AI-Security-Scanner/1.0',
          },
        });
      } finally {
        clearTimeout(timer);
      }

      const location = response.headers.get('location');
      hops.push({
        url: current.href,
        status: response.status,
        location,
      });

      if (!location || response.status < 300 || response.status >= 400) {
        break;
      }

      const next = new URL(location, current.href);
      current = await validateExternalUrl(next.href);
    }
  } catch (error) {
    timedOut = error instanceof DOMException && error.name === 'AbortError';
    return {
      originalUrl: original.href,
      finalUrl: current.href,
      hops,
      redirectCount: Math.max(0, hops.length - 1),
      hostnameChanged: new URL(original.href).hostname !== new URL(current.href).hostname,
      timedOut,
      error: timedOut ? 'Redirect analysis timed out' : error instanceof Error ? error.message : 'Redirect analysis failed',
    };
  }

  return {
    originalUrl: original.href,
    finalUrl: current.href,
    hops,
    redirectCount: Math.max(0, hops.length - 1),
    hostnameChanged: new URL(original.href).hostname !== new URL(current.href).hostname,
    timedOut,
  };
}
