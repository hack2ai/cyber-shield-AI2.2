export interface AnalyzeUrlRequest {
  url: string;
}

export function validateAnalyzeUrlRequest(input: unknown): AnalyzeUrlRequest {
  if (!input || typeof input !== 'object') {
    throw new Error('Request body must be a JSON object');
  }

  const value = input as Record<string, unknown>;
  if (typeof value.url !== 'string') {
    throw new Error('url must be a string');
  }

  const url = value.url.trim();
  if (!url) {
    throw new Error('url is required');
  }

  if (url.length > 4096) {
    throw new Error('url is too long');
  }

  return { url };
}
