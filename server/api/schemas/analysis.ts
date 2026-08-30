export interface AnalyzeUrlRequest {
  url: string;
}

export class RequestValidationError extends Error {
  readonly statusCode = 400;

  constructor(message: string) {
    super(message);
    this.name = 'RequestValidationError';
  }
}

export function validateAnalyzeUrlRequest(input: unknown): AnalyzeUrlRequest {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new RequestValidationError('Request body must be a JSON object');
  }

  const value = input as Record<string, unknown>;
  if (typeof value.url !== 'string') {
    throw new RequestValidationError('url must be a string');
  }

  const url = value.url.trim();
  if (!url) {
    throw new RequestValidationError('url is required');
  }

  if (url.length > 4096) {
    throw new RequestValidationError('url is too long');
  }

  return { url };
}
