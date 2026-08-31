import type { Request, Response } from 'express';
import { RequestValidationError, validateAnalyzeUrlRequest } from './schemas/analysis.js';
import { analysisError, analysisSuccess } from './responses/analysis.js';
import { analyzeUrlEnriched } from '../analysis/enriched-analyzer.js';
import { addAnalysis } from '../analysis/store.js';
import { validateExternalUrl } from '../security/index.js';

export async function analyzeUrlController(req: Request, res: Response): Promise<void> {
  try {
    const { url } = validateAnalyzeUrlRequest(req.body);
    const safeUrl = await validateExternalUrl(url);
    const result = await analyzeUrlEnriched(safeUrl);

    addAnalysis(result);
    res.status(200).json(analysisSuccess(result));
  } catch (error) {
    if (error instanceof RequestValidationError) {
      res.status(error.statusCode)
        .json(analysisError('INVALID_REQUEST', error.message));
      return;
    }

    const message = error instanceof Error ? error.message : 'Unable to analyze URL';
    const lower = message.toLowerCase();
    const code = lower.includes('destination') || lower.includes('private')
      ? 'DESTINATION_NOT_ALLOWED'
      : lower.includes('url') || lower.includes('hostname')
        ? 'INVALID_URL'
        : 'ANALYSIS_FAILED';

    const clientMessage = code === 'INVALID_URL'
      ? 'The supplied URL is invalid.'
      : code === 'DESTINATION_NOT_ALLOWED'
        ? 'The requested destination is not allowed.'
        : 'Unable to analyze the URL.';

    if (code === 'ANALYSIS_FAILED') {
      console.error('URL analysis failed', {
        requestId: res.locals.requestId,
        error,
      });
    }

    res.status(code === 'INVALID_URL' || code === 'DESTINATION_NOT_ALLOWED' ? 400 : 500)
      .json(analysisError(code, clientMessage));
  }
}
