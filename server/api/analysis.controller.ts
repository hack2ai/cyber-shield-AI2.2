import type { Request, Response } from 'express';
import { validateAnalyzeUrlRequest } from './schemas/analysis.js';
import { analysisError, analysisSuccess } from './responses/analysis.js';
import { analyzeUrl } from '../analysis/index.js';
import { validateExternalUrl } from '../security/index.js';

export async function analyzeUrlController(req: Request, res: Response): Promise<void> {
  try {
    const { url } = validateAnalyzeUrlRequest(req.body);
    const safeUrl = await validateExternalUrl(url);
    const result = analyzeUrl(safeUrl);

    res.status(200).json(analysisSuccess(result));
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unable to analyze URL';
    const code = message.toLowerCase().includes('destination') || message.toLowerCase().includes('private')
      ? 'DESTINATION_NOT_ALLOWED'
      : message.toLowerCase().includes('url')
        ? 'INVALID_URL'
        : 'ANALYSIS_FAILED';

    res.status(code === 'INVALID_URL' || code === 'DESTINATION_NOT_ALLOWED' ? 400 : 500)
      .json(analysisError(code, message));
  }
}
