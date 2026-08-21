import type { Request, Response } from 'express';
import { validateAnalyzeUrlRequest } from './schemas/analysis.js';
import { analysisError, analysisSuccess } from './responses/analysis.js';
import { analyzeUrlEnriched } from '../analysis/enriched-analyzer.js';
import { addAnalysis } from '../analysis/store.js';
import { validateExternalUrl } from '../security/index.js';

export async function analyzeUrlController(req: Request, res: Response): Promise<void> {
  try {
    const { url } = validateAnalyzeUrlRequest(req.body);
    const safeUrl = await validateExternalUrl(url);
    const result = await analyzeUrlEnriched(safeUrl);

    // Keep the latest analysis in the in-memory store so the dashboard
    // endpoint can expose aggregate metrics for this running process.
    addAnalysis(result);

    res.status(200).json(analysisSuccess(result));
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unable to analyze URL';
    const lower = message.toLowerCase();
    const code = lower.includes('destination') || lower.includes('private')
      ? 'DESTINATION_NOT_ALLOWED'
      : lower.includes('url') || lower.includes('hostname')
        ? 'INVALID_URL'
        : 'ANALYSIS_FAILED';

    res.status(code === 'INVALID_URL' || code === 'DESTINATION_NOT_ALLOWED' ? 400 : 500)
      .json(analysisError(code, message));
  }
}
