import type { EnrichedUrlAnalysisResult } from '../../analysis/index.js';

export const ANALYSIS_API_VERSION = 'v1';

export interface AnalysisSuccessResponse {
  success: true;
  version: typeof ANALYSIS_API_VERSION;
  data: EnrichedUrlAnalysisResult;
}

export interface AnalysisErrorResponse {
  success: false;
  version: typeof ANALYSIS_API_VERSION;
  error: {
    code: string;
    message: string;
  };
}

export function analysisSuccess(data: EnrichedUrlAnalysisResult): AnalysisSuccessResponse {
  return {
    success: true,
    version: ANALYSIS_API_VERSION,
    data,
  };
}

export function analysisError(code: string, message: string): AnalysisErrorResponse {
  return {
    success: false,
    version: ANALYSIS_API_VERSION,
    error: { code, message },
  };
}
