import type { UrlAnalysisResult } from '../../analysis/index.js';

export interface AnalysisSuccessResponse {
  success: true;
  data: UrlAnalysisResult;
}

export interface AnalysisErrorResponse {
  success: false;
  error: {
    code: string;
    message: string;
  };
}

export function analysisSuccess(data: UrlAnalysisResult): AnalysisSuccessResponse {
  return { success: true, data };
}

export function analysisError(code: string, message: string): AnalysisErrorResponse {
  return {
    success: false,
    error: { code, message },
  };
}
