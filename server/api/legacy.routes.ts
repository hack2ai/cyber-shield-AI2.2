import { Router } from 'express';
import { analyzeUrlController } from './analysis.controller.js';
import { rateLimit } from '../security/index.js';

/** Backward-compatible route used by the scanner UI. */
export const legacyRouter = Router();
legacyRouter.post('/analyze', rateLimit, analyzeUrlController);
