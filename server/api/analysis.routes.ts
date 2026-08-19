import { Router } from 'express';
import { analyzeUrlController } from './analysis.controller.js';
import { rateLimit } from '../security/index.js';

export const analysisRouter = Router();

analysisRouter.post('/analysis', rateLimit, analyzeUrlController);
