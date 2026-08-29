import { Router } from 'express';
import { analyzeUrlController } from './analysis.controller.js';

export const analysisRouter = Router();

analysisRouter.post('/analysis', analyzeUrlController);
