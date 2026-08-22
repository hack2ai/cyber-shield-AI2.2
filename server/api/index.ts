import { Router } from 'express';
import { analysisRouter } from './analysis.routes.js';
import { dashboardRouter } from './dashboard.routes.js';
import { compatRouter } from './compat.routes.js';
import { trainingRouter } from './training.routes.js';

/** API router boundary. Mount this once from the Express application with app.use('/api', apiRouter). */
export const apiRouter = Router();

apiRouter.use(analysisRouter);
apiRouter.use('/dashboard', dashboardRouter);
apiRouter.use('/training', trainingRouter);
apiRouter.use(compatRouter);
