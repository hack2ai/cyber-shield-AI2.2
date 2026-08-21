import { Router } from 'express';
import { getDashboardStats } from '../services/dashboard.service.js';

export const dashboardRouter = Router();

dashboardRouter.get('/stats', (_req, res) => {
  res.status(200).json(getDashboardStats());
});
