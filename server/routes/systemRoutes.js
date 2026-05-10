import express from 'express';
import { getCapabilities } from '../controllers/systemController.js';

const router = express.Router();

router.get('/capabilities', getCapabilities);

export default router;
