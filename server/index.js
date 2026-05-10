import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import mongoose from 'mongoose';
import systemRoutes from './routes/systemRoutes.js';
import { attachUserContext } from './middlewares/authMiddleware.js';
import globalErrorHandler from './middlewares/errorMiddleware.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;

app.use(
  cors({
    origin: ['http://localhost:5173', process.env.CLIENT_URL].filter(Boolean),
    credentials: true,
  })
);
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(attachUserContext);

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
    timestamp: new Date().toISOString(),
  });
});

app.use('/api/system', systemRoutes);

app.get('/', (req, res) => {
  res.send('MyVisit API is running');
});

app.use('*', (req, res) => {
  res.status(404).json({ message: 'API endpoint not found' });
});

app.use(globalErrorHandler);

const startServer = async () => {
  if (process.env.MONGO_URI) {
    try {
      await mongoose.connect(process.env.MONGO_URI);
      console.log('MongoDB connected');
    } catch (error) {
      console.error('MongoDB connection failed:', error.message);
    }
  } else {
    console.warn('MONGO_URI is not set. Electrical project persistence will not work.');
  }

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
};

startServer();
