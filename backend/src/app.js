import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import './config/db.config.js'; 
import authRoutes from './routes/auth.routes.js';

dotenv.config();
const app = express();

// Middlewares globales
app.use(express.json());
app.use(helmet());

// Configuración de CORS
app.use(cors({
  origin: "http://localhost:4200",   // Permite solo Angular
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true   // ✅ Permite envío de cookies
}));



// Límite de peticiones (protege contra ataques)
app.use(rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minuto
  max: 100, // máximo 100 requests/minuto
  message: '⚠️ Demasiadas peticiones desde esta IP. Intenta más tarde.'
}));

// Ruta base temporal
app.get('/', (req, res) => {
  res.send('✅ API funcionando correctamente');
});

app.use('/api/auth', authRoutes);

export default app;
