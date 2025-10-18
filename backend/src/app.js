import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import './config/db.config.js'; 
import authRoutes from './routes/auth.routes.js';
import session from "express-session";
import oauthRoutes from "./routes/oauth.routes.js";
import passport from "./services/oauth.service.js";
import webauthnRegisterRoutes from "./routes/webauthn.routes.js";
import webauthnAuthRoutes from "./routes/webauthn.routes.js";
import smsRoutes from "./routes/sms.routes.js";


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
  credentials: true   //  Permite envío de cookies
}));

app.use(
  session({
    secret: "supersecretkey",
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

/*
// Límite de peticiones (protege contra ataques)
app.use(rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minuto
  max: 100, // máximo 100 requests/minuto
  message: '⚠️ Demasiadas peticiones desde esta IP. Intenta más tarde.'
}));
*/

// Ruta base temporal
app.get('/', (req, res) => {
  res.send(' API funcionando correctamente');
});

// 1. TOKEN + CONTRAEÑA
app.use('/api/auth', authRoutes);

// 2. OAUTH2 (GOOGLE, FACEBOOK)
app.use("/api/oauth", oauthRoutes);

// 3. WEBAUTHN (BIOMETRÍA)
app.use("/api/webauthn", webauthnRegisterRoutes);
app.use("/api/webauthn", webauthnAuthRoutes);

// 4. SMS
app.use("/api/sms", smsRoutes);

export default app;
