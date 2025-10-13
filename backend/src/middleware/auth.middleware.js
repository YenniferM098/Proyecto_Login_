import { JWTService } from '../services/jwt.service.js';

/**
 * Middleware para verificar el token JWT en rutas protegidas
 */
export const verifyAuth = (req, res, next) => {
  // Espera el formato: Authorization: Bearer <token>
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }

  const decoded = JWTService.verifyToken(token);
  if (!decoded) {
    return res.status(403).json({ error: 'Token inválido o expirado' });
  }

  // Almacena la info del usuario decodificada para usar en la ruta
  req.user = decoded;
  next();
};

