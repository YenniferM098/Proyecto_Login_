import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
dotenv.config();

const SECRET = process.env.JWT_SECRET || 'default_secret';

export const JWTService = {
  /**
   * Genera un token JWT firmado con el secreto del .env
   * @param {Object} payload - Datos a incluir en el token (por ejemplo: id, correo)
   * @param {String} expiresIn - Duración del token (por defecto 1h)
   * @returns {String} token firmado
   */
  generateToken: (payload, expiresIn = '1h') => {
    return jwt.sign(payload, SECRET, { expiresIn });
  },

  /**
   * Verifica si un token JWT es válido
   * @param {String} token - Token recibido del cliente
   * @returns {Object|null} payload decodificado o null si es inválido
   */
  verifyToken: (token) => {
    try {
      return jwt.verify(token, SECRET);
    } catch (err) {
      return null;
    }
  },

  /**
   * Decodifica un token sin verificarlo (solo lectura)
   * @param {String} token
   * @returns {Object|null}
   */
  decodeToken: (token) => {
    try {
      return jwt.decode(token);
    } catch (err) {
      return null;
    }
  },
};
