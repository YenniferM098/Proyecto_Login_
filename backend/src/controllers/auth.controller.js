import bcrypt from "bcryptjs";
import { poolPromise } from "../config/db.config.js";
import { UserModel } from "../models/user.model.js";
import { JWTService } from "../services/jwt.service.js";
import { SessionModel } from '../models/session.model.js';
import { RefreshModel } from "../models/refresh.model.js";
import { v4 as uuidv4 } from "uuid";
import sql from "mssql";
import dotenv from "dotenv";

dotenv.config();

export const AuthController = {
/**
 * ================================================================
 *  MÉTODO 0 — REGISTRO DE USUARIO (valida correo y teléfono únicos)
 * ================================================================
 */
register: async (req, res) => {
  try {
    const pool = await poolPromise;
    const { nombre, apaterno, amaterno, correo, telefono, contrasena } = req.body;

    if (!nombre || !apaterno || !amaterno || !correo || !telefono || !contrasena)
      return res.status(400).json({ error: "Faltan datos obligatorios" });

    // 🔹 Verificar si ya existe un usuario con el mismo correo
    const userEmail = await pool.request()
      .input("correo", correo)
      .query("SELECT id_usuario FROM Usuarios WHERE correo = @correo");

    if (userEmail.recordset.length > 0)
      return res.status(409).json({ error: "El correo ya está registrado" });

    // 🔹 Verificar si ya existe un usuario con el mismo teléfono
    const userPhone = await pool.request()
      .input("telefono", telefono)
      .query("SELECT id_usuario FROM Usuarios WHERE telefono = @telefono");

    if (userPhone.recordset.length > 0)
      return res.status(409).json({ error: "El número de teléfono ya está registrado" });

    // 🔹 Cifrar contraseña
    const contrasenaHash = await bcrypt.hash(contrasena, 12);

    // 🔹 Crear usuario en la BD
    await UserModel.create(pool, {
      nombre,
      apaterno,
      amaterno,
      correo,
      telefono,
      contrasenaHash,
      metodo: "2FA",
      proveedor: null,
    });

    res.status(201).json({
      message: "✅ Usuario registrado correctamente con autenticación 2FA",
    });
  } catch (err) {
    console.error("❌ Error en registro:", err);
    res.status(500).json({ error: "Error interno del servidor" });
  }
},

  /**  Verifica si un correo ya está registrado */
  checkEmail: async (req, res) => {
    try {
      const { correo } = req.query;
      if (!correo) return res.status(400).json({ error: "Correo requerido" });

      const pool = await poolPromise;
      const result = await pool
        .request()
        .input("correo", sql.NVarChar(100), correo)
        .query("SELECT id_usuario FROM Usuarios WHERE correo = @correo");

      res.json({ exists: result.recordset.length > 0 });
    } catch (err) {
      console.error("❌ Error en checkEmail:", err);
      res.status(500).json({ error: "Error interno del servidor" });
    }
  },

  /**  Verifica si un teléfono ya está registrado */
  checkPhone: async (req, res) => {
    try {
      const { telefono } = req.query;
      if (!telefono) return res.status(400).json({ error: "Teléfono requerido" });

      const pool = await poolPromise;
      const result = await pool
        .request()
        .input("telefono", sql.NVarChar(20), telefono)
        .query("SELECT id_usuario FROM Usuarios WHERE telefono = @telefono");

      res.json({ exists: result.recordset.length > 0 });
    } catch (err) {
      console.error("❌ Error en checkPhone:", err);
      res.status(500).json({ error: "Error interno del servidor" });
    }
  },

  /**
   * ================================================================
   *  MÉTODO 1️ — LOGIN NORMAL (CONTRASEÑA + TOKEN INTERNO JWT + REFRESH TOKEN)
   * ================================================================
   */
  login: async (req, res) => {
    try {
      const pool = await poolPromise;
      const { correo, contrasena } = req.body;

      if (!correo || !contrasena)
        return res.status(400).json({ error: "Faltan credenciales" });

      const user = await UserModel.findByEmail(pool, correo);
      if (!user)
        return res.status(401).json({ error: "Correo incorrecto" });

      const validPassword = await bcrypt.compare(contrasena, user.contrasena);
      if (!validPassword)
        return res.status(401).json({ error: "Contraseña incorrecta" });

      // ✅ Generar access token JWT
      const accessToken = JWTService.generateToken(
        { id: user.id_usuario, correo: user.correo },
        "15m" // duración corta
      );

      // ✅ Generar refresh token (UUID aleatorio)
      const refreshToken = uuidv4();
      await RefreshModel.save(pool, user.id_usuario, refreshToken, 7); // 7 días

      // ✅ Guardar sesión en SesionesJWT
      await SessionModel.save(pool, user.id_usuario, accessToken, req.ip);

      res.status(200).json({
        message: "Inicio de sesión exitoso",
        accessToken,
        refreshToken,
        user: {
          id: user.id_usuario,
          nombre: user.nombre,
          correo: user.correo,
        },
      });
    } catch (err) {
      console.error("❌ Error en login:", err);
      res.status(500).json({ error: "Error interno del servidor" });
    }
  },

  /**
   * ================================================================
   * REFRESH TOKEN — ROTACIÓN DE TOKENS
   * ================================================================
   */
  refreshToken: async (req, res) => {
    try {
      const pool = await poolPromise;
      const { id_usuario, refreshToken } = req.body;

      if (!id_usuario || !refreshToken)
        return res.status(400).json({ error: "Faltan datos" });

      const valid = await RefreshModel.validate(pool, id_usuario, refreshToken);
      if (!valid)
        return res.status(401).json({ error: "Refresh token inválido o expirado" });

      // ✅ Generar nuevos tokens
      const newAccess = JWTService.generateToken({ id: id_usuario }, "15m");
      const newRefresh = uuidv4();

      // ✅ Rotar tokens
      await RefreshModel.save(pool, id_usuario, newRefresh, 7);

      res.status(200).json({
        message: "Tokens renovados correctamente",
        accessToken: newAccess,
        refreshToken: newRefresh,
      });
    } catch (err) {
      console.error("❌ Error en refresh token:", err);
      res.status(500).json({ error: "Error al renovar token" });
    }
  },


 /**
   * ================================================================
   * MÉTODO LOGOUT — CIERRE TOTAL DE SESIÓN
   * ================================================================
   * Este método:
   * 1️ Valida el token enviado por header (Bearer)
   * 2️ Marca la sesión JWT como cerrada
   * 3️ Revoca el refresh token en TokensRefresh
   * ================================================================
   */
  logout: async (req, res) => {
    try {
      const pool = await poolPromise;
      const authHeader = req.headers.authorization;
      const token = authHeader && authHeader.split(" ")[1];
      const { id_usuario } = req.body; // opcional para refrescos futuros

      if (!token)
        return res.status(400).json({ error: "Token no proporcionado" });

      // ✅ Verificar que el token JWT sea válido
      const decoded = JWTService.verifyToken(token);
      if (!decoded)
        return res.status(403).json({ error: "Token inválido o expirado" });

      const userId = id_usuario || decoded.id;

      // ✅ 1. Marcar la sesión JWT como cerrada
      await pool.request()
        .input("id_usuario", sql.Int, userId)
        .query(`
          UPDATE SesionesJWT
          SET fecha_cierre = GETDATE()
          WHERE id_usuario = @id_usuario AND fecha_cierre IS NULL
        `);

      // ✅ 2. Revocar el refresh token activo
      await RefreshModel.revoke(pool, userId);

      // ✅ 3. (Opcional) Limpieza de tokens 2FA expirados
      await pool.request()
        .input("id_usuario", sql.Int, userId)
        .query(`
          UPDATE Tokens2FA
          SET estado = 'Expirado'
          WHERE id_usuario = @id_usuario AND fecha_expiracion < GETDATE()
        `);

      // ✅ 4. Respuesta exitosa
      res.status(200).json({
        message: "✅ Sesión cerrada correctamente",
        user: {
          id_usuario: userId,
        },
      });
    } catch (err) {
      console.error("❌ Error en logout:", err);
      res.status(500).json({ error: "Error interno al cerrar sesión" });
    }
  },

};
