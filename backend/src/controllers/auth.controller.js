import bcrypt from "bcryptjs";
import { poolPromise } from "../config/db.config.js";
import { UserModel } from "../models/user.model.js";
import { JWTService } from "../services/jwt.service.js";
import { TwoFAService } from "../services/twofa.service.js";
import { TokenModel } from "../models/token.model.js";
import { SMSService } from "../services/sms.service.js";
import dotenv from "dotenv";
dotenv.config();

export const AuthController = {
/**
 * ================================================================
 *  MÉTODO 0️⃣ — REGISTRO DE USUARIO (valida correo y teléfono únicos)
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

  /**
   * ================================================================
   *  MÉTODO 1️⃣ — LOGIN NORMAL (CONTRASEÑA + TOKEN INTERNO JWT)
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
        return res.status(401).json({ error: "Correo o contraseña inválidos" });

      const validPassword = await bcrypt.compare(contrasena, user.contrasena);
      if (!validPassword)
        return res.status(401).json({ error: "Correo o contraseña inválidos" });

      // Generar JWT
      const token = JWTService.generateToken({
        id: user.id_usuario,
        correo: user.correo,
      });

      // Generar token 2FA temporal
      const otp = TwoFAService.generateOTP();
      const otpHash = await bcrypt.hash(otp, 10);
      const fechaExp = new Date(Date.now() + 60 * 1000);
      await TokenModel.save(pool, user.id_usuario, otpHash, "2FA", fechaExp);

      res.status(200).json({
        message: "Inicio de sesión exitoso",
        token,
        otp,
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
 *  MÉTODO 2️⃣ — AUTENTICACIÓN POR SMS (OTP REAL CON PREFIJO +52)
 * ================================================================
 * - Verifica si el número existe en la BD
 * - Genera un código OTP de 6 dígitos
 * - Cifra y guarda en la tabla Tokens2FA
 * - Envía el SMS real usando Textbelt
 * ================================================================
 */
loginSMS: async (req, res) => {
  try {
    const pool = await poolPromise;
    const { telefono } = req.body;

    if (!telefono)
      return res.status(400).json({ error: "Falta el número de teléfono" });

    // 🔹 Verificar existencia del usuario por número
    const result = await pool.request()
      .input("telefono", telefono)
      .query("SELECT * FROM Usuarios WHERE telefono = @telefono");

    if (!result.recordset.length)
      return res.status(404).json({ error: "Teléfono no registrado" });

    const user = result.recordset[0];

    // 🔹 Generar OTP de 6 dígitos
    const otp = Math.floor(100000 + Math.random() * 900000);

    // 🔹 Cifrar y guardar en Tokens2FA
    const otpHash = await bcrypt.hash(String(otp), 10);
    const fechaExp = new Date(Date.now() + 60 * 1000); // Expira en 1 min

    await TokenModel.save(pool, user.id_usuario, otpHash, "SMS", fechaExp);

    // 🔹 Agregar prefijo automático (+52)
    let telefonoFormateado = user.telefono;
    if (!telefonoFormateado.startsWith("+")) {
      telefonoFormateado = "+52" + telefonoFormateado;
    }

    // 🔹 Enviar SMS real con Textbelt
    await SMSService.sendSMS(
      telefonoFormateado,
      `Tu código de acceso es: ${otp}`
    );

    res.status(200).json({
      message: "Código OTP enviado correctamente por SMS",
      telefono: telefonoFormateado,
    });
  } catch (err) {
    console.error("❌ Error en loginSMS:", err);
    res.status(500).json({ error: "Error al enviar SMS" });
  }
},


  /**
   * ================================================================
   *  MÉTODO 3️⃣ — VERIFICAR CÓDIGO OTP DEL SMS
   * ================================================================
   */
  verifySMS: async (req, res) => {
    try {
      const pool = await poolPromise;
      const { telefono, otp } = req.body;

      if (!telefono || !otp)
        return res.status(400).json({ error: "Faltan datos" });

      const result = await pool.request()
        .input("telefono", telefono)
        .query("SELECT * FROM Usuarios WHERE telefono = @telefono");

      if (!result.recordset.length)
        return res.status(404).json({ error: "Teléfono no registrado" });

      const user = result.recordset[0];

      const tokenData = await TokenModel.findLatest(pool, user.id_usuario);
      if (!tokenData)
        return res.status(404).json({ error: "No hay código activo" });

      const valid = await bcrypt.compare(String(otp), tokenData.codigo_otp);
      if (!valid)
        return res.status(401).json({ error: "Código incorrecto o expirado" });

      // Generar JWT de sesión al autenticar por SMS
      const token = JWTService.generateToken({
        id: user.id_usuario,
        telefono: user.telefono,
      });

      // Marcar OTP como usado
      await pool.request()
        .input("id_token", tokenData.id_token)
        .query("UPDATE Tokens2FA SET estado = 'Usado' WHERE id_token = @id_token");

      res.status(200).json({
        message: "✅ Autenticación por SMS exitosa",
        token,
        user: {
          id: user.id_usuario,
          nombre: user.nombre,
          telefono: user.telefono,
        },
      });
    } catch (err) {
      console.error("❌ Error en verifySMS:", err);
      res.status(500).json({ error: "Error al verificar OTP" });
    }
  },
};
