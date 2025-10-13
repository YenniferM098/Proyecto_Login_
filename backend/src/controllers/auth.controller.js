import bcrypt from "bcryptjs";
import { poolPromise } from "../config/db.config.js";
import { UserModel } from "../models/user.model.js";
import { TokenModel } from "../models/token.model.js";
import { JWTService } from "../services/jwt.service.js";
import { TwoFAService } from "../services/twofa.service.js";
import { SMSService } from "../services/sms.service.js";
import dotenv from "dotenv";
dotenv.config();

export const AuthController = {
  /**
   * Registro de usuario con autenticación 2FA por defecto
   */
  register: async (req, res) => {
    try {
      const pool = await poolPromise;
      const { nombre, apaterno, amaterno, correo, telefono, contrasena } = req.body;

      if (!nombre || !apaterno || !amaterno || !correo || !contrasena)
        return res.status(400).json({ error: "Faltan datos obligatorios" });

      const userExist = await UserModel.findByEmail(pool, correo);
      if (userExist)
        return res.status(409).json({ error: "El correo ya está registrado" });

      const contrasenaHash = await bcrypt.hash(contrasena, 12);

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

      res.status(201).json({ message: "Usuario registrado correctamente con 2FA" });
    } catch (err) {
      console.error("❌ Error en registro:", err);
      res.status(500).json({ error: "Error interno del servidor" });
    }
  },

  /**
   * Login con autenticación 2FA automática
   * (contraseña + token interno generado/validado)
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

      // Verifica si tiene activo el método 2FA
      if (user.metodo_autenticacion === "2FA") {
        // 1️⃣ Generar OTP temporal
        const otp = TwoFAService.generateOTP();
        const hashOTP = await TwoFAService.hashOTP(otp);

        // 2️⃣ Guardar OTP cifrado en BD
        await TokenModel.save(pool, user.id_usuario, hashOTP, "2FA");

        // 3️⃣ Validar internamente el OTP (automático)
        const valid = await TwoFAService.verifyOTP(otp, hashOTP);
        if (!valid) return res.status(401).json({ error: "Falla en validación 2FA" });

        // 4️⃣ Generar el JWT final
        const token = JWTService.generateToken({
          id: user.id_usuario,
          correo: user.correo,
        });

        return res.status(200).json({
          message: "✅ Autenticación 2FA completada correctamente",
          token,
          user: {
            id: user.id_usuario,
            nombre: user.nombre,
            correo: user.correo,
          },
        });
      }

      res.status(403).json({ error: "Método de autenticación no permitido." });
    } catch (err) {
      console.error("❌ Error en login:", err);
      res.status(500).json({ error: "Error interno del servidor" });
    }
  },

  /**
   * Autenticación por SMS (sin contraseña)
   */
sendSMSLogin: async (req, res) => {
  try {
    const pool = await poolPromise;
    const { telefono } = req.body;

    if (!telefono)
      return res.status(400).json({ error: "Número de teléfono requerido" });

    const user = await UserModel.findByPhone(pool, telefono);
    if (!user)
      return res.status(404).json({ error: "Número no registrado" });

    // 1️⃣ Generar código temporal de 6 dígitos
    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    // 2️⃣ Cifrar el OTP para almacenarlo
    const hashOTP = await TwoFAService.hashOTP(otp);

    // 3️⃣ Calcular fecha de expiración (1 minuto)
    const fechaExp = new Date(Date.now() + 60 * 1000);

    // 4️⃣ Guardar el token en BD
    await TokenModel.save(pool, user.id_usuario, hashOTP, "SMS", fechaExp);

    // 5️⃣ Enviar el código por SMS (simulado o Twilio)
    await SMSService.sendSMS(telefono, `Tu código de acceso es: ${otp}`);

    res.status(200).json({
      message: "Código enviado al teléfono",
      telefono,
      expires_in: 60,
    });
  } catch (err) {
    console.error("❌ Error en sendSMSLogin:", err);
    res.status(500).json({ error: "Error al enviar código SMS" });
  }
},

  verifySMSLogin: async (req, res) => {
    try {
      const pool = await poolPromise;
      const { telefono, otp } = req.body;

      const user = await UserModel.findByPhone(pool, telefono);
      if (!user)
        return res.status(404).json({ error: "Usuario no encontrado" });

      const tokenDB = await TokenModel.findLatest(pool, user.id_usuario);
      if (!tokenDB)
        return res.status(404).json({ error: "No hay token activo" });

      const valid = await TwoFAService.verifyOTP(otp, tokenDB.codigo_otp);
      const expired = TwoFAService.isExpired(tokenDB.fecha_expiracion);

      if (!valid || expired)
        return res.status(401).json({ error: "Código inválido o expirado" });

      const token = JWTService.generateToken({
        id: user.id_usuario,
        correo: user.correo,
      });

      res.status(200).json({
        message: "Inicio de sesión por SMS exitoso",
        token,
        user: {
          id: user.id_usuario,
          nombre: user.nombre,
          telefono: user.telefono,
        },
      });
    } catch (err) {
      console.error("❌ Error en verifySMSLogin:", err);
      res.status(500).json({ error: "Error al verificar código SMS" });
    }
  },
};
