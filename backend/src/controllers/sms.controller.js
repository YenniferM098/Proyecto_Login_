import bcrypt from "bcrypt";
import sql from "mssql";
import { poolPromise } from "../config/db.config.js";
import { TwilioService } from "../services/sms.service.js";
import { JWTService } from "../services/jwt.service.js";

export class SMSController {
  /**
   * Enviar OTP por SMS
   */
  static async sendOTP(req, res) {
    try {
      const { telefono } = req.body;

      if (!telefono)
        return res.status(400).json({ error: "Falta el número de teléfono" });

      const pool = await poolPromise;
      const result = await pool.request()
        .input("telefono", sql.NVarChar, telefono)
        .query("SELECT id_usuario FROM Usuarios WHERE telefono = @telefono");

      if (!result.recordset.length)
        return res.status(404).json({ error: "Teléfono no registrado" });

      const user = result.recordset[0];

      // 🔹 Generar OTP de 6 dígitos
      const otp = Math.floor(100000 + Math.random() * 900000);
      const otpHash = await bcrypt.hash(String(otp), 10);

      // 🔹 Guardar OTP en tabla Tokens2FA
      const fechaExp = new Date(Date.now() + 2 * 60 * 1000); // expira en 2 minutos
      await pool.request()
        .input("id_usuario", sql.Int, user.id_usuario)
        .input("codigo_otp", sql.NVarChar, otpHash)
        .input("tipo", sql.NVarChar, "SMS")
        .input("estado", sql.NVarChar, "Activo")
        .input("fecha_expiracion", sql.DateTime, fechaExp)
        .query(`
          INSERT INTO Tokens2FA (id_usuario, codigo_otp, tipo, estado, fecha_expiracion)
          VALUES (@id_usuario, @codigo_otp, @tipo, @estado, @fecha_expiracion)
        `);

      // 🔹 Formatear número con prefijo si falta
      const destino = telefono.startsWith("+") ? telefono : `+52${telefono}`;

      // 🔹 Enviar SMS real con Twilio
      const smsResult = await TwilioService.sendSMS(
        destino,
        `Tu código de acceso es: ${otp}`
      );

      if (!smsResult.success) throw new Error(smsResult.error);

      res.json({
        success: true,
        message: "Código OTP enviado correctamente",
        telefono: destino,
      });
    } catch (error) {
      console.error("❌ Error en sendOTP:", error);
      res.status(500).json({ error: "Error al enviar SMS", details: error.message });
    }
  }

  /**
   * Verificar OTP recibido y generar token JWT
   */
  static async verifyOTP(req, res) {
    try {
      const { telefono, otp } = req.body;

      if (!telefono || !otp)
        return res.status(400).json({ error: "Faltan datos" });

      const pool = await poolPromise;
      const userResult = await pool.request()
        .input("telefono", sql.NVarChar, telefono)
        .query("SELECT * FROM Usuarios WHERE telefono = @telefono");

      if (!userResult.recordset.length)
        return res.status(404).json({ error: "Teléfono no registrado" });

      const user = userResult.recordset[0];

      // 🔹 Obtener el último OTP activo
      const tokenResult = await pool.request()
        .input("id_usuario", sql.Int, user.id_usuario)
        .query(`
          SELECT TOP 1 * FROM Tokens2FA
          WHERE id_usuario = @id_usuario AND estado = 'Activo'
          ORDER BY id_token DESC
        `);

      if (!tokenResult.recordset.length)
        return res.status(404).json({ error: "No hay código activo" });

      const tokenData = tokenResult.recordset[0];

      const valido = await bcrypt.compare(String(otp), tokenData.codigo_otp);
      if (!valido)
        return res.status(401).json({ error: "Código incorrecto o expirado" });

      // 🔹 Marcar OTP como usado
      await pool.request()
        .input("id_token", sql.Int, tokenData.id_token)
        .query("UPDATE Tokens2FA SET estado = 'Usado' WHERE id_token = @id_token");

      // 🔹 Generar token JWT usando tu servicio
      const token = JWTService.generateToken(
        {
          id_usuario: user.id_usuario,
          telefono,
          nombre: user.nombre,
        },
        "1h" // duración del token
      );

      // ✅ Respuesta final
      res.json({
  success: true,
  message: "✅ Autenticación por SMS exitosa",
  token,
  user: {
    id: user.id_usuario,
    nombre: user.nombre,
    correo: user.correo || null, // si lo tienes
    telefono,
  },
});

    } catch (error) {
      console.error("❌ Error en verifyOTP:", error);
      res.status(500).json({ error: "Error al verificar OTP", details: error.message });
    }
  }
}
