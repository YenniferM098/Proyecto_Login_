import { poolPromise } from "../config/db.config.js";
import { WebAuthnService } from "../services/webauthn.service.js";

export const WebAuthnController = {
  // Genera las opciones para el registro biométrico
  registerOptions: async (req, res) => {
    try {
      const pool = await poolPromise;
      const { id_usuario } = req.body;

      const result = await pool.request()
        .input("id_usuario", id_usuario)
        .query("SELECT * FROM Usuarios WHERE id_usuario = @id_usuario");

      if (!result.recordset.length)
        return res.status(404).json({ error: "Usuario no encontrado" });

      const user = result.recordset[0];
      const options = await WebAuthnService.generateRegistrationOptions(user);

      res.status(200).json(options);
    } catch (err) {
      console.error("❌ Error en registerOptions:", err);
      res.status(500).json({ error: "Error al generar opciones de registro" });
    }
  },

  // Guarda los datos biométricos en la tabla Usuarios
  registerVerify: async (req, res) => {
    try {
      const pool = await poolPromise;
      const { id_usuario, attestationResponse, challenge } = req.body;

      // Verificar la respuesta biométrica
      const result = await WebAuthnService.verifyRegistration(attestationResponse, challenge);

      // Estructura a guardar
      const biometriaData = {
        credentialId: result.credentialId.toString("base64"),
        publicKey: result.publicKey,
        signCount: result.signCount
      };

      // Guardar en el campo huella_biometrica
      await pool.request()
        .input("id_usuario", id_usuario)
        .input("huella_biometrica", JSON.stringify(biometriaData))
        .query(`
          UPDATE Usuarios
          SET huella_biometrica = @huella_biometrica
          WHERE id_usuario = @id_usuario
        `);

      res.status(200).json({ message: "✅ Biometría registrada correctamente" });
    } catch (err) {
      console.error("❌ Error en registerVerify:", err);
      res.status(500).json({ error: "Error al registrar biometría" });
    }
  },

  // Verifica autenticación biométrica
  authenticate: async (req, res) => {
    try {
      const pool = await poolPromise;
      const { id_usuario, assertionResponse, challenge } = req.body;

      // Obtener datos guardados
      const result = await pool.request()
        .input("id_usuario", id_usuario)
        .query("SELECT huella_biometrica FROM Usuarios WHERE id_usuario = @id_usuario");

      if (!result.recordset.length)
        return res.status(404).json({ error: "Usuario no encontrado" });

      const biometriaData = JSON.parse(result.recordset[0].huella_biometrica);

      // Verificar autenticación
      const verifyResult = await WebAuthnService.verifyAuthentication(
        assertionResponse,
        challenge,
        biometriaData.publicKey,
        biometriaData.signCount
      );

      // Actualizar contador
      biometriaData.signCount = verifyResult.newCounter;

      await pool.request()
        .input("id_usuario", id_usuario)
        .input("huella_biometrica", JSON.stringify(biometriaData))
        .query(`
          UPDATE Usuarios
          SET huella_biometrica = @huella_biometrica
          WHERE id_usuario = @id_usuario
        `);

      res.status(200).json({ message: "✅ Autenticación biométrica exitosa" });
    } catch (err) {
      console.error("❌ Error en authenticate:", err);
      res.status(500).json({ error: "Error al autenticar biometría" });
    }
  },
};
