import crypto from "crypto";
import jwt from "jsonwebtoken";
import sql from "mssql";
import bcrypt from "bcrypt";
import { poolPromise } from "../config/db.config.js";
import { verifyAttestationResponse, verifyAssertionResponse } from "../services/webauthn.service.js";

export class WebAuthnController {
  // -------------------------------
  // REGISTRO COMPLETO (Usuario + Biometría)
  // -------------------------------
  static async registerBiometric(req, res) {
    let transaction;
    try {
      const { nombre, apaterno, amaterno, correo, telefono, contrasena, biometria } = req.body;

      console.log("📝 Iniciando registro con biometría...");
      console.log("📧 Correo:", correo);
      console.log("🔐 Tipo biométrico:", biometria?.tipo);

      if (!nombre || !apaterno || !amaterno || !correo || !telefono || !contrasena) {
        return res.status(400).json({ error: "Faltan datos del usuario" });
      }
      if (!biometria || !biometria.tipo || !biometria.credentialData) {
        return res.status(400).json({ error: "Faltan datos biométricos" });
      }

      const pool = await poolPromise;
      transaction = new sql.Transaction(pool);
      await transaction.begin();

      // 1. Verificar correo
      const existingUser = await transaction
        .request()
        .input("correo", sql.NVarChar, correo)
        .query("SELECT id_usuario FROM Usuarios WHERE correo = @correo");

      if (existingUser.recordset.length > 0) {
        await transaction.rollback();
        return res.status(400).json({ error: "El correo ya está registrado" });
      }

      // 2. Crear usuario
      const hashedPassword = await bcrypt.hash(contrasena, 10);
      await transaction
        .request()
        .input("nombre", sql.NVarChar, nombre)
        .input("a_paterno", sql.NVarChar, apaterno)
        .input("a_materno", sql.NVarChar, amaterno)
        .input("correo", sql.NVarChar, correo)
        .input("telefono", sql.NVarChar, telefono)
        .input("contrasena", sql.NVarChar, hashedPassword)
        .query(`
          INSERT INTO Usuarios (nombre, a_paterno, a_materno, correo, telefono, contrasena)
          VALUES (@nombre, @a_paterno, @a_materno, @correo, @telefono, @contrasena)
        `);

      // 3. Procesar biometría
      const { tipo, challenge, credentialData } = biometria;
      const base64ToBuffer = (b64) => Buffer.from(b64, "base64");
      const bufferToArrayBuffer = (buf) => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
      const attestationData = {
        id: credentialData.id,
        rawId: bufferToArrayBuffer(base64ToBuffer(credentialData.rawId)),
        type: credentialData.type,
        response: {
          clientDataJSON: bufferToArrayBuffer(base64ToBuffer(credentialData.response.clientDataJSON)),
          attestationObject: bufferToArrayBuffer(base64ToBuffer(credentialData.response.attestationObject)),
        },
      };

      const verifyResult = await verifyAttestationResponse(attestationData, challenge, correo);
      if (verifyResult.error) {
        await transaction.rollback();
        return res.status(400).json({ error: verifyResult.error });
      }

      // 4. Guardar datos biométricos
      await transaction
        .request()
        .input("correo", sql.NVarChar, correo)
        .input("publicKey", sql.NVarChar(sql.MAX), verifyResult.publicKey)
        .input("credentialId", sql.NVarChar, credentialData.id)
        .input("huella_biometrica", sql.NVarChar, tipo)
        .input("counter", sql.Int, verifyResult.counter || 0)
        .query(`
          UPDATE Usuarios
          SET publicKey = @publicKey, credentialId = @credentialId,
              huella_biometrica = @huella_biometrica, prevCounter = @counter
          WHERE correo = @correo
        `);

      await transaction.commit();
      res.json({ success: true, message: "Usuario registrado con biometría exitosamente" });
    } catch (error) {
      if (transaction) await transaction.rollback();
      res.status(500).json({ error: "Error en el registro", details: error.message });
    }
  }

  // -------------------------------
  // OPCIONES DE REGISTRO
  // -------------------------------
  static registerOptions(req, res) {
    try {
      const { correo, tipo } = req.body;
      const challenge = crypto.randomBytes(32).toString("base64");

      const options = {
        challenge,
        rp: { name: "Sistema Auth", id: "localhost" },
        user: {
          id: Buffer.from(correo).toString("base64"),
          name: correo,
          displayName: correo,
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        timeout: 60000,
        authenticatorSelection: {
          authenticatorAttachment: tipo === "HUELLA" ? "platform" : "cross-platform",
          residentKey: "preferred",
          userVerification: "required",
        },
        attestation: "none",
      };

      res.json(options);
    } catch (error) {
      res.status(500).json({ error: "Error al generar opciones WebAuthn" });
    }
  }

  // -------------------------------
  // VERIFICAR REGISTRO
  // -------------------------------
  static async registerVerify(req, res) {
    try {
      const { correo, tipo, challenge, credentialData } = req.body;
      const base64ToBuffer = (b64) => Buffer.from(b64, "base64");
      const bufferToArrayBuffer = (buf) => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);

      const attestationData = {
        id: credentialData.id,
        rawId: bufferToArrayBuffer(base64ToBuffer(credentialData.rawId)),
        type: credentialData.type,
        response: {
          clientDataJSON: bufferToArrayBuffer(base64ToBuffer(credentialData.response.clientDataJSON)),
          attestationObject: bufferToArrayBuffer(base64ToBuffer(credentialData.response.attestationObject)),
        },
      };

      const result = await verifyAttestationResponse(attestationData, challenge, correo);
      if (result.error) return res.status(400).json({ error: result.error });

      const pool = await poolPromise;
      const update = await pool
        .request()
        .input("correo", sql.NVarChar, correo)
        .input("publicKey", sql.NVarChar(sql.MAX), result.publicKey)
        .input("credentialId", sql.NVarChar, credentialData.id)
        .input("huella_biometrica", sql.NVarChar, tipo)
        .input("counter", sql.Int, result.counter || 0)
        .query(`
          UPDATE Usuarios
          SET publicKey = @publicKey, credentialId = @credentialId,
              huella_biometrica = @huella_biometrica, prevCounter = @counter
          WHERE correo = @correo
        `);

      if (update.rowsAffected[0] === 0)
        return res.status(404).json({ error: "Usuario no encontrado" });

      res.json({ success: true, message: "Biometría registrada correctamente" });
    } catch (error) {
      res.status(500).json({ error: "Error al verificar la autenticación biométrica", details: error.message });
    }
  }

  // -------------------------------
  // OBTENER TIPO DE BIOMETRÍA
  // -------------------------------
  static async getTipo(req, res) {
    try {
      const { correo } = req.params;
      const pool = await poolPromise;
      const result = await pool
        .request()
        .input("correo", sql.NVarChar, correo)
        .query("SELECT huella_biometrica AS metodo FROM Usuarios WHERE correo = @correo");

      if (result.recordset.length === 0)
        return res.status(404).json({ error: "Usuario no encontrado o sin biometría" });

      res.json({ metodo: result.recordset[0].metodo });
    } catch (error) {
      res.status(500).json({ error: "Error al obtener tipo de biometría", details: error.message });
    }
  }

  // -------------------------------
  // OPCIONES DE AUTENTICACIÓN (LOGIN)
  // -------------------------------
  static async authOptions(req, res) {
    try {
      const { correo } = req.body;
      const pool = await poolPromise;
      const userRes = await pool
        .request()
        .input("correo", sql.NVarChar, correo)
        .query("SELECT credentialId, huella_biometrica FROM Usuarios WHERE correo = @correo");

      if (userRes.recordset.length === 0)
        return res.status(404).json({ error: "Usuario no encontrado" });

      const user = userRes.recordset[0];
      const challenge = crypto.randomBytes(32).toString("base64");

      const options = {
        challenge,
        timeout: 60000,
        rpId: "localhost",
        allowCredentials: [
          { type: "public-key", id: user.credentialId, transports: ["internal"] },
        ],
        userVerification: "required",
      };

      res.json(options);
    } catch (error) {
      res.status(500).json({ error: "Error al generar opciones de autenticación" });
    }
  }



 // -------------------------------
  // VERIFICAR AUTENTICACIÓN (LOGIN)
  // -------------------------------
  static async authVerify(req, res) {
    try {
      const { correo, assertionResponse } = req.body;
      const base64ToBuffer = (b64) => Buffer.from(b64, "base64");
      const bufferToArrayBuffer = (buf) => buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);

      const assertionData = {
        id: assertionResponse.id,
        rawId: bufferToArrayBuffer(base64ToBuffer(assertionResponse.rawId)),
        type: "public-key",
        response: {
          clientDataJSON: bufferToArrayBuffer(base64ToBuffer(assertionResponse.response.clientDataJSON)),
          authenticatorData: bufferToArrayBuffer(base64ToBuffer(assertionResponse.response.authenticatorData)),
          signature: bufferToArrayBuffer(base64ToBuffer(assertionResponse.response.signature)),
          userHandle: assertionResponse.response.userHandle
            ? bufferToArrayBuffer(base64ToBuffer(assertionResponse.response.userHandle))
            : null,
        },
      };

      const result = await verifyAssertionResponse(assertionData, correo);
      if (result.error) return res.status(400).json({ error: result.error });

      const pool = await poolPromise;
      const userRes = await pool
        .request()
        .input("correo", sql.NVarChar, correo)
        .query("SELECT * FROM Usuarios WHERE correo = @correo");

      if (userRes.recordset.length === 0)
        return res.status(404).json({ error: "Usuario no encontrado" });

      const user = userRes.recordset[0];
      
      // ✅ INCLUIR TODOS LOS DATOS EN EL TOKEN
      const token = jwt.sign(
        { 
          id_usuario: user.id_usuario,
          id: user.id_usuario, // Compatibilidad
          correo: user.correo,
          nombre: user.nombre,
          a_paterno: user.a_paterno,
          a_materno: user.a_materno,
          telefono: user.telefono,
          metodo_autenticacion: "Biometría",
          authMethod: "biometric"
        },
        process.env.JWT_SECRET || "tu_secreto_jwt",
        { expiresIn: "24h" }
      );

      // ✅ DEVOLVER DATOS COMPLETOS DEL USUARIO
      res.json({
        success: true,
        token,
        accessToken: token,
        user: { 
          id_usuario: user.id_usuario,
          nombre: user.nombre,
          a_paterno: user.a_paterno,
          a_materno: user.a_materno,
          correo: user.correo,
          telefono: user.telefono,
          metodo_autenticacion: "Biometría",
          estado: user.estado || "Activo"
        },
        message: "Autenticación biométrica exitosa",
      });
    } catch (error) {
      console.error("❌ Error en authVerify:", error);
      res.status(500).json({ error: "Error al verificar autenticación biométrica", details: error.message });
    }
  }
}
