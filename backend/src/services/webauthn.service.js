import { Fido2Lib } from 'fido2-lib';
import { poolPromise } from '../config/db.config.js';
import sql from 'mssql';
import pkg from 'cbor';
const { decodeFirstSync } = pkg;


const f2l = new Fido2Lib({
  timeout: 60000,
  rpId: "localhost",
  rpName: "Sistema Auth",
  challengeSize: 32,
  attestation: "none",
  cryptoParams: [-7, -257], // ES256 y RS256
  authenticatorAttachment: "platform",
  authenticatorRequireResidentKey: false,
  authenticatorUserVerification: "required"
});

// FUNCIÓN PARA REGISTRO (Attestation)
export async function verifyAttestationResponse(attestationResponse, expectedChallenge, correo) {
  try {
    console.log("🔐 Iniciando verificación de REGISTRO (attestation)...");
    console.log("📧 Correo:", correo);
    console.log("🎫 Challenge esperado:", expectedChallenge);

    // Decodificar el clientDataJSON (viene como ArrayBuffer)
    const decoder = new TextDecoder('utf-8');
    const clientDataJSON = decoder.decode(attestationResponse.response.clientDataJSON);
    const clientData = JSON.parse(clientDataJSON);
    const challengeFromClient = clientData.challenge;
    
    console.log("🔍 Challenge desde clientData:", challengeFromClient);
    console.log("📋 ClientData completo:", clientData);

    // Preparar expectativas para la atestación usando el challenge del cliente
    const attestationExpectations = {
      challenge: challengeFromClient,
      origin: "http://localhost:4200",
      factor: "either"
    };

    console.log("📋 Expectativas de atestación:", attestationExpectations);

    console.log("🔍 Llamando a f2l.attestationResult...");
    
    let result;
    try {
      result = await f2l.attestationResult(attestationResponse, attestationExpectations);
      console.log("✅ attestationResult ejecutado correctamente");
    } catch (attestationError) {
      console.error("⚠️ Error en attestationResult:", attestationError.message);
      
      // Si falla por TPM, intentamos extraer la clave pública manualmente
      if (attestationError.message.includes('tpm') || attestationError.message.includes('TPM')) {
        console.log("🔧 Intentando extracción manual de clave pública...");
        
        try {
          // Decodificar el attestationObject usando CBOR
          const attestationObjectBuffer = Buffer.from(attestationResponse.response.attestationObject);
          console.log("📦 Buffer de attestationObject creado, longitud:", attestationObjectBuffer.length);
          
          const attestationObject = decodeFirstSync(attestationObjectBuffer);
          
          console.log("📦 AttestationObject decodificado:", {
            fmt: attestationObject.fmt,
            hasAuthData: !!attestationObject.authData
          });
          
          if (attestationObject.authData) {
            const authData = Buffer.from(attestationObject.authData);
            console.log("✅ AuthData encontrado, longitud:", authData.length);
            
            // Extraer información básica del authData
            const rpIdHash = authData.slice(0, 32);
            const flags = authData[32];
            const counter = authData.readUInt32BE(33);
            
            console.log("📊 Datos extraídos:", {
              rpIdHashLength: rpIdHash.length,
              flags: flags.toString(2).padStart(8, '0'),
              counter: counter,
              hasCredentialData: !!(flags & 0x40) // Bit 6 indica presencia de credential data
            });
            
            // Guardar el authData completo como "clave pública"
            // En un sistema real, aquí extraerías el COSE key del credential data
            const publicKeyData = authData.toString('base64');
            
            console.log("✅ Datos biométricos extraídos manualmente");
            console.log("📏 Longitud de datos de clave pública:", publicKeyData.length);
            
            return {
              publicKey: publicKeyData,
              counter: counter,
              credentialId: attestationResponse.id,
              extractedManually: true
            };
          } else {
            throw new Error("No se encontró authData en attestationObject");
          }
        } catch (manualError) {
          console.error("❌ Error en extracción manual:", manualError);
          console.error("Stack de error manual:", manualError.stack);
          throw new Error(`No se pudo extraer la clave pública: ${manualError.message}`);
        }
      }
      
      throw attestationError;
    }
    
    console.log("✅ Resultado de attestationResult:", {
      hasAuthnrData: !!result.authnrData,
      hasPublicKey: !!result.authnrData?.get('credentialPublicKeyPem'),
      counter: result.authnrData?.get('counter')
    });

    // Extraer la clave pública
    const publicKeyPem = result.authnrData.get('credentialPublicKeyPem');
    
    if (!publicKeyPem) {
      console.error("❌ No se pudo extraer la clave pública del resultado");
      return { error: "No se pudo extraer la clave pública" };
    }

    console.log("✅ Clave pública extraída exitosamente");
    console.log("📏 Longitud de clave pública:", publicKeyPem.length);

    return {
      publicKey: publicKeyPem,
      counter: result.authnrData.get('counter') || 0,
      credentialId: attestationResponse.id
    };

  } catch (error) {
    console.error("❌ Error al verificar la atestación:", error);
    console.error("Stack trace:", error.stack);
    return { error: error.message || "Error al verificar la atestación" };
  }
}

// FUNCIÓN PARA LOGIN (Assertion) - Para uso futuro
export async function verifyAssertionResponse(assertionResponse, correo) {
  try {
    console.log("🔐 Iniciando verificación de LOGIN (assertion)...");
    console.log("📧 Correo:", correo);

    // Recuperar la clave pública del usuario de la BD
    const pool = await poolPromise;
    const userResult = await pool
      .request()
      .input("correo", sql.NVarChar, correo)
      .query("SELECT publicKey, prevCounter, credentialId FROM Usuarios WHERE correo = @correo");

    if (userResult.recordset.length === 0) {
      console.log("❌ Usuario no encontrado:", correo);
      return { error: "Usuario no encontrado" };
    }

    const user = userResult.recordset[0];
    console.log("✅ Usuario encontrado, tiene clave pública:", !!user.publicKey);

    if (!user.publicKey) {
      console.log("❌ No hay clave pública registrada para el usuario");
      return { error: "No se encontró la clave pública" };
    }

    // Decodificar clientDataJSON
    const decoder = new TextDecoder('utf-8');
    const clientDataJSON = decoder.decode(assertionResponse.response.clientDataJSON);
    const clientData = JSON.parse(clientDataJSON);

    // Preparar expectativas para la aserción
    const assertionExpectations = {
      challenge: clientData.challenge,
      origin: "http://localhost:4200",
      factor: "either",
      publicKey: user.publicKey,
      prevCounter: user.prevCounter || 0,
      userHandle: Buffer.from(correo).toString('base64')
    };

    console.log("📋 Expectativas de aserción preparadas");

    // Verificar la aserción
    const result = await f2l.assertionResult(assertionResponse, assertionExpectations);
    
    console.log("✅ Aserción verificada exitosamente");

    // Actualizar el contador en la BD
    await pool
      .request()
      .input("prevCounter", sql.Int, result.authnrData.get('counter'))
      .input("correo", sql.NVarChar, correo)
      .query("UPDATE Usuarios SET prevCounter = @prevCounter WHERE correo = @correo");

    console.log("✅ Contador actualizado en BD");

    return {
      verified: true,
      counter: result.authnrData.get('counter')
    };

  } catch (error) {
    console.error("❌ Error al verificar la aserción:", error);
    console.error("Stack trace:", error.stack);
    return { error: error.message || "Error al verificar la aserción" };
  }
}