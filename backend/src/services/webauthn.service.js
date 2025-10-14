import { Fido2Lib } from "fido2-lib";
import base64url from "base64url";

const f2l = new Fido2Lib({
  timeout: 60000,
  rpId: "localhost",          // Dominio del servidor (en producción será tu dominio)
  rpName: "Autenticacion", // Nombre de tu app
  challengeSize: 64,
  attestation: "none",
  cryptoParams: [-7, -257],   // ES256 y RS256
});

export const WebAuthnService = {
  async generateRegistrationOptions(user) {
    const registrationOptions = await f2l.attestationOptions();
    registrationOptions.user = {
      id: base64url(Buffer.from(String(user.id_usuario))),
      name: user.correo,
      displayName: user.nombre || user.correo,
    };
    registrationOptions.challenge = base64url(registrationOptions.challenge);
    // Puedes guardar este challenge temporalmente en sesión o tabla
    return registrationOptions;
  },

  async verifyRegistration(attestationResponse, expectedChallenge) {
    const attestationExpectations = {
      challenge: expectedChallenge,
      origin: "http://localhost:4200", // dominio del front Angular
      factor: "either",
    };
    const regResult = await f2l.attestationResult(attestationResponse, attestationExpectations);

    return {
      credentialId: regResult.authnrData.get("credId"),
      publicKey: regResult.authnrData.get("credentialPublicKeyPem"),
      signCount: regResult.authnrData.get("signCount"),
    };
  },

  async generateAuthenticationOptions(registeredCredentials) {
    const authnOptions = await f2l.assertionOptions();
    authnOptions.challenge = base64url(authnOptions.challenge);
    authnOptions.allowCredentials = registeredCredentials.map((cred) => ({
      type: "public-key",
      id: base64url(Buffer.from(cred.credential_id)),
    }));
    return authnOptions;
  },

  async verifyAuthentication(assertionResponse, expectedChallenge, storedPublicKeyPem, prevSignCount) {
    const assertionExpectations = {
      challenge: expectedChallenge,
      origin: "http://localhost:4200",
      factor: "either",
      publicKey: storedPublicKeyPem,
      prevCounter: prevSignCount,
    };
    const authnResult = await f2l.assertionResult(assertionResponse, assertionExpectations);
    return { newCounter: authnResult.authnrData.get("signCount") };
  },
};
