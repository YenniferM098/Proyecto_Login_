import express from "express";
import { WebAuthnController } from "../controllers/webauthn.controller.js";

const router = express.Router();

// Registro con biometría
router.post("/register/biometric", WebAuthnController.registerBiometric);
router.post("/register/options", WebAuthnController.registerOptions);
router.post("/register/verify", WebAuthnController.registerVerify);

// Consultar tipo biometría
router.get("/tipo/:correo", WebAuthnController.getTipo);

// Autenticación con biometría
router.post("/auth/options", WebAuthnController.authOptions);
router.post("/auth/verify", WebAuthnController.authVerify);

export default router;
