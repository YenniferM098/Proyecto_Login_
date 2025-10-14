import express from "express";
import { WebAuthnController } from "../controllers/webauthn.controller.js";

const router = express.Router();

router.post("/register/options", WebAuthnController.registerOptions);
router.post("/register/verify", WebAuthnController.registerVerify);
router.post("/authenticate", WebAuthnController.authenticate);

export default router;
