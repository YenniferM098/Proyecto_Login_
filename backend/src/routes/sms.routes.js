import express from "express";
import { SMSController } from "../controllers/sms.controller.js";

const router = express.Router();

router.post("/send", SMSController.sendOTP);      // Enviar SMS OTP
router.post("/verify", SMSController.verifyOTP);  // Verificar SMS OTP

export default router;
