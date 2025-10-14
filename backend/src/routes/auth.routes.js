 import express from 'express';
import { AuthController } from '../controllers/auth.controller.js';

const router = express.Router();

// Registro
router.post('/register', AuthController.register);

// Inicio de sesión
router.post('/login', AuthController.login);

// Login por SMS (envía OTP)
router.post("/login-sms", AuthController.loginSMS);

// Verificación del código SMS
router.post("/verify-sms", AuthController.verifySMS);


export default router;
