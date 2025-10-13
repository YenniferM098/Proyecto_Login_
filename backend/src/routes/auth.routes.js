 import express from 'express';
import { AuthController } from '../controllers/auth.controller.js';

const router = express.Router();

// Registro
router.post('/register', AuthController.register);

// Inicio de sesión
router.post('/login', AuthController.login);

// Login alternativo por SMS
router.post("/sms/login", AuthController.sendSMSLogin);
router.post("/sms/verify", AuthController.verifySMSLogin);


export default router;
