import express from "express";
import passport from "../services/oauth.service.js";
import { OAuthController } from "../controllers/oauth.controller.js";

const router = express.Router();

// --- GOOGLE ---
router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));
router.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/api/oauth/failure" }),
  OAuthController.success
);

// --- FACEBOOK ---
router.get("/facebook", passport.authenticate("facebook", { scope: ["email"] }));
router.get(
  "/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/api/oauth/failure" }),
  OAuthController.success
);

// --- FALLBACK ---
router.get("/failure", OAuthController.failure);

export default router;

