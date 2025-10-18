import express from "express";
import passport from "../services/oauth.service.js";
import { OAuthController } from "../controllers/oauth.controller.js";

const router = express.Router();

router.get("/google", passport.authenticate("google", { scope: ["profile", "email"] }));

router.get(
  "/google/callback",
  passport.authenticate("google", { failureRedirect: "/api/oauth/failure" }),
  OAuthController.success
);

router.get("/facebook", passport.authenticate("facebook", { scope: ["email"] }));

router.get(
  "/facebook/callback",
  passport.authenticate("facebook", { failureRedirect: "/api/oauth/failure" }),
  OAuthController.success
);

router.get("/failure", OAuthController.failure);

export default router;
