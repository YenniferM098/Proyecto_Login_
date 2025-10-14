export const OAuthController = {
  success: (req, res) => {
    if (!req.user)
      return res.status(401).json({ error: "No se pudo autenticar el usuario" });
    res.status(200).json({
      message: "✅ Inicio de sesión con OAuth exitoso",
      user: {
        id: req.user.id_usuario,
        nombre: req.user.nombre,
        correo: req.user.correo,
        proveedor: req.user.proveedor_oauth,
      },
    });
  },

  failure: (req, res) => {
    res.status(401).json({ error: "❌ Falló la autenticación con proveedor" });
  },
};

