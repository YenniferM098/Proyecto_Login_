import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as FacebookStrategy } from "passport-facebook";
import { poolPromise } from "../config/db.config.js";
import sql from "mssql";

// --- Estrategia GOOGLE ---
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CALLBACK_URL,
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const pool = await poolPromise;
        const email = profile.emails?.[0]?.value;
        const nombre = profile.displayName || "Usuario Google";
        const proveedor = "Google";

        if (!email) return done(new Error("Google no proporcionó correo"), null);

        // Buscar usuario existente
        const result = await pool
          .request()
          .input("correo", sql.NVarChar, email)
          .query("SELECT * FROM Usuarios WHERE correo = @correo");

        let user;
        if (result.recordset.length > 0) {
          // Usuario ya existe, actualizar proveedor si falta
          user = result.recordset[0];
          if (!user.proveedor_oauth) {
            await pool.request()
              .input("correo", sql.NVarChar, email)
              .input("proveedor_oauth", sql.NVarChar, proveedor)
              .query("UPDATE Usuarios SET proveedor_oauth = @proveedor_oauth WHERE correo = @correo");
          }
        } else {
          // Registrar nuevo usuario desde OAuth
          const insert = await pool.request()
            .input("nombre", sql.NVarChar, nombre)
            .input("correo", sql.NVarChar, email)
            .input("telefono", sql.NVarChar, "")
            .input("contrasena", sql.NVarChar, "") // vacío, ya que OAuth no usa contraseña
            .input("metodo_autenticacion", sql.NVarChar, "OAuth")
            .input("proveedor_oauth", sql.NVarChar, proveedor)
            .query(`
              INSERT INTO Usuarios (nombre, correo, telefono, contrasena, metodo_autenticacion, proveedor_oauth)
              OUTPUT INSERTED.*
              VALUES (@nombre, @correo, @telefono, @contrasena, @metodo_autenticacion, @proveedor_oauth)
            `);
          user = insert.recordset[0];
        }

        return done(null, user);
      } catch (err) {
        console.error("❌ Error en Google OAuth:", err);
        done(err, null);
      }
    }
  )
);

// --- Estrategia FACEBOOK ---
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      callbackURL: process.env.FACEBOOK_CALLBACK_URL,
      profileFields: ["id", "emails", "displayName"],
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const pool = await poolPromise;
        const email = profile.emails?.[0]?.value;
        const nombre = profile.displayName || "Usuario Facebook";
        const proveedor = "Facebook";

        if (!email) return done(new Error("Facebook no proporcionó correo"), null);

        const result = await pool
          .request()
          .input("correo", sql.NVarChar, email)
          .query("SELECT * FROM Usuarios WHERE correo = @correo");

        let user;
        if (result.recordset.length > 0) {
          user = result.recordset[0];
          if (!user.proveedor_oauth) {
            await pool.request()
              .input("correo", sql.NVarChar, email)
              .input("proveedor_oauth", sql.NVarChar, proveedor)
              .query("UPDATE Usuarios SET proveedor_oauth = @proveedor_oauth WHERE correo = @correo");
          }
        } else {
          const insert = await pool.request()
            .input("nombre", sql.NVarChar, nombre)
            .input("correo", sql.NVarChar, email)
            .input("telefono", sql.NVarChar, "")
            .input("contrasena", sql.NVarChar, "")
            .input("metodo_autenticacion", sql.NVarChar, "OAuth")
            .input("proveedor_oauth", sql.NVarChar, proveedor)
            .query(`
              INSERT INTO Usuarios (nombre, correo, telefono, contrasena, metodo_autenticacion, proveedor_oauth)
              OUTPUT INSERTED.*
              VALUES (@nombre, @correo, @telefono, @contrasena, @metodo_autenticacion, @proveedor_oauth)
            `);
          user = insert.recordset[0];
        }

        return done(null, user);
      } catch (err) {
        console.error("❌ Error en Facebook OAuth:", err);
        done(err, null);
      }
    }
  )
);

// Serialización / deserialización básica
passport.serializeUser((user, done) => done(null, user.id_usuario));
passport.deserializeUser(async (id, done) => {
  try {
    const pool = await poolPromise;
    const result = await pool
      .request()
      .input("id_usuario", sql.Int, id)
      .query("SELECT * FROM Usuarios WHERE id_usuario = @id_usuario");
    done(null, result.recordset[0]);
  } catch (err) {
    done(err, null);
  }
});

export default passport;
