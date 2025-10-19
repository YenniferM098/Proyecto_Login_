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

        if (!email) {
          return done(null, false, { 
            message: "Google no proporcionó un correo electrónico. Por favor, autoriza el permiso de email." 
          });
        }

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
            user.proveedor_oauth = proveedor;
          }
        } else {
          // Registrar nuevo usuario desde OAuth
          const insert = await pool.request()
            .input("nombre", sql.NVarChar, nombre)
            .input("correo", sql.NVarChar, email)
            .input("telefono", sql.NVarChar, null)
            .input("contrasena", sql.NVarChar, "OAUTH_NO_PASSWORD") // ✅ Contraseña ficticia
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
      profileFields: ["id", "emails", "name", "displayName"],
      profileURL: "https://graph.facebook.com/v18.0/me?fields=id,name,email,first_name,last_name",
      enableProof: true
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const pool = await poolPromise;
        
        // DEBUG: Ver qué información proporciona Facebook
        console.log("📊 Facebook Profile completo:", JSON.stringify(profile, null, 2));
        console.log("📧 Emails recibidos:", profile.emails);
        console.log("🔍 _raw data:", profile._raw);
        console.log("🔍 _json data:", profile._json);
        
        const email = profile.emails?.[0]?.value || profile._json?.email;
        const nombre = profile.displayName || profile.name?.givenName || "Usuario Facebook";
        const proveedor = "Facebook";
        const facebookId = profile.id;

        // Si no hay email, crear cuenta temporal con Facebook ID
        if (!email) {
          console.warn("⚠️ Facebook no proporcionó email");
          console.warn("🔍 Creando cuenta temporal con Facebook ID");
          
          // Usar Facebook ID como email temporal
          const tempEmail = `facebook_${facebookId}@temp.oauth`;
          
          // Buscar si ya existe un usuario con este Facebook ID
          const result = await pool
            .request()
            .input("tempEmail", sql.NVarChar, tempEmail)
            .query("SELECT * FROM Usuarios WHERE correo = @tempEmail");

          let user;
          if (result.recordset.length > 0) {
            user = result.recordset[0];
            console.log("✅ Usuario existente encontrado:", user.nombre);
          } else {
            const insert = await pool.request()
              .input("nombre", sql.NVarChar, nombre)
              .input("correo", sql.NVarChar, tempEmail)
              .input("telefono", sql.NVarChar, null) // ✅ NULL en lugar de ""
              .input("contrasena", sql.NVarChar, null) // ✅ NULL en lugar de ""
              .input("metodo_autenticacion", sql.NVarChar, "OAuth")
              .input("proveedor_oauth", sql.NVarChar, proveedor)
              .query(`
                INSERT INTO Usuarios (nombre, correo, telefono, contrasena, metodo_autenticacion, proveedor_oauth)
                OUTPUT INSERTED.*
                VALUES (@nombre, @correo, @telefono, @contrasena, @metodo_autenticacion, @proveedor_oauth)
              `);
            user = insert.recordset[0];
            console.log("✅ Nuevo usuario creado con email temporal:", tempEmail);
          }
          
          return done(null, user);
        }

        // Si hay email, proceder normalmente
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
            user.proveedor_oauth = proveedor;
          }
        } else {
          const insert = await pool.request()
            .input("nombre", sql.NVarChar, nombre)
            .input("correo", sql.NVarChar, email)
            .input("telefono", sql.NVarChar, null) // ✅ NULL en lugar de ""
            .input("contrasena", sql.NVarChar, null) // ✅ NULL en lugar de ""
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