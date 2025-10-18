import bcrypt from 'bcryptjs';
import sql from 'mssql';

export const SessionModel = {
  /**
   * Guarda una nueva sesión JWT
   */
  save: async (pool, id_usuario, jwtToken, ip) => {
    try {
      const jwtHash = await bcrypt.hash(jwtToken, 12);
      await pool.request()
        .input('id_usuario', sql.Int, id_usuario)
        .input('jwt_token', sql.NVarChar(sql.MAX), jwtHash)
        .input('ip_origen', sql.NVarChar(100), ip)
        .query(`
          INSERT INTO SesionesJWT (id_usuario, jwt_token, fecha_inicio, ip_origen)
          VALUES (@id_usuario, @jwt_token, GETDATE(), @ip_origen)
        `);
    } catch (err) {
      console.error('❌ Error al guardar sesión JWT:', err);
    }
  },

  /**
   * Valida si el JWT sigue activo (no expirado ni cerrado)
   */
  validate: async (pool, id_usuario, jwtToken) => {
    const result = await pool.request()
      .input('id_usuario', sql.Int, id_usuario)
      .query(`
        SELECT TOP 1 jwt_token, fecha_cierre
        FROM SesionesJWT
        WHERE id_usuario = @id_usuario
        ORDER BY fecha_inicio DESC
      `);

    if (!result.recordset.length) return false;

    const session = result.recordset[0];
    if (session.fecha_cierre) return false; // sesión cerrada
    return await bcrypt.compare(jwtToken, session.jwt_token);
  },
};
