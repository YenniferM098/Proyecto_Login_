import sql from "mssql";
import bcrypt from "bcryptjs";

export const RefreshModel = {
  /**
   * Guarda o reemplaza un refresh token para un usuario.
   */
  save: async (pool, id_usuario, refreshToken, duracionDias = 7) => {
    const hash = await bcrypt.hash(refreshToken, 10);
    const exp = new Date(Date.now() + duracionDias * 24 * 60 * 60 * 1000);

    // Revoca tokens anteriores
    await pool.request()
      .input("id_usuario", sql.Int, id_usuario)
      .query("UPDATE TokensRefresh SET estado = 'Revocado' WHERE id_usuario = @id_usuario");

    // Guarda el nuevo
    await pool.request()
      .input("id_usuario", sql.Int, id_usuario)
      .input("refresh_token", sql.NVarChar(512), hash)
      .input("fecha_expiracion", sql.DateTime, exp)
      .query(`
        INSERT INTO TokensRefresh (id_usuario, refresh_token, fecha_expiracion, estado)
        VALUES (@id_usuario, @refresh_token, @fecha_expiracion, 'Activo')
      `);
  },

  /**
   * Valida un refresh token recibido del cliente.
   */
  validate: async (pool, id_usuario, token) => {
    const result = await pool.request()
      .input("id_usuario", sql.Int, id_usuario)
      .query(`
        SELECT TOP 1 * FROM TokensRefresh
        WHERE id_usuario = @id_usuario AND estado = 'Activo'
        ORDER BY fecha_emision DESC
      `);

    if (!result.recordset.length) return false;

    const record = result.recordset[0];
    const match = await bcrypt.compare(token, record.refresh_token);
    if (!match) return false;

    // Verificar expiración
    const now = new Date();
    if (now > record.fecha_expiracion) return false;

    return true;
  },

  /**
   * Revoca un refresh token (por logout o rotación)
   */
  revoke: async (pool, id_usuario) => {
  await pool.request()
    .input("id_usuario", sql.Int, id_usuario)
    .query(`
      UPDATE TokensRefresh
      SET estado = 'Revocado'
      WHERE id_usuario = @id_usuario AND estado = 'Activo'
    `);
  }
};
