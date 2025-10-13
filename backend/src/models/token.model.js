import sql from "mssql";

export const TokenModel = {
  save: async (pool, id_usuario, codigo_otp, tipo, fecha_expiracion = null) => {
    // Si no se pasa fecha_expiracion, se calcula por defecto (+1 min)
    const expiracionFinal = fecha_expiracion || new Date(Date.now() + 60 * 1000);

    await pool.request()
      .input("id_usuario", sql.Int, id_usuario)
      .input("codigo_otp", sql.NVarChar(256), codigo_otp)
      .input("fecha_emision", sql.DateTime, new Date())
      .input("fecha_expiracion", sql.DateTime, expiracionFinal)
      .input("tipo", sql.NVarChar(20), tipo)
      .input("estado", sql.NVarChar(20), "Activo")
      .query(`
        INSERT INTO Tokens2FA (id_usuario, codigo_otp, fecha_emision, fecha_expiracion, tipo, estado)
        VALUES (@id_usuario, @codigo_otp, @fecha_emision, @fecha_expiracion, @tipo, @estado)
      `);
  },

  findLatest: async (pool, id_usuario) => {
    const result = await pool.request()
      .input("id_usuario", sql.Int, id_usuario)
      .query(`
        SELECT TOP 1 * FROM Tokens2FA
        WHERE id_usuario = @id_usuario AND estado = 'Activo'
        ORDER BY fecha_emision DESC
      `);
    return result.recordset[0];
  },
};
