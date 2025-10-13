import sql from 'mssql';

export const UserModel = {
  create: async (pool, data) => {
    const { nombre, apaterno, amaterno,correo, telefono, contrasenaHash, metodo, proveedor } = data;

    await pool.request()
      .input('nombre', sql.NVarChar(100), nombre)
      .input('a_paterno', sql.NVarChar(100), apaterno)
      .input('a_materno', sql.NVarChar(100), amaterno)
      .input('correo', sql.NVarChar(100), correo)
      .input('telefono', sql.NVarChar(20), telefono)
      .input('contrasena', sql.NVarChar(256), contrasenaHash)
      .input('metodo_autenticacion', sql.NVarChar(50), metodo)
      .input('proveedor_oauth', sql.NVarChar(50), proveedor)
      .query(`
        INSERT INTO Usuarios (nombre,a_paterno,a_materno, correo, telefono, contrasena, metodo_autenticacion, proveedor_oauth)
        VALUES (@nombre,@a_paterno,@a_materno, @correo, @telefono, @contrasena, @metodo_autenticacion, @proveedor_oauth)
      `);
  },

  findByEmail: async (pool, correo) => {
    const result = await pool.request()
      .input('correo', sql.NVarChar(100), correo)
      .query('SELECT * FROM Usuarios WHERE correo = @correo');
    return result.recordset[0];
  },
};
