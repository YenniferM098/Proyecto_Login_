import sql from 'mssql';
import config from '../config.js';

const poolPromise = new sql.ConnectionPool(config.db)
  .connect()
  .then((pool) => {
    console.log('✅ Conectado a SQL Server');
    return pool;
  })
  .catch((err) => {
    console.error('❌ Error de conexión a la base de datos:', err);
    process.exit(1);
  });

export { sql, poolPromise };
