const { Pool } = require('pg');
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { require: true, rejectUnauthorized: false }, // DEV ONLY
});
async function ping() {
  const res = await pool.query('select now() as now');
  return res.rows[0].now;
}
module.exports = { pool, ping };