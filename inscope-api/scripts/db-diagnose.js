require('dotenv').config();
const { Client } = require('pg');

function mask(str=''){ try{const u=new URL(str); if(u.password) u.password='***'; return u.toString(); }catch{ return '[INVALID DATABASE_URL]'; } }

(async () => {
  console.log('--- DB DIAG (DEV no-verify) ---');
  console.log('DATABASE_URL =', mask(process.env.DATABASE_URL));
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { require: true, rejectUnauthorized: false }, // DEV ONLY
  });
  try {
    await client.connect();
    const r = await client.query('select now() as now');
    console.log('OK (DEV no-verify). now =', r.rows[0].now);
    await client.end();
    process.exit(0);
  } catch (e) {
    console.error('FAIL (DEV no-verify):', e.code, e.message);
    process.exit(1);
  }
})();