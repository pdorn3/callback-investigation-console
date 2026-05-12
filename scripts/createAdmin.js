require('dotenv').config();

const bcrypt = require('bcryptjs');
const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

async function createAdmin() {
  const email = 'paul@callback.local';
  const password = 'ChangeThisPassword123!';

  const passwordHash = await bcrypt.hash(password, 10);

  await pool.query(
    `
    INSERT INTO investigators (
      email,
      password_hash,
      role
    )
    VALUES ($1, $2, $3)
    ON CONFLICT (email)
    DO NOTHING
    `,
    [
      email,
      passwordHash,
      'admin'
    ]
  );

  console.log('Admin investigator created.');

  process.exit(0);
}

createAdmin().catch((err) => {
  console.error(err);
  process.exit(1);
});