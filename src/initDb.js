const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS investigators (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'investigator',
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS investigation_targets (
      id SERIAL PRIMARY KEY,

      target_type TEXT NOT NULL DEFAULT 'phone_identity',
      target_label TEXT,

      originating_number TEXT,
      latest_callback_number TEXT,
      all_callback_numbers TEXT,
      recommended_call_number TEXT,

      website_hint TEXT,
      company_hint TEXT,
      email_hint TEXT,
      address_hint TEXT,
      identity_gap TEXT,

      priority_score INTEGER DEFAULT 0,
      violations_count INTEGER DEFAULT 0,
      affected_users_count INTEGER DEFAULT 0,

      first_seen_at TIMESTAMP,
      last_seen_at TIMESTAMP,

      suspected_category TEXT,
      status TEXT NOT NULL DEFAULT 'unresolved',

      assigned_to INTEGER REFERENCES investigators(id),

      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS investigation_target_notes (
      id SERIAL PRIMARY KEY,
      investigation_target_id INTEGER REFERENCES investigation_targets(id) ON DELETE CASCADE,
      investigator_id INTEGER REFERENCES investigators(id),
      note TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS investigation_results (
      id SERIAL PRIMARY KEY,

      investigation_target_id INTEGER REFERENCES investigation_targets(id) ON DELETE CASCADE,

      company_name TEXT,
      website TEXT,
      email TEXT,
      address TEXT,
      agent_name TEXT,
      service_category TEXT,

      confidence_level TEXT,
      outcome TEXT,
      notes TEXT,

      created_by INTEGER REFERENCES investigators(id),
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
}

module.exports = { initDb };