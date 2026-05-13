require('dotenv').config();

const path = require('path');
const express = require('express');
const { Pool } = require('pg');
const { initDb } = require('./initDb');

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.get('/health', async (req, res) => {
  try {
    const result = await pool.query('SELECT NOW()');

    res.json({
      ok: true,
      service: 'callback-investigation-console',
      db_connected: true,
      time: result.rows[0].now
    });
  } catch (err) {
    console.error('Health check DB error:', err);

    res.status(500).json({
      ok: false,
      db_connected: false,
      error: err.message
    });
  }
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`Callback Investigation Console running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });
