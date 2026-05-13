require('dotenv').config();

const path = require('path');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { initDb } = require('./initDb');

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-this-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false }
  })
);

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  next();
}

function safe(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

app.get('/', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.redirect('/dashboard');
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'login.html'));
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const result = await pool.query(
      `SELECT * FROM investigators WHERE email = $1 LIMIT 1`,
      [email]
    );

    if (result.rows.length === 0) return res.status(401).send('Invalid credentials');

    const user = result.rows[0];
    const validPassword = await bcrypt.compare(password, user.password_hash);

    if (!validPassword) return res.status(401).send('Invalid credentials');

    req.session.user = {
      id: user.id,
      email: user.email,
      role: user.role
    };

    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    res.status(500).send('Login error');
  }
});

app.get('/dashboard', requireAuth, async (req, res) => {
  const result = await pool.query(`
    SELECT
      t.*,
      r.company_name,
      r.website,
      r.service_category AS resolved_service_category,
      r.outcome AS latest_outcome
    FROM callback_targets t
    LEFT JOIN LATERAL (
      SELECT *
      FROM callback_identity_results r
      WHERE r.callback_target_id = t.id
      ORDER BY r.created_at DESC
      LIMIT 1
    ) r ON true
    ORDER BY t.priority_score DESC, t.violations_count DESC, t.last_seen_at DESC NULLS LAST
  `);

  const rows = result.rows.map((target) => {
    const category = target.resolved_service_category || target.suspected_category || '—';

    return `
      <tr>
        <td>${target.priority_score || 0}</td>
        <td><strong>${safe(target.callback_number)}</strong></td>
        <td>${target.violations_count || 0}</td>
        <td>${target.affected_users_count || 0}</td>
        <td>${safe(category)}</td>
        <td>${safe(target.company_name || '—')}</td>
        <td>${target.website ? `<a href="${safe(target.website)}" target="_blank">${safe(target.website)}</a>` : '—'}</td>
        <td>${safe(target.status)}</td>
        <td><a href="/investigation/${target.id}">Open</a></td>
      </tr>
    `;
  }).join('');

  res.send(`
    <html>
      <head>
        <title>Callback Investigation Console</title>
      </head>
      <body style="font-family: Arial; padding: 40px; background: #f9fafb;">
        <h1>Callback Investigation Console</h1>

        <p>
          Logged in as <strong>${safe(req.session.user.email)}</strong>
          · <a href="/logout">Logout</a>
        </p>

        <p>
          <a href="/seed-targets">Seed test targets</a>
        </p>

        <table border="1" cellpadding="10" cellspacing="0" style="background: white; border-collapse: collapse; width: 100%;">
          <thead>
            <tr>
              <th>Priority</th>
              <th>Callback Number</th>
              <th>Violations</th>
              <th>Users</th>
              <th>Category</th>
              <th>Company</th>
              <th>Website</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            ${rows || '<tr><td colspan="9">No callback targets yet. Click “Seed test targets.”</td></tr>'}
          </tbody>
        </table>
      </body>
    </html>
  `);
});

app.get('/seed-targets', requireAuth, async (req, res) => {
  await pool.query(`
    INSERT INTO callback_targets (
      callback_number,
      priority_score,
      violations_count,
      affected_users_count,
      suspected_category,
      status,
      first_seen_at,
      last_seen_at
    )
    VALUES
      ('800-555-0101', 95, 87, 14, 'Medicare', 'unresolved', NOW() - INTERVAL '10 days', NOW()),
      ('888-555-0102', 82, 64, 9, 'Warranty', 'unresolved', NOW() - INTERVAL '7 days', NOW()),
      ('877-555-0103', 70, 41, 5, 'Debt Relief', 'unresolved', NOW() - INTERVAL '5 days', NOW())
    ON CONFLICT (callback_number)
    DO NOTHING
  `);

  res.redirect('/dashboard');
});

app.get('/investigation/:id', requireAuth, async (req, res) => {
  const targetResult = await pool.query(
    `SELECT * FROM callback_targets WHERE id = $1`,
    [req.params.id]
  );

  if (targetResult.rows.length === 0) return res.status(404).send('Target not found');

  const target = targetResult.rows[0];

  const latestResult = await pool.query(
    `
    SELECT *
    FROM callback_identity_results
    WHERE callback_target_id = $1
    ORDER BY created_at DESC
    LIMIT 1
    `,
    [req.params.id]
  );

  const latest = latestResult.rows[0] || {};

  res.send(`
    <html>
      <body style="font-family: Arial; padding: 40px;">
        <p><a href="/dashboard">← Back to dashboard</a></p>

        <h1>${safe(target.callback_number)}</h1>

        <p><strong>Priority:</strong> ${target.priority_score || 0}</p>
        <p><strong>Violations:</strong> ${target.violations_count || 0}</p>
        <p><strong>Affected Users:</strong> ${target.affected_users_count || 0}</p>
        <p><strong>Category:</strong> ${safe(latest.service_category || target.suspected_category || '—')}</p>
        <p><strong>Status:</strong> ${safe(target.status)}</p>

        <hr>

        <h2>Manual Investigation</h2>

        <form method="POST" action="/investigation/${target.id}/save">
          <div style="margin-bottom: 12px;">
            <label>Company Name</label><br>
            <input type="text" name="company_name" value="${safe(latest.company_name)}" style="width: 400px; padding: 8px;" />
          </div>

          <div style="margin-bottom: 12px;">
            <label>Website</label><br>
            <input type="text" name="website" value="${safe(latest.website)}" style="width: 400px; padding: 8px;" />
          </div>

          <div style="margin-bottom: 12px;">
            <label>Email</label><br>
            <input type="text" name="email" value="${safe(latest.email)}" style="width: 400px; padding: 8px;" />
          </div>

          <div style="margin-bottom: 12px;">
            <label>Agent Name</label><br>
            <input type="text" name="agent_name" value="${safe(latest.agent_name)}" style="width: 400px; padding: 8px;" />
          </div>

          <div style="margin-bottom: 12px;">
            <label>Service Category</label><br>
            <input type="text" name="service_category" value="${safe(latest.service_category || target.suspected_category)}" style="width: 400px; padding: 8px;" />
          </div>

          <div style="margin-bottom: 12px;">
            <label>Outcome</label><br>
            <select name="outcome" style="width: 250px; padding: 8px;">
              <option value="resolved" ${latest.outcome === 'resolved' ? 'selected' : ''}>Resolved</option>
              <option value="partial" ${latest.outcome === 'partial' ? 'selected' : ''}>Partial</option>
              <option value="dead_end" ${latest.outcome === 'dead_end' ? 'selected' : ''}>Dead End</option>
              <option value="ivr_only" ${latest.outcome === 'ivr_only' ? 'selected' : ''}>IVR Only</option>
              <option value="hostile" ${latest.outcome === 'hostile' ? 'selected' : ''}>Hostile</option>
            </select>
          </div>

          <div style="margin-bottom: 12px;">
            <label>Notes</label><br>
            <textarea name="notes" rows="6" style="width: 600px; padding: 8px;">${safe(latest.notes)}</textarea>
          </div>

          <button type="submit" style="padding: 10px 18px;">
            Save Investigation Result
          </button>
        </form>
      </body>
    </html>
  `);
});

app.post('/investigation/:id/save', requireAuth, async (req, res) => {
  try {
    const {
      company_name,
      website,
      email,
      agent_name,
      service_category,
      outcome,
      notes
    } = req.body;

    await pool.query(
      `
      INSERT INTO callback_identity_results (
        callback_target_id,
        company_name,
        website,
        email,
        agent_name,
        service_category,
        outcome,
        notes,
        created_by
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
      `,
      [
        req.params.id,
        company_name,
        website,
        email,
        agent_name,
        service_category,
        outcome,
        notes,
        req.session.user.id
      ]
    );

    await pool.query(
      `
      UPDATE callback_targets
      SET status = $2,
          suspected_category = COALESCE(NULLIF($3, ''), suspected_category),
          updated_at = NOW()
      WHERE id = $1
      `,
      [
        req.params.id,
        outcome === 'resolved' || outcome === 'partial' ? 'investigated' : outcome,
        service_category
      ]
    );

    res.redirect('/dashboard');
  } catch (err) {
    console.error(err);
    res.status(500).send('Failed to save investigation');
  }
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
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