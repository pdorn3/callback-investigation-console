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
app.use(express.json({ limit: '1mb' }));

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

function requireImportKey(req, res, next) {
  const providedKey = req.headers['x-import-api-key'];

  if (!process.env.IMPORT_API_KEY || providedKey !== process.env.IMPORT_API_KEY) {
    return res.status(401).json({ ok: false, error: 'unauthorized' });
  }

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

app.post('/api/import-targets', requireImportKey, async (req, res) => {
  try {
    const targets = Array.isArray(req.body.targets)
      ? req.body.targets
      : [req.body];

    let imported = 0;

    for (const target of targets) {
      const targetType = target.target_type || 'phone_identity';

      const originatingNumber = target.originating_number || null;
      const latestCallbackNumber = target.latest_callback_number || null;
      const allCallbackNumbers = Array.isArray(target.all_callback_numbers)
        ? target.all_callback_numbers.join(', ')
        : target.all_callback_numbers || null;

      const recommendedCallNumber =
        target.recommended_call_number ||
        latestCallbackNumber ||
        originatingNumber ||
        null;

      const targetLabel =
        target.target_label ||
        target.company_hint ||
        target.website_hint ||
        recommendedCallNumber ||
        'Investigation target';

      await pool.query(
        `
        INSERT INTO investigation_targets (
          target_type,
          target_label,
          originating_number,
          latest_callback_number,
          all_callback_numbers,
          recommended_call_number,
          website_hint,
          company_hint,
          email_hint,
          address_hint,
          identity_gap,
          priority_score,
          violations_count,
          affected_users_count,
          suspected_category,
          status,
          first_seen_at,
          last_seen_at
        )
        VALUES (
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'unresolved',$16,$17
        )
        ON CONFLICT DO NOTHING
        `,
        [
          targetType,
          targetLabel,
          originatingNumber,
          latestCallbackNumber,
          allCallbackNumbers,
          recommendedCallNumber,
          target.website_hint || null,
          target.company_hint || null,
          target.email_hint || null,
          target.address_hint || null,
          target.identity_gap || 'Identity incomplete',
          target.priority_score || 0,
          target.violations_count || 0,
          target.affected_users_count || 0,
          target.suspected_category || null,
          target.first_seen_at || null,
          target.last_seen_at || null
        ]
      );

      imported += 1;
    }

    res.json({
      ok: true,
      imported
    });
  } catch (err) {
    console.error('Import targets error:', err);

    res.status(500).json({
      ok: false,
      error: err.message
    });
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
    FROM investigation_targets t
    LEFT JOIN LATERAL (
      SELECT *
      FROM investigation_results r
      WHERE r.investigation_target_id = t.id
      ORDER BY r.created_at DESC
      LIMIT 1
    ) r ON true
    ORDER BY t.priority_score DESC, t.violations_count DESC, t.last_seen_at DESC NULLS LAST
  `);

  const rows = result.rows.map((target) => {
    const category = target.resolved_service_category || target.suspected_category || '—';
    const displayTarget =
      target.recommended_call_number ||
      target.latest_callback_number ||
      target.originating_number ||
      target.target_label ||
      '—';

    return `
      <tr>
        <td>${target.priority_score || 0}</td>
        <td>${safe(target.target_type)}</td>
        <td><strong>${safe(displayTarget)}</strong></td>
        <td>${safe(target.originating_number || '—')}</td>
        <td>${safe(target.latest_callback_number || '—')}</td>
        <td>${target.violations_count || 0}</td>
        <td>${target.affected_users_count || 0}</td>
        <td>${safe(category)}</td>
        <td>${safe(target.company_name || target.company_hint || '—')}</td>
        <td>${target.website ? `<a href="${safe(target.website)}" target="_blank">${safe(target.website)}</a>` : safe(target.website_hint || '—')}</td>
        <td>${safe(target.status)}</td>
        <td><a href="/investigation/${target.id}">Open</a></td>
      </tr>
    `;
  }).join('');

  res.send(`
    <html>
      <head>
        <title>Identity Investigation Console</title>
      </head>
      <body style="font-family: Arial; padding: 40px; background: #f9fafb;">
        <h1>Identity Investigation Console</h1>

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
              <th>Type</th>
              <th>Recommended Call</th>
              <th>Originating #</th>
              <th>Latest Callback #</th>
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
            ${rows || '<tr><td colspan="12">No investigation targets yet. Click “Seed test targets.”</td></tr>'}
          </tbody>
        </table>
      </body>
    </html>
  `);
});

app.get('/seed-targets', requireAuth, async (req, res) => {
  await pool.query(`
    INSERT INTO investigation_targets (
      target_type,
      target_label,
      originating_number,
      latest_callback_number,
      all_callback_numbers,
      recommended_call_number,
      company_hint,
      website_hint,
      identity_gap,
      priority_score,
      violations_count,
      affected_users_count,
      suspected_category,
      status,
      first_seen_at,
      last_seen_at
    )
    VALUES
      (
        'phone_identity',
        'Originating number with active callback trail',
        '404-555-1000',
        '800-555-0101',
        '877-555-0001, 800-555-0101',
        '800-555-0101',
        NULL,
        NULL,
        'Need company name and website from callback path',
        95,
        87,
        14,
        'Medicare',
        'unresolved',
        NOW() - INTERVAL '10 days',
        NOW()
      ),
      (
        'phone_identity',
        'Originating number; callback appears stale',
        '404-555-2000',
        '888-555-0102',
        '888-555-0102, 888-555-0000',
        '404-555-2000',
        NULL,
        NULL,
        'Latest callback may be stale; call originating number first',
        82,
        64,
        9,
        'Warranty',
        'unresolved',
        NOW() - INTERVAL '7 days',
        NOW()
      ),
      (
        'domain_identity',
        'Domain present but operator unknown',
        NULL,
        NULL,
        NULL,
        NULL,
        NULL,
        'example-loans.com',
        'Need company/legal identity behind domain',
        70,
        41,
        5,
        'Loans',
        'unresolved',
        NOW() - INTERVAL '5 days',
        NOW()
      )
    ON CONFLICT DO NOTHING
  `);

  res.redirect('/dashboard');
});

app.get('/investigation/:id', requireAuth, async (req, res) => {
  const targetResult = await pool.query(
    `SELECT * FROM investigation_targets WHERE id = $1`,
    [req.params.id]
  );

  if (targetResult.rows.length === 0) return res.status(404).send('Target not found');

  const target = targetResult.rows[0];

  const latestResult = await pool.query(
    `
    SELECT *
    FROM investigation_results
    WHERE investigation_target_id = $1
    ORDER BY created_at DESC
    LIMIT 1
    `,
    [req.params.id]
  );

  const latest = latestResult.rows[0] || {};

  const recommendedCall =
    target.recommended_call_number ||
    target.latest_callback_number ||
    target.originating_number ||
    '—';

  res.send(`
    <html>
      <body style="font-family: Arial; padding: 40px;">
        <p><a href="/dashboard">← Back to dashboard</a></p>

        <h1>${safe(target.target_label || recommendedCall)}</h1>

        <p><strong>Target Type:</strong> ${safe(target.target_type)}</p>
        <p><strong>Recommended Call Number:</strong> ${safe(recommendedCall)}</p>
        <p><strong>Originating Number:</strong> ${safe(target.originating_number || '—')}</p>
        <p><strong>Latest Callback Number:</strong> ${safe(target.latest_callback_number || '—')}</p>
        <p><strong>All Callback Numbers:</strong> ${safe(target.all_callback_numbers || '—')}</p>
        <p><strong>Website Hint:</strong> ${safe(target.website_hint || '—')}</p>
        <p><strong>Company Hint:</strong> ${safe(target.company_hint || '—')}</p>
        <p><strong>Identity Gap:</strong> ${safe(target.identity_gap || '—')}</p>
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
            <input type="text" name="company_name" value="${safe(latest.company_name || target.company_hint)}" style="width: 400px; padding: 8px;" />
          </div>

          <div style="margin-bottom: 12px;">
            <label>Website</label><br>
            <input type="text" name="website" value="${safe(latest.website || target.website_hint)}" style="width: 400px; padding: 8px;" />
          </div>

          <div style="margin-bottom: 12px;">
            <label>Email</label><br>
            <input type="text" name="email" value="${safe(latest.email || target.email_hint)}" style="width: 400px; padding: 8px;" />
          </div>

          <div style="margin-bottom: 12px;">
            <label>Address</label><br>
            <input type="text" name="address" value="${safe(latest.address || target.address_hint)}" style="width: 600px; padding: 8px;" />
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
            <label>Confidence</label><br>
            <select name="confidence_level" style="width: 250px; padding: 8px;">
              <option value="">Select</option>
              <option value="high" ${latest.confidence_level === 'high' ? 'selected' : ''}>High</option>
              <option value="medium" ${latest.confidence_level === 'medium' ? 'selected' : ''}>Medium</option>
              <option value="low" ${latest.confidence_level === 'low' ? 'selected' : ''}>Low</option>
            </select>
          </div>

          <div style="margin-bottom: 12px;">
            <label>Outcome</label><br>
            <select name="outcome" style="width: 250px; padding: 8px;">
              <option value="resolved" ${latest.outcome === 'resolved' ? 'selected' : ''}>Resolved</option>
              <option value="partial" ${latest.outcome === 'partial' ? 'selected' : ''}>Partial</option>
              <option value="dead_end" ${latest.outcome === 'dead_end' ? 'selected' : ''}>Dead End</option>
              <option value="ivr_only" ${latest.outcome === 'ivr_only' ? 'selected' : ''}>IVR Only</option>
              <option value="hostile" ${latest.outcome === 'hostile' ? 'selected' : ''}>Hostile</option>
              <option value="needs_followup" ${latest.outcome === 'needs_followup' ? 'selected' : ''}>Needs Follow-Up</option>
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
      address,
      agent_name,
      service_category,
      confidence_level,
      outcome,
      notes
    } = req.body;

    await pool.query(
      `
      INSERT INTO investigation_results (
        investigation_target_id,
        company_name,
        website,
        email,
        address,
        agent_name,
        service_category,
        confidence_level,
        outcome,
        notes,
        created_by
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
      `,
      [
        req.params.id,
        company_name,
        website,
        email,
        address,
        agent_name,
        service_category,
        confidence_level,
        outcome,
        notes,
        req.session.user.id
      ]
    );

    await pool.query(
      `
      UPDATE investigation_targets
      SET status = $2,
          suspected_category = COALESCE(NULLIF($3, ''), suspected_category),
          company_hint = COALESCE(NULLIF($4, ''), company_hint),
          website_hint = COALESCE(NULLIF($5, ''), website_hint),
          email_hint = COALESCE(NULLIF($6, ''), email_hint),
          address_hint = COALESCE(NULLIF($7, ''), address_hint),
          updated_at = NOW()
      WHERE id = $1
      `,
      [
        req.params.id,
        outcome === 'resolved' || outcome === 'partial' ? 'investigated' : outcome,
        service_category,
        company_name,
        website,
        email,
        address
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
      service: 'identity-investigation-console',
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
      console.log(`Identity Investigation Console running on port ${PORT}`);
    });
  })
  .catch((err) => {
    console.error('Failed to initialize database:', err);
    process.exit(1);
  });