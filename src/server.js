require('dotenv').config();

const path = require('path');
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { initDb } = require('./initDb');

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production' || Boolean(process.env.RENDER);

if (isProduction && !process.env.SESSION_SECRET) {
  throw new Error('SESSION_SECRET is required in production');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

if (isProduction) app.set('trust proxy', 1);

app.use(express.urlencoded({ extended: true }));
app.use(express.json({ limit: '1mb' }));

app.use(
  session({
    store: new PgSession({
      pool,
      createTableIfMissing: true
    }),
    secret: process.env.SESSION_SECRET || 'callback-local-development-only',
    resave: false,
    saveUninitialized: false,
    cookie: {
      secure: isProduction,
      httpOnly: true,
      sameSite: 'lax',
      maxAge: 12 * 60 * 60 * 1000
    }
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

function statusBadge(status) {
  const normalized = String(status || 'unresolved');
  const tone =
    normalized === 'investigated' || normalized === 'resolved'
      ? 'green'
      : normalized === 'dead_end' || normalized === 'hostile'
        ? 'red'
        : normalized === 'needs_followup' || normalized === 'partial'
          ? 'amber'
          : 'blue';

  return `<span class="badge badge-${tone}">${safe(normalized.replace(/_/g, ' '))}</span>`;
}

function appSidebar(user, active = 'dashboard') {
  return `
    <aside class="sidebar glass">
      <div class="brand">
        <div class="brand-mark">CS</div>
        <div class="brand-copy">
          <div class="brand-name">CallSlayer</div>
          <div class="brand-subtitle">Investigation Console</div>
        </div>
      </div>
      <nav class="nav">
        <div class="nav-label">Operations</div>
        <a class="nav-item ${active === 'dashboard' ? 'active' : ''}" href="/dashboard">
          <span class="nav-icon">⌂</span><span>Investigation Queue</span>
        </a>
        <div class="nav-label">Workspace</div>
        <a class="nav-item ${active === 'investigation' ? 'active' : ''}" href="/dashboard">
          <span class="nav-icon">◎</span><span>Target Research</span>
        </a>
      </nav>
      <div class="sidebar-footer">
        <div class="user-block">
          <div class="avatar">${safe(user.email.slice(0, 1).toUpperCase())}</div>
          <div class="user-meta">
            <div class="user-email">${safe(user.email)}</div>
            <div class="user-role">${safe(user.role)}</div>
          </div>
          <a class="logout" href="/logout">Log out</a>
        </div>
      </div>
    </aside>
  `;
}

function appDocument({ title, user, active, header, actions = '', content }) {
  return `<!doctype html>
    <html lang="en">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>${safe(title)} · CallSlayer</title>
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="/app.css">
      </head>
      <body>
        <div class="app-shell">
          ${appSidebar(user, active)}
          <main class="main">
            <header class="topbar glass">
              <div>${header}</div>
              <div class="actions">${actions}</div>
            </header>
            <div class="content">${content}</div>
          </main>
        </div>
      </body>
    </html>`;
}

app.get('/app.css', (req, res) => {
  res.sendFile(path.join(__dirname, 'views', 'app.css'));
});

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

    let created = 0;
    let updated = 0;

    for (const target of targets) {
      const sourceType = target.source_type || null;
      const sourceId = target.source_id || target.originating_number || null;
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

      const importResult = await pool.query(
        `
        INSERT INTO investigation_targets (
          source_type,
          source_id,
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
          $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,'unresolved',$18,$19
        )
        ON CONFLICT (source_type, source_id)
          WHERE source_type IS NOT NULL AND source_id IS NOT NULL
        DO UPDATE SET
          target_type = EXCLUDED.target_type,
          target_label = EXCLUDED.target_label,
          originating_number = EXCLUDED.originating_number,
          latest_callback_number = EXCLUDED.latest_callback_number,
          all_callback_numbers = EXCLUDED.all_callback_numbers,
          recommended_call_number = EXCLUDED.recommended_call_number,
          website_hint = EXCLUDED.website_hint,
          company_hint = EXCLUDED.company_hint,
          email_hint = EXCLUDED.email_hint,
          address_hint = EXCLUDED.address_hint,
          identity_gap = EXCLUDED.identity_gap,
          priority_score = EXCLUDED.priority_score,
          violations_count = EXCLUDED.violations_count,
          affected_users_count = EXCLUDED.affected_users_count,
          suspected_category = EXCLUDED.suspected_category,
          first_seen_at = EXCLUDED.first_seen_at,
          last_seen_at = EXCLUDED.last_seen_at,
          updated_at = NOW()
        RETURNING (xmax = 0) AS inserted
        `,
        [
          sourceType,
          sourceId,
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

      if (importResult.rows[0]?.inserted) created += 1;
      else updated += 1;
    }

    res.json({
      ok: true,
      processed: targets.length,
      created,
      updated
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
    WITH target_groups AS (
      SELECT
        COALESCE(
          recommended_call_number,
          latest_callback_number,
          originating_number,
          'target:' || id::text
        ) AS investigation_number,
        ARRAY_AGG(id ORDER BY priority_score DESC, last_seen_at DESC NULLS LAST) AS target_ids,
        COUNT(*)::integer AS target_count,
        SUM(violations_count)::integer AS grouped_violations_count,
        SUM(affected_users_count)::integer AS grouped_affected_users_count,
        MAX(priority_score)::integer AS source_priority_score,
        MIN(first_seen_at) AS grouped_first_seen_at,
        MAX(last_seen_at) AS grouped_last_seen_at,
        STRING_AGG(DISTINCT originating_number, ', ') FILTER (WHERE originating_number IS NOT NULL) AS grouped_originating_numbers,
        STRING_AGG(DISTINCT latest_callback_number, ', ') FILTER (WHERE latest_callback_number IS NOT NULL) AS grouped_callback_numbers,
        (ARRAY_AGG(id ORDER BY priority_score DESC, last_seen_at DESC NULLS LAST))[1] AS representative_id
      FROM investigation_targets
      GROUP BY 1
    )
    SELECT
      t.*,
      g.investigation_number,
      g.target_ids,
      g.target_count,
      g.grouped_violations_count,
      g.grouped_affected_users_count,
      g.source_priority_score,
      g.grouped_first_seen_at,
      g.grouped_last_seen_at,
      g.grouped_originating_numbers,
      g.grouped_callback_numbers,
      r.company_name,
      r.website,
      r.lead_generator,
      r.service_category AS resolved_service_category,
      r.outcome AS latest_outcome
    FROM target_groups g
    JOIN investigation_targets t ON t.id = g.representative_id
    LEFT JOIN LATERAL (
      SELECT *
      FROM investigation_results r
      WHERE r.investigation_target_id = ANY(g.target_ids)
      ORDER BY r.created_at DESC
      LIMIT 1
    ) r ON true
  `);

  const rows = result.rows.map((target) => {
    const category = target.resolved_service_category || target.suspected_category || '—';
    const displayTarget = target.investigation_number.startsWith('target:')
      ? target.target_label || 'Non-phone target'
      : target.investigation_number;
    const daysSinceLastSeen = target.grouped_last_seen_at
      ? (Date.now() - new Date(target.grouped_last_seen_at).getTime()) / 86400000
      : Infinity;
    const violationPoints = Math.min(target.grouped_violations_count, 40);
    const userPoints = Math.min(target.grouped_affected_users_count * 4, 20);
    const repeatPoints = Math.min((target.target_count - 1) * 3, 15);
    const recencyPoints = daysSinceLastSeen <= 7 ? 20 : daysSinceLastSeen <= 30 ? 10 : 0;
    const callablePoints = target.investigation_number.startsWith('target:') ? 0 : 5;
    const roiScore = violationPoints + userPoints + repeatPoints + recencyPoints + callablePoints;

    return {
      roiScore,
      violations: target.grouped_violations_count,
      html: `
      <tr>
        <td>
          <span class="score">${roiScore}</span>
          <div class="secondary-cell" title="Violations ${violationPoints} + users ${userPoints} + repeats ${repeatPoints} + recency ${recencyPoints} + callable ${callablePoints}">
            ROI score
          </div>
        </td>
        <td>
          <div class="primary-cell mono">${safe(displayTarget)}</div>
          <div class="secondary-cell">${target.target_count} linked source${target.target_count === 1 ? '' : 's'}</div>
        </td>
        <td><span class="badge badge-blue">${safe(target.target_type.replace(/_/g, ' '))}</span></td>
        <td class="mono secondary-cell">${safe(target.grouped_originating_numbers || '—')}</td>
        <td><strong>${target.grouped_violations_count || 0}</strong></td>
        <td>${target.grouped_affected_users_count || 0}</td>
        <td>${safe(category)}</td>
        <td>
          <div class="primary-cell">${safe(target.company_name || target.company_hint || 'Unknown')}</div>
          <div class="secondary-cell">${safe(target.website || target.website_hint || 'No website identified')}</div>
        </td>
        <td>${safe(target.lead_generator || '—')}</td>
        <td>${statusBadge(target.status)}</td>
        <td><a class="open-link" href="/investigation/${target.id}">Investigate →</a></td>
      </tr>
    `
    };
  })
    .sort((a, b) => b.roiScore - a.roiScore || b.violations - a.violations)
    .map((entry) => entry.html)
    .join('');

  const totalTargets = result.rows.length;
  const unresolved = result.rows.filter((target) => target.status === 'unresolved').length;
  const investigated = result.rows.filter((target) => target.status === 'investigated').length;
  const totalViolations = result.rows.reduce((sum, target) => sum + (target.grouped_violations_count || 0), 0);

  res.send(appDocument({
    title: 'Investigation Queue',
    user: req.session.user,
    active: 'dashboard',
    header: `
      <div class="eyebrow">Identity Operations</div>
      <h1>Investigation Queue</h1>
      <div class="subtext">Prioritized callback and identity targets requiring manual research</div>
    `,
    actions: `
      <a class="btn btn-primary" href="/dashboard">Refresh queue</a>
    `,
    content: `
      <section class="metrics">
        <div class="metric">
          <div class="metric-label">Investigation Numbers</div>
          <div class="metric-value">${totalTargets}</div>
          <div class="metric-note">Consolidated from ${result.rows.reduce((sum, target) => sum + target.target_count, 0)} source targets</div>
        </div>
        <div class="metric">
          <div class="metric-label">Unresolved</div>
          <div class="metric-value">${unresolved}</div>
          <div class="metric-note">Ready for investigator review</div>
        </div>
        <div class="metric">
          <div class="metric-label">Investigated</div>
          <div class="metric-value">${investigated}</div>
          <div class="metric-note">With a saved outcome</div>
        </div>
        <div class="metric">
          <div class="metric-label">Linked Violations</div>
          <div class="metric-value">${totalViolations}</div>
          <div class="metric-note">Evidence records represented</div>
        </div>
      </section>
      <section class="panel glass">
        <div class="panel-head">
          <div class="panel-title">
            <h2>Ranked Investigation Numbers</h2>
            <p>Grouped by callable number and ranked by expected investigation ROI.</p>
          </div>
          <span class="badge badge-green">Live queue</span>
        </div>
        <div class="table-wrap">
          <table>
            <thead>
              <tr>
                <th>ROI Rank</th>
                <th>Investigation Number</th>
                <th>Type</th>
                <th>Linked Originating Numbers</th>
                <th>Violations</th>
                <th>Users</th>
                <th>Category</th>
                <th>Identity</th>
                <th>Lead Generator</th>
                <th>Status</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              ${rows || '<tr><td colspan="11"><div class="empty">No investigation targets yet.</div></td></tr>'}
            </tbody>
          </table>
        </div>
      </section>
    `
  }));
});

app.get('/investigation/:id', requireAuth, async (req, res) => {
  const targetResult = await pool.query(
    `SELECT * FROM investigation_targets WHERE id = $1`,
    [req.params.id]
  );

  if (targetResult.rows.length === 0) return res.status(404).send('Target not found');

  const target = targetResult.rows[0];

  const groupResult = await pool.query(
    `
    WITH selected AS (
      SELECT COALESCE(
        recommended_call_number,
        latest_callback_number,
        originating_number,
        'target:' || id::text
      ) AS investigation_number
      FROM investigation_targets
      WHERE id = $1
    )
    SELECT
      ARRAY_AGG(t.id) AS target_ids,
      COUNT(*)::integer AS target_count,
      SUM(t.violations_count)::integer AS violations_count,
      SUM(t.affected_users_count)::integer AS affected_users_count,
      MIN(t.first_seen_at) AS first_seen_at,
      MAX(t.last_seen_at) AS last_seen_at,
      STRING_AGG(DISTINCT t.originating_number, ', ') FILTER (WHERE t.originating_number IS NOT NULL) AS originating_numbers,
      STRING_AGG(DISTINCT t.latest_callback_number, ', ') FILTER (WHERE t.latest_callback_number IS NOT NULL) AS callback_numbers
    FROM investigation_targets t
    CROSS JOIN selected s
    WHERE COALESCE(
      t.recommended_call_number,
      t.latest_callback_number,
      t.originating_number,
      'target:' || t.id::text
    ) = s.investigation_number
    `,
    [req.params.id]
  );
  const group = groupResult.rows[0];

  const latestResult = await pool.query(
    `
    SELECT *
    FROM investigation_results
    WHERE investigation_target_id = ANY($1::integer[])
    ORDER BY created_at DESC
    LIMIT 1
    `,
    [group.target_ids]
  );

  const latest = latestResult.rows[0] || {};

  const recommendedCall =
    target.recommended_call_number ||
    target.latest_callback_number ||
    target.originating_number ||
    '—';

  res.send(appDocument({
    title: target.target_label || recommendedCall,
    user: req.session.user,
    active: 'investigation',
    header: `
      <div class="eyebrow">Target #${target.id} · ${safe(target.target_type.replace(/_/g, ' '))}</div>
      <h1>${safe(target.target_label || recommendedCall)}</h1>
      <div class="subtext">Review source signals and record the verified identity.</div>
    `,
    actions: `
      <a class="btn btn-secondary" href="/dashboard">← Back to queue</a>
      ${statusBadge(target.status)}
    `,
    content: `
      <section class="detail-grid">
        <div class="panel glass">
          <div class="panel-head">
            <div class="panel-title">
              <h2>Target Intelligence</h2>
              <p>Known identifiers and prioritization signals</p>
            </div>
            <span class="score">${target.priority_score || 0}</span>
          </div>
          <div class="info-list">
            <div class="info-row"><div class="info-label">Recommended Call</div><div class="info-value mono">${safe(recommendedCall)}</div></div>
            <div class="info-row"><div class="info-label">Linked Sources</div><div class="info-value">${group.target_count} source target${group.target_count === 1 ? '' : 's'} grouped under this number</div></div>
            <div class="info-row"><div class="info-label">Originating Numbers</div><div class="info-value mono">${safe(group.originating_numbers || '—')}</div></div>
            <div class="info-row"><div class="info-label">Callback Numbers</div><div class="info-value mono">${safe(group.callback_numbers || '—')}</div></div>
            <div class="info-row"><div class="info-label">Website Hint</div><div class="info-value">${safe(target.website_hint || '—')}</div></div>
            <div class="info-row"><div class="info-label">Company Hint</div><div class="info-value">${safe(target.company_hint || '—')}</div></div>
            <div class="info-row"><div class="info-label">Identity Gap</div><div class="info-value">${safe(target.identity_gap || '—')}</div></div>
            <div class="info-row"><div class="info-label">Violations / Users</div><div class="info-value">${group.violations_count || 0} violations · ${group.affected_users_count || 0} affected-user signals</div></div>
            <div class="info-row"><div class="info-label">Category</div><div class="info-value">${safe(latest.service_category || target.suspected_category || '—')}</div></div>
          </div>
        </div>
        <form class="panel glass form-panel" method="POST" action="/investigation/${target.id}/save">
          <div class="panel-head">
            <div class="panel-title">
              <h2>Investigation Result</h2>
              <p>Capture the verified operator identity and investigation outcome.</p>
            </div>
            <span class="badge badge-blue">Manual review</span>
          </div>
          <div class="form-grid">
            <div class="field">
              <label for="company_name">Company Name</label>
              <input id="company_name" type="text" name="company_name" value="${safe(latest.company_name || target.company_hint)}">
            </div>
            <div class="field">
              <label for="website">Website</label>
              <input id="website" type="url" name="website" value="${safe(latest.website || target.website_hint)}">
            </div>
            <div class="field">
              <label for="email">Email</label>
              <input id="email" type="email" name="email" value="${safe(latest.email || target.email_hint)}">
            </div>
            <div class="field">
              <label for="agent_name">Agent Name</label>
              <input id="agent_name" type="text" name="agent_name" value="${safe(latest.agent_name)}">
            </div>
            <div class="field">
              <label for="lead_generator">Lead Generator</label>
              <input id="lead_generator" type="text" name="lead_generator" value="${safe(latest.lead_generator)}" placeholder="Company or source that generated the lead">
            </div>
            <div class="field full">
              <label for="address">Address</label>
              <input id="address" type="text" name="address" value="${safe(latest.address || target.address_hint)}">
            </div>
            <div class="field">
              <label for="service_category">Service Category</label>
              <input id="service_category" type="text" name="service_category" value="${safe(latest.service_category || target.suspected_category)}">
            </div>
            <div class="field">
              <label for="confidence_level">Confidence</label>
              <select id="confidence_level" name="confidence_level">
                <option value="">Select confidence</option>
                <option value="high" ${latest.confidence_level === 'high' ? 'selected' : ''}>High</option>
                <option value="medium" ${latest.confidence_level === 'medium' ? 'selected' : ''}>Medium</option>
                <option value="low" ${latest.confidence_level === 'low' ? 'selected' : ''}>Low</option>
              </select>
            </div>
            <div class="field">
              <label for="outcome">Outcome</label>
              <select id="outcome" name="outcome">
                <option value="resolved" ${latest.outcome === 'resolved' ? 'selected' : ''}>Resolved</option>
                <option value="partial" ${latest.outcome === 'partial' ? 'selected' : ''}>Partial</option>
                <option value="dead_end" ${latest.outcome === 'dead_end' ? 'selected' : ''}>Dead End</option>
                <option value="ivr_only" ${latest.outcome === 'ivr_only' ? 'selected' : ''}>IVR Only</option>
                <option value="hostile" ${latest.outcome === 'hostile' ? 'selected' : ''}>Hostile</option>
                <option value="needs_followup" ${latest.outcome === 'needs_followup' ? 'selected' : ''}>Needs Follow-Up</option>
              </select>
            </div>
            <div class="field full">
              <label for="notes">Investigator Notes</label>
              <textarea id="notes" name="notes" placeholder="Document who answered, what was disclosed, and any recommended follow-up.">${safe(latest.notes)}</textarea>
            </div>
          </div>
          <div class="form-actions">
            <a class="btn btn-secondary" href="/dashboard">Cancel</a>
            <button class="btn btn-primary" type="submit">Save investigation result</button>
          </div>
        </form>
      </section>
    `
  }));
});

app.post('/investigation/:id/save', requireAuth, async (req, res) => {
  try {
    const {
      company_name,
      website,
      email,
      address,
      agent_name,
      lead_generator,
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
        lead_generator,
        service_category,
        confidence_level,
        outcome,
        notes,
        created_by
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
      `,
      [
        req.params.id,
        company_name,
        website,
        email,
        address,
        agent_name,
        lead_generator,
        service_category,
        confidence_level,
        outcome,
        notes,
        req.session.user.id
      ]
    );

    await pool.query(
      `
      WITH selected AS (
        SELECT COALESCE(
          recommended_call_number,
          latest_callback_number,
          originating_number,
          'target:' || id::text
        ) AS investigation_number
        FROM investigation_targets
        WHERE id = $1
      )
      UPDATE investigation_targets
      SET status = $2,
          suspected_category = COALESCE(NULLIF($3, ''), suspected_category),
          company_hint = COALESCE(NULLIF($4, ''), company_hint),
          website_hint = COALESCE(NULLIF($5, ''), website_hint),
          email_hint = COALESCE(NULLIF($6, ''), email_hint),
          address_hint = COALESCE(NULLIF($7, ''), address_hint),
          updated_at = NOW()
      FROM selected
      WHERE COALESCE(
        investigation_targets.recommended_call_number,
        investigation_targets.latest_callback_number,
        investigation_targets.originating_number,
        'target:' || investigation_targets.id::text
      ) = selected.investigation_number
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
