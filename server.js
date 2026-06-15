/**
 * NOVA Backend — OAuth Token Server
 * Handles Google OAuth (Calendar + Gmail) with encrypted token storage
 * Deploy to Railway.app
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { google } = require('googleapis');
const CryptoJS = require('crypto-js');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// ── DATABASE SETUP ─────────────────────────────────────────────────────────────
const DB_PATH = process.env.DATABASE_PATH || path.join(__dirname, 'nova.db');
const db = new Database(DB_PATH);

db.exec(`
  CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now')),
    expires_at INTEGER
  );
  CREATE TABLE IF NOT EXISTS tokens (
    user_id     TEXT NOT NULL,
    provider    TEXT NOT NULL,
    token_data  TEXT NOT NULL,
    updated_at  INTEGER DEFAULT (strftime('%s','now')),
    PRIMARY KEY (user_id, provider)
  );
  CREATE TABLE IF NOT EXISTS oauth_state (
    state      TEXT PRIMARY KEY,
    user_id    TEXT NOT NULL,
    provider   TEXT NOT NULL,
    created_at INTEGER DEFAULT (strftime('%s','now'))
  );
`);

// ── ENCRYPTION ─────────────────────────────────────────────────────────────────
const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || 'nova-default-key-change-in-prod';

function encrypt(data) {
  return CryptoJS.AES.encrypt(JSON.stringify(data), ENCRYPTION_KEY).toString();
}

function decrypt(ciphertext) {
  const bytes = CryptoJS.AES.decrypt(ciphertext, ENCRYPTION_KEY);
  return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
}

// ── GOOGLE OAUTH CLIENT ────────────────────────────────────────────────────────
function getGoogleClient() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.GOOGLE_REDIRECT_URI || `${process.env.BACKEND_URL}/auth/google/callback`
  );
}

const GOOGLE_SCOPES = [
  'https://www.googleapis.com/auth/calendar.readonly',
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
];

// ── MIDDLEWARE ─────────────────────────────────────────────────────────────────
app.use(helmet({
  crossOriginResourcePolicy: false,
  frameguard: false,              // remove X-Frame-Options so iframe embedding works
  contentSecurityPolicy: false,  // handled by the PWA itself
}));
app.use(express.json());
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, curl, etc)
    if (!origin) return callback(null, true);
    const allowed = process.env.ALLOWED_ORIGINS
      ? process.env.ALLOWED_ORIGINS.split(',')
      : ['http://localhost:3000'];
    // Always allow perplexity.ai and sites.pplx.app
    const alwaysAllow = ['perplexity.ai', 'pplx.app', 'railway.app', 'localhost'];
    if (alwaysAllow.some(d => origin.includes(d))) return callback(null, true);
    if (allowed.includes(origin)) return callback(null, true);
    callback(null, true); // permissive for now — lock down in production
  },
  credentials: true,
}));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
app.use('/api', limiter);

// ── AUTH MIDDLEWARE ────────────────────────────────────────────────────────────
function requireSession(req, res, next) {
  const sessionId = req.headers['x-nova-session'];
  if (!sessionId) return res.status(401).json({ error: 'No session' });

  const session = db.prepare(
    'SELECT * FROM sessions WHERE session_id = ? AND (expires_at IS NULL OR expires_at > strftime(\'%s\',\'now\'))'
  ).get(sessionId);

  if (!session) return res.status(401).json({ error: 'Invalid or expired session' });

  req.userId = session.user_id;
  req.sessionId = sessionId;
  next();
}

// ── ROUTES ─────────────────────────────────────────────────────────────────────

// Health check
app.get('/', (req, res) => {
  res.json({ status: 'ok', name: 'NOVA Backend', version: '1.0.0' });
});

// ── SESSION MANAGEMENT ─────────────────────────────────────────────────────────

// Create or retrieve a session for a user
app.post('/api/session', (req, res) => {
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });

  // Check if session already exists
  const existing = db.prepare(
    'SELECT session_id FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1'
  ).get(userId);

  if (existing) {
    return res.json({ sessionId: existing.session_id });
  }

  const sessionId = uuidv4();
  db.prepare('INSERT INTO sessions (session_id, user_id) VALUES (?, ?)').run(sessionId, userId);
  res.json({ sessionId });
});

// ── GOOGLE OAUTH ───────────────────────────────────────────────────────────────

// Step 1: Generate Google OAuth URL
app.get('/auth/google/connect', requireSession, (req, res) => {
  if (!process.env.GOOGLE_CLIENT_ID) {
    return res.status(503).json({ error: 'Google OAuth not configured' });
  }

  const oauth2Client = getGoogleClient();
  const state = uuidv4();

  db.prepare('INSERT INTO oauth_state (state, user_id, provider) VALUES (?, ?, ?)').run(
    state, req.userId, 'google'
  );

  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: GOOGLE_SCOPES,
    state,
    prompt: 'consent',
  });

  res.json({ url });
});

// Step 2: Google OAuth callback
app.get('/auth/google/callback', async (req, res) => {
  const { code, state, error } = req.query;

  if (error) {
    return res.redirect(`${process.env.NOVA_APP_URL || '/'}?auth_error=${error}`);
  }

  const stateRow = db.prepare('SELECT * FROM oauth_state WHERE state = ?').get(state);
  if (!stateRow) {
    return res.redirect(`${process.env.NOVA_APP_URL || '/'}?auth_error=invalid_state`);
  }

  db.prepare('DELETE FROM oauth_state WHERE state = ?').run(state);

  try {
    const oauth2Client = getGoogleClient();
    const { tokens } = await oauth2Client.getToken(code);

    // Store encrypted tokens
    const encrypted = encrypt(tokens);
    db.prepare(`
      INSERT INTO tokens (user_id, provider, token_data) VALUES (?, ?, ?)
      ON CONFLICT(user_id, provider) DO UPDATE SET token_data = excluded.token_data, updated_at = strftime('%s','now')
    `).run(stateRow.user_id, 'google', encrypted);

    // Redirect back to NOVA app with success
    const appUrl = process.env.NOVA_APP_URL || '/';
    res.redirect(`${appUrl}?auth_success=google`);
  } catch (err) {
    console.error('Google OAuth error:', err);
    res.redirect(`${process.env.NOVA_APP_URL || '/'}?auth_error=token_exchange_failed`);
  }
});

// Check which integrations are connected
app.get('/api/integrations/status', requireSession, (req, res) => {
  const rows = db.prepare('SELECT provider FROM tokens WHERE user_id = ?').all(req.userId);
  const connected = rows.map(r => r.provider);
  res.json({ connected });
});

// Disconnect an integration
app.delete('/api/integrations/:provider', requireSession, (req, res) => {
  db.prepare('DELETE FROM tokens WHERE user_id = ? AND provider = ?').run(
    req.userId, req.params.provider
  );
  res.json({ success: true });
});

// ── GOOGLE CALENDAR ────────────────────────────────────────────────────────────

app.get('/api/google/calendar/today', requireSession, async (req, res) => {
  const tokenRow = db.prepare('SELECT token_data FROM tokens WHERE user_id = ? AND provider = ?')
    .get(req.userId, 'google');

  if (!tokenRow) return res.status(404).json({ error: 'Google not connected' });

  try {
    const tokens = decrypt(tokenRow.token_data);
    const oauth2Client = getGoogleClient();
    oauth2Client.setCredentials(tokens);

    // Auto-refresh token if needed
    oauth2Client.on('tokens', (newTokens) => {
      const merged = { ...tokens, ...newTokens };
      db.prepare(`UPDATE tokens SET token_data = ?, updated_at = strftime('%s','now') WHERE user_id = ? AND provider = ?`)
        .run(encrypt(merged), req.userId, 'google');
    });

    const calendar = google.calendar({ version: 'v3', auth: oauth2Client });

    const now = new Date();
    const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const endOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);

    const response = await calendar.events.list({
      calendarId: 'primary',
      timeMin: startOfDay.toISOString(),
      timeMax: endOfDay.toISOString(),
      singleEvents: true,
      orderBy: 'startTime',
      maxResults: 20,
    });

    const events = (response.data.items || []).map(e => ({
      id: e.id,
      title: e.summary || 'Untitled',
      start: e.start?.dateTime || e.start?.date,
      end: e.end?.dateTime || e.end?.date,
      location: e.location,
      description: e.description,
      attendees: (e.attendees || []).map(a => a.email),
      isAllDay: !e.start?.dateTime,
      meetLink: e.hangoutLink || null,
    }));

    res.json({ events, date: now.toISOString() });
  } catch (err) {
    console.error('Calendar error:', err);
    res.status(500).json({ error: 'Failed to fetch calendar', details: err.message });
  }
});

app.get('/api/google/calendar/upcoming', requireSession, async (req, res) => {
  const tokenRow = db.prepare('SELECT token_data FROM tokens WHERE user_id = ? AND provider = ?')
    .get(req.userId, 'google');

  if (!tokenRow) return res.status(404).json({ error: 'Google not connected' });

  try {
    const tokens = decrypt(tokenRow.token_data);
    const oauth2Client = getGoogleClient();
    oauth2Client.setCredentials(tokens);

    const calendar = google.calendar({ version: 'v3', auth: oauth2Client });
    const days = parseInt(req.query.days) || 7;

    const now = new Date();
    const future = new Date(now.getTime() + days * 24 * 60 * 60 * 1000);

    const response = await calendar.events.list({
      calendarId: 'primary',
      timeMin: now.toISOString(),
      timeMax: future.toISOString(),
      singleEvents: true,
      orderBy: 'startTime',
      maxResults: 30,
    });

    const events = (response.data.items || []).map(e => ({
      id: e.id,
      title: e.summary || 'Untitled',
      start: e.start?.dateTime || e.start?.date,
      end: e.end?.dateTime || e.end?.date,
      location: e.location,
      isAllDay: !e.start?.dateTime,
      meetLink: e.hangoutLink || null,
    }));

    res.json({ events });
  } catch (err) {
    console.error('Calendar upcoming error:', err);
    res.status(500).json({ error: 'Failed to fetch upcoming events', details: err.message });
  }
});

// ── GMAIL ──────────────────────────────────────────────────────────────────────

app.get('/api/google/gmail/inbox', requireSession, async (req, res) => {
  const tokenRow = db.prepare('SELECT token_data FROM tokens WHERE user_id = ? AND provider = ?')
    .get(req.userId, 'google');

  if (!tokenRow) return res.status(404).json({ error: 'Google not connected' });

  try {
    const tokens = decrypt(tokenRow.token_data);
    const oauth2Client = getGoogleClient();
    oauth2Client.setCredentials(tokens);

    oauth2Client.on('tokens', (newTokens) => {
      const merged = { ...tokens, ...newTokens };
      db.prepare(`UPDATE tokens SET token_data = ?, updated_at = strftime('%s','now') WHERE user_id = ? AND provider = ?`)
        .run(encrypt(merged), req.userId, 'google');
    });

    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
    const maxResults = parseInt(req.query.limit) || 10;
    const query = req.query.q || 'is:unread';

    const listResponse = await gmail.users.messages.list({
      userId: 'me',
      maxResults,
      q: query,
    });

    const messages = listResponse.data.messages || [];

    // Fetch details for each message in parallel
    const details = await Promise.all(
      messages.map(msg =>
        gmail.users.messages.get({
          userId: 'me',
          id: msg.id,
          format: 'metadata',
          metadataHeaders: ['From', 'Subject', 'Date'],
        })
      )
    );

    const emails = details.map(d => {
      const headers = d.data.payload?.headers || [];
      const get = name => headers.find(h => h.name === name)?.value || '';
      return {
        id: d.data.id,
        from: get('From'),
        subject: get('Subject'),
        date: get('Date'),
        snippet: d.data.snippet,
        isUnread: d.data.labelIds?.includes('UNREAD'),
      };
    });

    res.json({ emails });
  } catch (err) {
    console.error('Gmail error:', err);
    res.status(500).json({ error: 'Failed to fetch emails', details: err.message });
  }
});

// Get full email content
app.get('/api/google/gmail/message/:id', requireSession, async (req, res) => {
  const tokenRow = db.prepare('SELECT token_data FROM tokens WHERE user_id = ? AND provider = ?')
    .get(req.userId, 'google');

  if (!tokenRow) return res.status(404).json({ error: 'Google not connected' });

  try {
    const tokens = decrypt(tokenRow.token_data);
    const oauth2Client = getGoogleClient();
    oauth2Client.setCredentials(tokens);

    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    const msg = await gmail.users.messages.get({
      userId: 'me',
      id: req.params.id,
      format: 'full',
    });

    const headers = msg.data.payload?.headers || [];
    const get = name => headers.find(h => h.name === name)?.value || '';

    // Extract plain text body
    let body = '';
    function extractBody(part) {
      if (part.mimeType === 'text/plain' && part.body?.data) {
        body += Buffer.from(part.body.data, 'base64').toString('utf-8');
      }
      if (part.parts) part.parts.forEach(extractBody);
    }
    extractBody(msg.data.payload);

    res.json({
      id: msg.data.id,
      from: get('From'),
      to: get('To'),
      subject: get('Subject'),
      date: get('Date'),
      body: body.slice(0, 3000), // Limit for AI context
      snippet: msg.data.snippet,
    });
  } catch (err) {
    console.error('Gmail message error:', err);
    res.status(500).json({ error: 'Failed to fetch email', details: err.message });
  }
});

// ── START ──────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`NOVA Backend running on port ${PORT}`);
  console.log(`Google OAuth: ${process.env.GOOGLE_CLIENT_ID ? 'configured' : 'NOT configured'}`);
});

module.exports = app;
