const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

// Sessions stored in memory — cleared on restart (users just log in again)
const sessions = new Map();

// Parse team users from env var
// Format in Railway: TEAM_USERS=lauren:pass123,sarah:pass456,mike:pass789
function getUsers() {
  const raw = process.env.TEAM_USERS || '';
  const users = {};
  raw.split(',').forEach(pair => {
    const [username, password] = pair.trim().split(':');
    if (username && password) users[username.toLowerCase()] = password;
  });
  return users;
}

app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));

// ── LOGIN ────────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Missing credentials.' });

  const users = getUsers();
  const storedPassword = users[username.toLowerCase()];

  if (!storedPassword || storedPassword !== password) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { username: username.toLowerCase(), createdAt: Date.now() });
  res.json({ token, username: username.toLowerCase() });
});

// ── LOGOUT ───────────────────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  const token = req.headers['x-session-token'];
  if (token) sessions.delete(token);
  res.json({ ok: true });
});

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.headers['x-session-token'];
  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }
  // Expire sessions after 12 hours
  const session = sessions.get(token);
  if (Date.now() - session.createdAt > 12 * 60 * 60 * 1000) {
    sessions.delete(token);
    return res.status(401).json({ error: 'Session expired. Please log in again.' });
  }
  req.session = session;
  next();
}

// ── ANTHROPIC PROXY (protected) ───────────────────────────────────────────────
app.post('/api/messages', requireAuth, async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'ANTHROPIC_API_KEY not set in environment variables.' });
  }
  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'anthropic-beta': 'web-search-2025-03-05',
      },
      body: JSON.stringify(req.body),
    });
    const data = await response.json();
    res.status(response.status).json(data);
  } catch (err) {
    console.error('Anthropic proxy error:', err);
    res.status(500).json({ error: 'Failed to reach Anthropic API.' });
  }
});

// ── FALLBACK ──────────────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  const users = getUsers();
  console.log(`Truecosmic Content Studio running on port ${PORT}`);
  console.log(`Team members configured: ${Object.keys(users).join(', ') || 'NONE — set TEAM_USERS env var'}`);
});
