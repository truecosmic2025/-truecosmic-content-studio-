const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

// Admin username (set via env or default to 'michael')
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || 'michael').toLowerCase();

// In-memory post log (survives until server restart — good enough for daily use)
const postLog = []; // { id, username, url, post, imageUrl, voiceName, timestamp }
const MAX_LOG = 500;

function getSecret() {
  return ANTHROPIC_API_KEY || 'fallback-secret-change-me';
}

function getUsers() {
  const raw = process.env.TEAM_USERS || '';
  const users = {};
  raw.split(',').forEach(pair => {
    const [username, password] = pair.trim().split(':');
    if (username && password) users[username.toLowerCase()] = password;
  });
  return users;
}

function makeToken(username) {
  const payload = `${username}:${getSecret()}`;
  return crypto.createHmac('sha256', getSecret()).update(payload).digest('hex');
}

function verifyToken(token, username) {
  if (!token || !username) return false;
  const expected = makeToken(username);
  try {
    return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected));
  } catch (e) {
    return false;
  }
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

  const token = makeToken(username.toLowerCase());
  const isAdmin = username.toLowerCase() === ADMIN_USERNAME;
  res.json({ token, username: username.toLowerCase(), isAdmin });
});

// ── LOGOUT ───────────────────────────────────────────────────────────────────
app.post('/api/logout', (req, res) => {
  res.json({ ok: true });
});

// ── AUTH MIDDLEWARE ───────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.headers['x-session-token'];
  const username = req.headers['x-username'];

  if (!token || !username) {
    return res.status(401).json({ error: 'Not authenticated.' });
  }

  if (!verifyToken(token, username)) {
    return res.status(401).json({ error: 'Invalid session. Please log in again.' });
  }

  const users = getUsers();
  if (!users[username.toLowerCase()]) {
    return res.status(401).json({ error: 'Account not found. Please contact your admin.' });
  }

  req.username = username.toLowerCase();
  next();
}

function requireAdmin(req, res, next) {
  if (req.username !== ADMIN_USERNAME) {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  next();
}

// ── FETCH URL ─────────────────────────────────────────────────────────────────
app.post('/api/fetch-url', requireAuth, async (req, res) => {
  const { url } = req.body;
  if (!url || !url.startsWith('http')) {
    return res.status(400).json({ error: 'Invalid URL.' });
  }

  try {
    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Mozilla/5.0 (compatible; TrueCosmic-ContentStudio/1.0)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
      signal: AbortSignal.timeout(12000),
    });

    if (!response.ok) {
      return res.status(502).json({ error: `Could not fetch article (HTTP ${response.status})` });
    }

    const html = await response.text();

    const ogMatch = html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i)
      || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["']/i);
    const imageUrl = ogMatch ? ogMatch[1] : null;

    const titleMatch = html.match(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)["']/i)
      || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:title["']/i);
    const ogTitle = titleMatch ? titleMatch[1] : null;

    const descMatch = html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i)
      || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']description["']/i);
    const metaDesc = descMatch ? descMatch[1] : null;

    let text = html
      .replace(/<script[\s\S]*?<\/script>/gi, '')
      .replace(/<style[\s\S]*?<\/style>/gi, '')
      .replace(/<nav[\s\S]*?<\/nav>/gi, '')
      .replace(/<header[\s\S]*?<\/header>/gi, '')
      .replace(/<footer[\s\S]*?<\/footer>/gi, '')
      .replace(/<aside[\s\S]*?<\/aside>/gi, '')
      .replace(/<!--[\s\S]*?-->/g, '')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&nbsp;/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .replace(/\s{2,}/g, ' ')
      .trim();

    const pageTitleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    const pageTitle = ogTitle || (pageTitleMatch ? pageTitleMatch[1].trim() : null);

    res.json({ text, imageUrl, title: pageTitle, metaDesc });
  } catch (err) {
    console.error('fetch-url error:', err.message);
    if (err.name === 'TimeoutError') {
      return res.status(504).json({ error: 'Article took too long to load. Try again.' });
    }
    res.status(500).json({ error: 'Failed to fetch article: ' + err.message });
  }
});

// ── LOG A POST (called by frontend after successful generation) ───────────────
app.post('/api/log-post', requireAuth, (req, res) => {
  const { url, post, imageUrl, voiceName, tone, firstPerson } = req.body;
  if (!url || !post) return res.status(400).json({ error: 'Missing url or post.' });

  const entry = {
    id: Date.now().toString(36) + Math.random().toString(36).slice(2, 6),
    username: req.username,
    url,
    post,
    imageUrl: imageUrl || null,
    voiceName: voiceName || '',
    tone: tone || '',
    firstPerson: !!firstPerson,
    timestamp: new Date().toISOString(),
  };

  postLog.unshift(entry); // newest first
  if (postLog.length > MAX_LOG) postLog.length = MAX_LOG;

  res.json({ ok: true });
});

// ── ADMIN: GET ALL POSTS ──────────────────────────────────────────────────────
app.get('/api/admin/posts', requireAuth, requireAdmin, (req, res) => {
  res.json({ posts: postLog });
});

// ── ADMIN: DELETE A POST FROM LOG ─────────────────────────────────────────────
app.delete('/api/admin/posts/:id', requireAuth, requireAdmin, (req, res) => {
  const idx = postLog.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Not found.' });
  postLog.splice(idx, 1);
  res.json({ ok: true });
});

// ── ANTHROPIC PROXY ───────────────────────────────────────────────────────────
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
  console.log(`Team members: ${Object.keys(users).join(', ') || 'NONE — set TEAM_USERS env var'}`);
  console.log(`Admin username: ${ADMIN_USERNAME}`);
});
