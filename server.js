const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

// Use ANTHROPIC_API_KEY as signing secret so no extra env var needed
function getSecret() {
  return ANTHROPIC_API_KEY || 'fallback-secret-change-me';
}

// Parse team users from env var
// Format: TEAM_USERS=lauren:pass123,sarah:pass456
function getUsers() {
  const raw = process.env.TEAM_USERS || '';
  const users = {};
  raw.split(',').forEach(pair => {
    const [username, password] = pair.trim().split(':');
    if (username && password) users[username.toLowerCase()] = password;
  });
  return users;
}

// Generate a persistent token — survives server restarts
function makeToken(username) {
  const payload = `${username}:${getSecret()}`;
  return crypto.createHmac('sha256', getSecret()).update(payload).digest('hex');
}

// Verify token without any stored state
function verifyToken(token, username) {
  if (!token || !username) return false;
  const expected = makeToken(username);
  return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expected));
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
  res.json({ token, username: username.toLowerCase() });
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

  req.username = username;
  next();
}

// ── FETCH URL (server-side article scraper) ───────────────────────────────────
// Called by both Post Generator and Medium Article Generator
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

    // Extract og:image
    const ogMatch = html.match(/<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']/i)
      || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["']/i);
    const imageUrl = ogMatch ? ogMatch[1] : null;

    // Extract og:title
    const titleMatch = html.match(/<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)["']/i)
      || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:title["']/i);
    const ogTitle = titleMatch ? titleMatch[1] : null;

    // Extract meta description
    const descMatch = html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']/i)
      || html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']description["']/i);
    const metaDesc = descMatch ? descMatch[1] : null;

    // Strip HTML to plain text
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

    // Extract page title from <title> tag as fallback
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
});
