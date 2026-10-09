const express = require('express');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
const ADMIN_USERNAME = (process.env.ADMIN_USERNAME || 'michael').toLowerCase();

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

function isAdmin(username) {
  return !!username && username.toLowerCase() === ADMIN_USERNAME;
}

// ── IN-MEMORY POST LOG (capped at 500 entries) ───────────────────────────────
// Populated on every successful generation (Facebook posts + Medium articles).
// Not persisted across restarts/deploys — this is a lightweight visibility
// log for the admin dashboard, not a system of record.
const POST_LOG_CAP = 500;
let postLog = [];
let postLogSeq = 1;

function logPost(entry) {
  const record = {
    id: postLogSeq++,
    timestamp: new Date().toISOString(),
    ...entry,
  };
  postLog.push(record);
  if (postLog.length > POST_LOG_CAP) {
    postLog = postLog.slice(postLog.length - POST_LOG_CAP);
  }
  return record;
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
  res.json({ token, username: username.toLowerCase(), isAdmin: isAdmin(username) });
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

// ── ADMIN MIDDLEWARE (chain after requireAuth) ───────────────────────────────
function requireAdmin(req, res, next) {
  if (!isAdmin(req.username)) {
    return res.status(403).json({ error: 'Admin access required.' });
  }
  next();
}

// ── ARTICLE SCRAPER (shared by /api/fetch-url and automation) ────────────────
async function scrapeArticle(url) {
  const response = await fetch(url, {
    headers: {
      'User-Agent': 'Mozilla/5.0 (compatible; TrueCosmic-ContentStudio/1.0)',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    },
    signal: AbortSignal.timeout(12000),
  });

  if (!response.ok) {
    const err = new Error(`Could not fetch article (HTTP ${response.status})`);
    err.status = 502;
    throw err;
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

  return { text, imageUrl, title: pageTitle, metaDesc };
}

// ── FETCH URL (server-side article scraper) ───────────────────────────────────
// Called by both Post Generator and Medium Article Generator
app.post('/api/fetch-url', requireAuth, async (req, res) => {
  const { url } = req.body;
  if (!url || !url.startsWith('http')) {
    return res.status(400).json({ error: 'Invalid URL.' });
  }

  try {
    res.json(await scrapeArticle(url));
  } catch (err) {
    console.error('fetch-url error:', err.message);
    if (err.status === 502) {
      return res.status(502).json({ error: err.message });
    }
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

// ── POST LOG (protected — any authenticated team member can write their own activity) ─
// Called by the frontend after a successful generation (FB post or Medium article)
// so the Super Admin Dashboard has visibility into team activity.
app.post('/api/log-post', requireAuth, (req, res) => {
  const {
    type,          // 'facebook' | 'medium'
    url,
    title,
    voiceName,     // team member display name used for the generation
    perspective,   // 'first' | 'neutral'
    language,      // 'en' | 'es'
    preview,       // short text preview for the dashboard list
  } = req.body || {};

  if (!type || (type !== 'facebook' && type !== 'medium')) {
    return res.status(400).json({ error: 'Invalid log entry type.' });
  }

  const record = logPost({
    type,
    url: url || null,
    title: title || null,
    voiceName: voiceName || null,
    perspective: perspective === 'first' ? 'first' : 'neutral',
    language: language === 'es' ? 'es' : 'en',
    preview: (preview || '').slice(0, 240),
    author: req.username,
  });

  res.json({ ok: true, id: record.id });
});

// ── SUPER ADMIN DASHBOARD (admin only) ───────────────────────────────────────
app.get('/api/admin/posts', requireAuth, requireAdmin, (req, res) => {
  const { teamMember, perspective, language, type } = req.query;

  let results = postLog;
  if (teamMember) {
    results = results.filter(p => (p.voiceName || '').toLowerCase() === String(teamMember).toLowerCase());
  }
  if (perspective) {
    results = results.filter(p => p.perspective === perspective);
  }
  if (language) {
    results = results.filter(p => p.language === language);
  }
  if (type) {
    results = results.filter(p => p.type === type);
  }

  // Most recent first
  const sorted = [...results].sort((a, b) => b.id - a.id);

  res.json({
    posts: sorted,
    total: postLog.length,
    filtered: sorted.length,
  });
});

app.delete('/api/admin/posts/:id', requireAuth, requireAdmin, (req, res) => {
  const id = parseInt(req.params.id, 10);
  const before = postLog.length;
  postLog = postLog.filter(p => p.id !== id);
  if (postLog.length === before) {
    return res.status(404).json({ error: 'Entry not found.' });
  }
  res.json({ ok: true });
});

// ── AUTOMATION: MEDIUM ARTICLE GENERATION (headless) ─────────────────────────
// Server-side port of generateMediumArticle() from index.html. Prompt, maps,
// model, token limit and parse fallback are copied verbatim — keep them in
// sync if the frontend version changes.
//
// Auth: AUTOMATION_KEY env var, sent as `x-automation-key: <key>` or
// `Authorization: Bearer <key>`. This is a dedicated secret for scheduled /
// headless callers — it is NOT a team member password and grants access to
// this endpoint only. If AUTOMATION_KEY is unset the endpoint is disabled.
const AUTOMATION_KEY = process.env.AUTOMATION_KEY;

const MEDIUM_LENGTH_MAP = {
  short: 'Write 400 to 600 words.',
  medium: 'Write 700 to 900 words.',
  long: 'Write 1000 to 1200 words.'
};

const MEDIUM_STYLE_MAP = {
  educational: 'Write as an educational, authoritative explainer. Clear headings, facts, practical insights.',
  personal: 'Write with a personal, first-person narrative style. Relatable, warm, story-driven.',
  howto: 'Write as a practical how-to guide. Step-by-step, actionable, easy to follow.',
  listicle: 'Write in a list format with clear numbered points or subheadings. Scannable and punchy.'
};

function requireAutomationKey(req, res, next) {
  if (!AUTOMATION_KEY) {
    return res.status(503).json({ error: 'Automation is disabled (AUTOMATION_KEY not set).' });
  }
  const auth = req.headers['authorization'] || '';
  const provided = req.headers['x-automation-key']
    || (auth.toLowerCase().startsWith('bearer ') ? auth.slice(7).trim() : '');
  if (!provided) {
    return res.status(401).json({ error: 'Missing automation key.' });
  }
  // Compare fixed-length digests so length differences don't leak or throw
  const a = crypto.createHash('sha256').update(String(provided)).digest();
  const b = crypto.createHash('sha256').update(AUTOMATION_KEY).digest();
  if (!crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'Invalid automation key.' });
  }
  next();
}

async function generateMediumArticleServer(url, { style = 'educational', length = 'medium', language = 'en' } = {}) {
  const { text: articleText, title: articleTitle, imageUrl } = await scrapeArticle(url);

  const lengthNote = MEDIUM_LENGTH_MAP[length];
  const styleNote = MEDIUM_STYLE_MAP[style];

  const langInstruction = language === 'es'
    ? 'Write the entire article in Spanish. Natural, native-level Spanish — not a translation. Do not include any English.'
    : 'Write in English.';

  const systemPrompt = `You are a writer for TrueCosmic, a Neville Goddard and Law of Assumption platform with 95,000+ community members. You write high-quality articles for Medium that establish TrueCosmic as an authority on manifestation, consciousness, and Neville Goddard's teachings.

Your articles must:
- Be written in clear, engaging prose that works well on Medium
- Establish genuine authority on the topic
- Be SEO and GEO-friendly — written so AI models like ChatGPT and Perplexity would cite them as an answer to related questions
- End with a natural call to action directing readers to TrueCosmic.com
- Sound like a knowledgeable human writer, never like AI

Style: ${styleNote}
Language: ${langInstruction}

IMPORTANT: Respond with a JSON object with exactly these fields:
{
  "title": "The article title",
  "article": "The full article text with proper paragraph breaks using \\n\\n",
  "tags": ["tag1", "tag2", "tag3", "tag4", "tag5"]
}

The article field should be the complete article including the title at the top, all body paragraphs, and this exact CTA at the end:

---

*This article was originally published on [TrueCosmic.com](https://truecosmic.com) — a platform dedicated to Neville Goddard's teachings and the Law of Assumption. Explore our full library of lectures, guided meditations, and manifestation tools.*

The tags should be 5 relevant Medium tags from: Law of Assumption, Neville Goddard, Manifestation, Spirituality, Personal Development, Self Improvement, Consciousness, Mental Health, Psychology, Mindfulness, Life Lessons, Motivation, Relationships, Love, Self Love`;

  const userPrompt = `${lengthNote}

Rewrite the following TrueCosmic article for Medium. Keep the core content and insights but rewrite it as a standalone Medium piece. The original article URL is: ${url}

ORIGINAL ARTICLE CONTENT:
${articleText.slice(0, 5000)}`;

  const res = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': ANTHROPIC_API_KEY,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-5',
      max_tokens: 2000,
      system: systemPrompt,
      messages: [{ role: 'user', content: userPrompt }]
    })
  });

  const data = await res.json();
  if (!data.content || !Array.isArray(data.content)) {
    throw new Error(data.error?.message || data.error || 'API error');
  }

  const raw = data.content.filter(b => b.type === 'text').map(b => b.text).join('').trim();

  const parsed = parseMediumResponse(raw, articleTitle);
  return { ...parsed, imageUrl, sourceTitle: articleTitle };
}

// More forgiving than the frontend's parser: the model sometimes wraps the
// JSON in ``` fences, adds text around it, or leaves quotes unescaped inside
// "article". Headless runs have no human to untangle that, so recover what
// we can instead of dumping the raw JSON into the article body.
const MEDIUM_DEFAULT_TAGS = ['Law of Assumption', 'Neville Goddard', 'Manifestation', 'Spirituality', 'Personal Development'];

function parseMediumResponse(raw, fallbackTitle) {
  const tryParse = (s) => { try { return JSON.parse(s); } catch (e) { return null; } };
  const unfence = (s) => String(s).replace(/```(?:json)?\s*/gi, '').replace(/```/g, '').trim();

  let text = unfence(raw);
  let obj = tryParse(text);
  if (!obj) {
    const a = text.indexOf('{'), b = text.lastIndexOf('}');
    if (a !== -1 && b > a) obj = tryParse(text.slice(a, b + 1));
  }

  // Last resort: pull the fields out by position (handles unescaped quotes in the article)
  if (!obj) {
    const t = text.match(/"title"\s*:\s*"((?:[^"\\]|\\.)*)"/);
    const tags = text.match(/"tags"\s*:\s*\[([^\]]*)\]/);
    const art = text.match(/"article"\s*:\s*"([\s\S]*)"\s*,\s*"tags"/);
    if (art) {
      obj = {
        title: t ? tryParse('"' + t[1] + '"') || t[1] : null,
        article: art[1].replace(/\\n/g, '\n').replace(/\\"/g, '"').replace(/\\\\/g, '\\'),
        tags: tags ? (tryParse('[' + tags[1] + ']') || []) : [],
      };
    }
  }

  if (!obj || typeof obj !== 'object') {
    return { title: String(fallbackTitle || 'Article').replace(/\s*[|–—-]\s*TrueCosmic\s*$/i, '').trim(), article: text, tags: MEDIUM_DEFAULT_TAGS, parseWarning: 'unparsed_model_output' };
  }

  // Nested case: "article" itself contains a fenced JSON object
  if (typeof obj.article === 'string' && /^\s*(```|\{\s*"title")/.test(obj.article)) {
    const inner = parseMediumResponse(obj.article, obj.title || fallbackTitle);
    if (!inner.parseWarning) obj = { ...obj, ...inner };
  }

  const cleanTitle = (s) => (s ? String(s).replace(/\s*[|–—-]\s*TrueCosmic\s*$/i, '').trim() : s);
  return {
    title: cleanTitle(obj.title) || cleanTitle(fallbackTitle) || 'Article',
    article: typeof obj.article === 'string' ? obj.article.trim() : text,
    tags: Array.isArray(obj.tags) && obj.tags.length ? obj.tags.slice(0, 5) : MEDIUM_DEFAULT_TAGS,
  };
}

app.post('/api/automation/medium-generate', requireAutomationKey, async (req, res) => {
  if (!ANTHROPIC_API_KEY) {
    return res.status(500).json({ error: 'ANTHROPIC_API_KEY not set in environment variables.' });
  }
  const { url, style = 'educational', length = 'medium', language = 'en' } = req.body || {};
  if (!url || !String(url).startsWith('http')) {
    return res.status(400).json({ error: 'Invalid URL.' });
  }
  if (!MEDIUM_STYLE_MAP[style]) {
    return res.status(400).json({ error: `Invalid style. Use one of: ${Object.keys(MEDIUM_STYLE_MAP).join(', ')}` });
  }
  if (!MEDIUM_LENGTH_MAP[length]) {
    return res.status(400).json({ error: `Invalid length. Use one of: ${Object.keys(MEDIUM_LENGTH_MAP).join(', ')}` });
  }
  const lang = language === 'es' ? 'es' : 'en';

  try {
    const result = await generateMediumArticleServer(url, { style, length, language: lang });

    const record = logPost({
      type: 'medium',
      url,
      title: result.title || result.sourceTitle || null,
      voiceName: null,
      perspective: 'neutral',
      language: lang,
      preview: (result.article || '').slice(0, 240),
      author: 'automation',
    });

    res.json({
      ok: true,
      logId: record.id,
      canonicalUrl: url,
      title: result.title || null,
      article: result.article || '',
      tags: result.tags || [],
      imageUrl: result.imageUrl || null,
      wordCount: (result.article || '').split(/\s+/).filter(Boolean).length,
      parseWarning: result.parseWarning || null,
    });
  } catch (err) {
    console.error('automation/medium-generate error:', err.message);
    if (err.status === 502) return res.status(502).json({ error: err.message });
    if (err.name === 'TimeoutError') return res.status(504).json({ error: 'Article took too long to load. Try again.' });
    res.status(500).json({ error: 'Generation failed: ' + err.message });
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
