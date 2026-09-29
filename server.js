const express = require('express'), helmet = require('helmet'), crypto = require('crypto');
const Database = require('better-sqlite3'), path = require('path');
const E = process.env, PORT = E.PORT || 3000, PROD = E.NODE_ENV === 'production';
const BASE = (E.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const SECRET = E.SESSION_SECRET;
if (!SECRET || !E.ADMIN_PASSWORD) throw new Error('Set SESSION_SECRET and ADMIN_PASSWORD');
const OAUTH = !!(E.IG_APP_ID && E.IG_APP_SECRET), REDIRECT = `${BASE}/auth/callback`;

// ---------- Database ----------
const db = new Database(E.DB_PATH || 'data.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  uuid TEXT UNIQUE NOT NULL,
  username TEXT NOT NULL COLLATE NOCASE,
  ig_user_id TEXT,
  verified INTEGER NOT NULL DEFAULT 0,      -- 1 = confirmed via Instagram OAuth
  source TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_visits_user ON visits(username);
CREATE INDEX IF NOT EXISTS idx_visits_time ON visits(created_at);`);
const insert = db.prepare('INSERT INTO visits (uuid,username,ig_user_id,verified,source) VALUES (?,?,?,?,?)');
const record = (username, igId, verified, source) =>
  insert.run(crypto.randomUUID(), username, igId || null, verified ? 1 : 0, (source || '').slice(0, 200) || null);

// ---------- Helpers ----------
const hmac = v => crypto.createHmac('sha256', SECRET).update(v).digest('base64url');
const sign = v => `${v}.${hmac(v)}`;
const unsign = s => {
  if (!s) return null; const i = s.lastIndexOf('.'); if (i < 0) return null;
  const v = s.slice(0, i), a = Buffer.from(s.slice(i + 1)), b = Buffer.from(hmac(v));
  return a.length === b.length && crypto.timingSafeEqual(a, b) ? v : null;
};
const cookies = req => Object.fromEntries((req.headers.cookie || '').split(';')
  .map(c => c.trim().split(/=(.*)/s).slice(0, 2)).filter(p => p[0]).map(([k, v]) => [k, decodeURIComponent(v || '')]));
const setCookie = (res, n, v, ms, sameSite = 'strict') =>
  res.cookie(n, v, { httpOnly: true, secure: PROD, sameSite, maxAge: ms, path: '/' });
const sha = s => crypto.createHash('sha256').update(s).digest();
const USER_RE = /^[A-Za-z0-9._]{1,30}$/;

// ---------- App ----------
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'", "'unsafe-inline'"], styleSrc: ["'self'", "'unsafe-inline'"],
  imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], formAction: ["'self'"], frameAncestors: ["'none'"] } } }));
app.use(express.json({ limit: '2kb' }));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h', extensions: ['html'] }));
app.get('/healthz', (_, res) => res.send('ok'));
app.get('/api/config', (_, res) => res.json({ oauth: OAUTH }));

// Visitor: voluntary username entry (unverified fallback)
app.post('/api/visit', (req, res) => {
  const { username, consent, source } = req.body || {};
  const u = String(username || '').trim().replace(/^@/, '');
  if (consent !== true) return res.status(400).json({ error: 'Please agree to share your username.' });
  if (!USER_RE.test(u)) return res.status(400).json({ error: 'Enter a valid Instagram username.' });
  try { record(u, null, false, typeof source === 'string' ? source : ''); res.json({ ok: true }); }
  catch (e) { console.error(e); res.status(500).json({ error: 'Something went wrong. Try again.' }); }
});

// Visitor: official Instagram OAuth (Instagram API with Instagram Login)
app.get('/auth/instagram', (req, res) => {
  if (!OAUTH) return res.redirect('/?error=unavailable');
  const state = crypto.randomBytes(16).toString('hex');
  const src = String(req.query.src || '').slice(0, 200);
  setCookie(res, 'ig_state', sign(`${state}|${encodeURIComponent(src)}`), 10 * 60 * 1000, 'lax');
  const q = new URLSearchParams({ client_id: E.IG_APP_ID, redirect_uri: REDIRECT, response_type: 'code',
    scope: 'instagram_business_basic', state });
  res.redirect(`https://www.instagram.com/oauth/authorize?${q}`);
});

app.get('/auth/callback', async (req, res) => {
  const fail = c => res.redirect(`/?error=${c}`);
  try {
    if (req.query.error || !req.query.code) return fail('denied');
    const v = unsign(cookies(req).ig_state); res.clearCookie('ig_state');
    const [state, src] = (v || '').split('|');
    if (!state || state !== req.query.state) return fail('state');
    const tok = await fetch('https://api.instagram.com/oauth/access_token', {
      method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: E.IG_APP_ID, client_secret: E.IG_APP_SECRET,
        grant_type: 'authorization_code', redirect_uri: REDIRECT, code: String(req.query.code).replace(/#_$/, '') })
    }).then(r => r.json());
    if (!tok.access_token) return fail('token');
    const me = await fetch(`https://graph.instagram.com/me?fields=user_id,username&access_token=${encodeURIComponent(tok.access_token)}`)
      .then(r => r.json());   // access token is used once and never stored
    if (!me.username) return fail('profile');
    record(me.username, me.user_id || me.id, true, decodeURIComponent(src || ''));
    res.redirect('/?done=1');
  } catch (e) { console.error(e); fail('server'); }
});

// ---------- Admin ----------
const tries = new Map();
app.post('/admin/login', (req, res) => {
  const ip = req.ip, t = tries.get(ip) || { n: 0, at: Date.now() };
  if (Date.now() - t.at > 15 * 60 * 1000) { t.n = 0; t.at = Date.now(); }
  if (t.n >= 5) return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  const ok = crypto.timingSafeEqual(sha(String((req.body || {}).password || '')), sha(E.ADMIN_PASSWORD));
  if (!ok) { t.n++; tries.set(ip, t); return res.status(401).json({ error: 'Wrong password.' }); }
  tries.delete(ip);
  setCookie(res, 'admin', sign(String(Date.now() + 8 * 3600e3)), 8 * 3600e3);
  res.json({ ok: true });
});

const admin = express.Router();
admin.use((req, res, next) => {
  res.set('Cache-Control', 'no-store');
  const exp = Number(unsign(cookies(req).admin));
  if (!exp || exp < Date.now()) return res.status(401).json({ error: 'Not signed in.' });
  const o = req.get('origin');
  if (req.method !== 'GET' && o && o !== new URL(BASE).origin) return res.status(403).json({ error: 'Bad origin.' });
  next();
});
admin.post('/logout', (_, res) => { res.clearCookie('admin'); res.json({ ok: true }); });
admin.get('/stats', (_, res) => res.json(db.prepare(`SELECT COUNT(*) visits,
  COUNT(DISTINCT username) uniques,
  COALESCE(SUM(created_at >= strftime('%Y-%m-%dT00:00:00Z','now')),0) today FROM visits`).get()));
const search = q => { const like = `%${String(q || '').replace(/[\\%_]/g, '\\$&')}%`;
  return db.prepare(`SELECT id,uuid,username,verified,source,created_at FROM visits
    WHERE username LIKE ? ESCAPE '\\' OR COALESCE(source,'') LIKE ? ESCAPE '\\' ORDER BY id DESC LIMIT 1000`).all(like, like); };
admin.get('/visits', (req, res) => res.json(search(req.query.q)));
admin.get('/export.csv', (req, res) => {
  const cell = v => { let s = String(v ?? ''); if (/^[=+\-@\t\r]/.test(s)) s = "'" + s; return `"${s.replace(/"/g, '""')}"`; };
  const rows = search(req.query.q).map(r => [r.uuid, r.username, r.verified ? 'verified' : 'self-reported', r.source, r.created_at].map(cell).join(','));
  res.type('text/csv').set('Content-Disposition', 'attachment; filename="visitors.csv"')
    .send(['visit_id,username,verification,source,visited_at_utc', ...rows].join('\n'));
});
admin.delete('/visits/:id', (req, res) => { db.prepare('DELETE FROM visits WHERE id=?').run(Number(req.params.id)); res.json({ ok: true }); });
admin.delete('/visits', (_, res) => { db.prepare('DELETE FROM visits').run(); res.json({ ok: true }); });
app.use('/admin/api', admin);
app.get('/admin', (_, res) => res.set('X-Robots-Tag', 'noindex').sendFile(path.join(__dirname, 'public/admin.html')));

app.use((err, _req, res, _next) => { console.error(err); res.status(500).json({ error: 'Server error.' }); });
app.listen(PORT, () => console.log(`Listening on ${PORT}`));
