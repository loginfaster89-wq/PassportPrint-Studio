// ════════════════════════════════════════════════════════════
// PassportPrint Studio — Backend API
// Node.js + Express + SQLite + Razorpay + JWT + bcrypt + nodemailer
// ════════════════════════════════════════════════════════════
// Endpoints:
//   POST /api/request-otp      { email, name?, purpose? }       → { ok, expiresIn, resendAfter }
//   POST /api/signup           { name, email, password, otp }   → { token, user }
//   POST /api/login            { email, password }              → { token, user }
//   GET  /api/me               (Bearer token)                    → { user }
//   POST /api/create-order     (Bearer) { plan: 'weekly'|'monthly' }
//                                                               → { orderId, amount, currency, keyId }
//   POST /api/verify-payment   (Bearer) { orderId, paymentId, signature, plan }
//                                                               → { ok: true, user }
//   GET  /api/plans            → { plans: [...] }
//   GET  /api/download-status  (Bearer)                          → { plan, limit, used, remaining, unlimited, dayKey }
//   POST /api/track-download   (Bearer)                          → { ok, plan, limit, used, remaining, unlimited, dayKey }
//                                                               (429 when daily free limit is already reached)
//   GET  /health               → { ok: true }
// ════════════════════════════════════════════════════════════

require('dotenv').config();
const express       = require('express');
const cors          = require('cors');
const crypto        = require('crypto');
const bcrypt        = require('bcryptjs');
const jwt           = require('jsonwebtoken');
const Database      = require('better-sqlite3');
const Razorpay      = require('razorpay');
const rateLimit     = require('express-rate-limit');
const nodemailer    = require('nodemailer');
const dns           = require('dns').promises;

// ── Config ──
const PORT                = parseInt(process.env.PORT || '4000', 10);
const JWT_SECRET          = process.env.JWT_SECRET || 'dev-only-secret-change-me';
const RAZORPAY_KEY_ID     = process.env.RAZORPAY_KEY_ID || '';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';
const DB_PATH             = process.env.DB_PATH || './pps.db';
const CORS_ORIGINS        = (process.env.CORS_ORIGINS || '*').split(',').map(s => s.trim());

// ── SMTP / OTP config ──
const SMTP_HOST      = process.env.SMTP_HOST || '';
const SMTP_PORT      = parseInt(process.env.SMTP_PORT || '465', 10);
const SMTP_USER      = process.env.SMTP_USER || '';
const SMTP_PASS      = process.env.SMTP_PASS || '';
const SMTP_FROM      = process.env.SMTP_FROM || (SMTP_USER ? `PassportPrint Studio <${SMTP_USER}>` : '');
const OTP_TTL_MS     = parseInt(process.env.OTP_TTL_MS     || String(10 * 60 * 1000), 10); // 10 min
const OTP_RESEND_MS  = parseInt(process.env.OTP_RESEND_MS  || String(60 * 1000),       10); // 60 s
const OTP_MAX_TRIES  = parseInt(process.env.OTP_MAX_TRIES  || '5',                     10);
const OTP_VERIFY_WINDOW_MS = parseInt(process.env.OTP_VERIFY_WINDOW_MS || String(15 * 60 * 1000), 10);
const SKIP_MX_CHECK  = (process.env.SKIP_MX_CHECK || '').toLowerCase() === 'true';

const PLANS = {
  weekly:  { id: 'weekly',  name: 'Weekly',  amount: parseInt(process.env.PRICE_WEEKLY  || '4900',  10), days: 7  },
  monthly: { id: 'monthly', name: 'Monthly', amount: parseInt(process.env.PRICE_MONTHLY || '14900', 10), days: 30 },
};

// Per-plan daily download/print sheet limits. 0 = unlimited.
const DAILY_LIMITS = {
  free:    parseInt(process.env.FREE_DAILY_SHEETS    || '2', 10),
  weekly:  parseInt(process.env.WEEKLY_DAILY_SHEETS  || '0', 10),
  monthly: parseInt(process.env.MONTHLY_DAILY_SHEETS || '0', 10),
};

// Timezone used to decide when the "daily" counter resets.
// Defaults to IST (UTC+5:30) since the app targets Indian users.
const DAILY_RESET_TZ_OFFSET_MIN = parseInt(process.env.DAILY_RESET_TZ_OFFSET_MIN || '330', 10);

if (JWT_SECRET === 'dev-only-secret-change-me') {
  console.warn('⚠️  JWT_SECRET is not set — using default. DO NOT use in production.');
}
if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
  console.warn('⚠️  Razorpay keys missing — payment endpoints will fail until configured.');
}
if (!SMTP_HOST || !SMTP_USER || !SMTP_PASS) {
  console.warn('⚠️  SMTP not fully configured — OTP emails will fail. Set SMTP_HOST/PORT/USER/PASS/FROM.');
}

// ── DB ──
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT UNIQUE NOT NULL,
    name            TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    plan            TEXT NOT NULL DEFAULT 'free',
    plan_expires_at INTEGER NOT NULL DEFAULT 0,
    created_at      INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS payments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL,
    razorpay_order_id    TEXT NOT NULL,
    razorpay_payment_id  TEXT,
    razorpay_signature   TEXT,
    plan            TEXT NOT NULL,
    amount          INTEGER NOT NULL,
    status          TEXT NOT NULL DEFAULT 'created',
    created_at      INTEGER NOT NULL,
    verified_at     INTEGER,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS idx_payments_user ON payments(user_id);
  CREATE INDEX IF NOT EXISTS idx_payments_order ON payments(razorpay_order_id);

  CREATE TABLE IF NOT EXISTS downloads_daily (
    user_id    INTEGER NOT NULL,
    day_key    TEXT    NOT NULL,
    count      INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(user_id, day_key),
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
  CREATE INDEX IF NOT EXISTS idx_downloads_user_day ON downloads_daily(user_id, day_key);

  CREATE TABLE IF NOT EXISTS email_otps (
    email         TEXT PRIMARY KEY,
    otp_hash      TEXT NOT NULL,
    purpose       TEXT NOT NULL DEFAULT 'signup',
    created_at    INTEGER NOT NULL,
    expires_at    INTEGER NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 0,
    verified_at   INTEGER
  );
  CREATE INDEX IF NOT EXISTS idx_email_otps_expires ON email_otps(expires_at);
`);

// ── Razorpay SDK (may throw if keys missing, guard at use site) ──
let razorpay = null;
if (RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET) {
  razorpay = new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET });
}

// ── SMTP transport (null until configured) ──
let mailer = null;
if (SMTP_HOST && SMTP_USER && SMTP_PASS) {
  mailer = nodemailer.createTransport({
    host:   SMTP_HOST,
    port:   SMTP_PORT,
    secure: SMTP_PORT === 465,
    auth:   { user: SMTP_USER, pass: SMTP_PASS },
  });
  mailer.verify().then(
    () => console.log('✓ SMTP transport ready'),
    (e) => console.warn('⚠️  SMTP verify failed:', e && e.message || e)
  );
}

// ── Disposable / temporary email domains (block at signup) ──
const DISPOSABLE_DOMAINS = new Set([
  '10minutemail.com','10minutemail.net','20minutemail.com','33mail.com','dispostable.com',
  'fakeinbox.com','fakemailgenerator.com','getairmail.com','getnada.com','grr.la',
  'guerrillamail.com','guerrillamail.net','guerrillamail.org','guerrillamail.biz',
  'guerrillamail.de','guerrillamailblock.com','sharklasers.com','pokemail.net','spam4.me',
  'mailinator.com','mailinator.net','mailinator.org','mailnesia.com','maildrop.cc',
  'mintemail.com','moakt.com','tempmail.com','temp-mail.org','temp-mail.io','tempmailaddress.com',
  'tempr.email','throwawaymail.com','trashmail.com','trashmail.de','yopmail.com','yopmail.fr',
  'yopmail.net','spambox.us','inboxbear.com','inboxkitten.com','mohmal.com','emailondeck.com',
  'tempmailo.com','tmpmail.org','tmpmail.net','burnermail.io','emailfake.com','mytemp.email',
  'mailcatch.com','jetable.org','mohmal.in','tempmailer.com','tempmail.dev','luxusmail.org',
  'fake-mail.ml','fakemail.net','throwam.com','gufum.com','tafmail.com','mailpoof.com',
  'getairmail.com','mvrht.net','dropmail.me','mail-temporaire.fr','instantemailaddress.com',
  'mytrashmail.com','tempmail.plus','tempail.com','discard.email','discardmail.com',
  'gongjua.com',
]);

function domainOf(email) {
  const at = (email || '').lastIndexOf('@');
  return at >= 0 ? email.slice(at + 1).trim().toLowerCase() : '';
}

function isDisposableEmail(email) {
  const d = domainOf(email);
  if (!d) return false;
  if (DISPOSABLE_DOMAINS.has(d)) return true;
  // Also block subdomains of a listed disposable domain (e.g. foo.mailinator.com)
  const parts = d.split('.');
  for (let i = 1; i < parts.length; i++) {
    if (DISPOSABLE_DOMAINS.has(parts.slice(i).join('.'))) return true;
  }
  return false;
}

// Check that the domain actually has mail exchangers (cheap “does this address
// plausibly exist” filter — catches typos like gnail.com / randomxyz.com).
async function hasValidMX(email) {
  if (SKIP_MX_CHECK) return true;
  const d = domainOf(email);
  if (!d) return false;
  try {
    const mx = await dns.resolveMx(d);
    if (mx && mx.length) return true;
  } catch (_) { /* fall through */ }
  try {
    // Some domains publish only A/AAAA records for the mail host.
    const a = await dns.resolve4(d).catch(() => null);
    const aaaa = await dns.resolve6(d).catch(() => null);
    if ((a && a.length) || (aaaa && aaaa.length)) return true;
  } catch (_) { /* ignore */ }
  return false;
}

function generateOtp() {
  // 6-digit numeric, uniform (crypto.randomInt is unbiased).
  return String(crypto.randomInt(0, 1_000_000)).padStart(6, '0');
}

function hashOtp(otp) {
  return crypto.createHmac('sha256', JWT_SECRET).update(String(otp)).digest('hex');
}

async function sendOtpEmail(email, otp, name) {
  if (!mailer) throw new Error('Email service not configured');
  const prettyName = (name && name.trim()) || 'there';
  const subject = `Your PassportPrint verification code: ${otp}`;
  const text = [
    `Hi ${prettyName},`,
    '',
    `Your PassportPrint Studio verification code is: ${otp}`,
    `This code will expire in ${Math.round(OTP_TTL_MS / 60000)} minutes.`,
    '',
    'If you didn\'t request this, you can safely ignore this email.',
    '',
    '— PassportPrint Studio',
  ].join('\n');
  const html = `
    <div style="font-family:-apple-system,Segoe UI,Roboto,Arial,sans-serif;background:#0b0b14;color:#e6e6f0;padding:32px 24px;max-width:560px;margin:0 auto;border-radius:12px;">
      <div style="font-size:20px;font-weight:700;letter-spacing:.3px;margin-bottom:8px;">Passport<em style="color:#7c5cff;font-style:normal;">Print</em> Studio</div>
      <div style="color:#a0a0c0;font-size:13px;margin-bottom:24px;">Email verification</div>
      <div style="color:#e6e6f0;font-size:15px;line-height:1.6;margin-bottom:20px;">Hi ${prettyName.replace(/[<>]/g,'')}, use the code below to verify your email address:</div>
      <div style="font-family:'Courier New',monospace;font-size:32px;font-weight:700;letter-spacing:8px;text-align:center;background:#15151f;padding:18px;border-radius:10px;color:#fff;margin-bottom:20px;">${otp}</div>
      <div style="color:#a0a0c0;font-size:12px;line-height:1.6;">This code will expire in ${Math.round(OTP_TTL_MS / 60000)} minutes. If you didn't request this, you can safely ignore this email.</div>
      <div style="color:#6b6b88;font-size:11px;margin-top:28px;border-top:1px solid #222234;padding-top:14px;">— PassportPrint Studio</div>
    </div>`;
  await mailer.sendMail({ from: SMTP_FROM, to: email, subject, text, html });
}

function cleanupExpiredOtps() {
  try {
    db.prepare('DELETE FROM email_otps WHERE expires_at < ?')
      .run(Date.now() - OTP_VERIFY_WINDOW_MS);
  } catch (_) { /* ignore */ }
}
setInterval(cleanupExpiredOtps, 5 * 60 * 1000).unref?.();

// ── Express app ──
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '256kb' }));
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);              // allow curl / server-to-server
    if (CORS_ORIGINS.includes('*')) return cb(null, true);
    if (CORS_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('CORS blocked: ' + origin));
  },
  credentials: false,
}));

// Rate limits
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, standardHeaders: true });
const otpLimiter  = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, standardHeaders: true });
const apiLimiter  = rateLimit({ windowMs:  1 * 60 * 1000, max: 60 });
app.use('/api/', apiLimiter);

// ── Helpers ──
function signToken(userId) {
  return jwt.sign({ uid: userId }, JWT_SECRET, { expiresIn: '30d' });
}
function authRequired(req, res, next) {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: 'Missing Authorization header' });
  try {
    const payload = jwt.verify(m[1], JWT_SECRET);
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(payload.uid);
    if (!user) return res.status(401).json({ error: 'User not found' });
    req.user = user;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}
function publicUser(u) {
  if (!u) return null;
  const active = u.plan !== 'free' && u.plan_expires_at > Date.now();
  return {
    id: u.id,
    email: u.email,
    name: u.name,
    plan: active ? u.plan : 'free',
    planExpiresAt: active ? u.plan_expires_at : 0,
    createdAt: u.created_at,
  };
}
function validEmail(s) { return typeof s === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(s); }

function effectivePlan(user) {
  if (!user || !user.plan || user.plan === 'free') return 'free';
  if (!user.plan_expires_at || user.plan_expires_at <= Date.now()) return 'free';
  return user.plan;
}

// Returns a YYYY-MM-DD string in the configured reset timezone (default IST).
function dayKeyFor(ts) {
  const shifted = new Date(ts + DAILY_RESET_TZ_OFFSET_MIN * 60 * 1000);
  const y = shifted.getUTCFullYear();
  const m = String(shifted.getUTCMonth() + 1).padStart(2, '0');
  const d = String(shifted.getUTCDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function getDownloadSnapshot(user) {
  const plan      = effectivePlan(user);
  const limit     = Number.isFinite(DAILY_LIMITS[plan]) ? DAILY_LIMITS[plan] : 0;
  const unlimited = limit === 0;
  const dayKey    = dayKeyFor(Date.now());
  const row = db.prepare(
    'SELECT count FROM downloads_daily WHERE user_id = ? AND day_key = ?'
  ).get(user.id, dayKey);
  const used      = row ? row.count : 0;
  const remaining = unlimited ? Infinity : Math.max(0, limit - used);
  return { plan, limit, used, remaining, unlimited, dayKey };
}

function serializeSnapshot(snap) {
  return {
    plan:      snap.plan,
    limit:     snap.limit,
    used:      snap.used,
    remaining: snap.unlimited ? null : snap.remaining,
    unlimited: snap.unlimited,
    dayKey:    snap.dayKey,
  };
}

// ── Routes ──
app.get('/health', (req, res) => {
  res.json({ ok: true, razorpayConfigured: !!razorpay, mailerConfigured: !!mailer });
});

// ── OTP: request a fresh 6-digit code for a given email ──
app.post('/api/request-otp', otpLimiter, async (req, res) => {
  try {
    const { email, name, purpose } = req.body || {};
    if (!validEmail(email)) return res.status(400).json({ error: 'Invalid email' });
    const lower = email.trim().toLowerCase();
    const p = purpose === 'signup' ? 'signup' : 'signup';

    if (isDisposableEmail(lower)) {
      return res.status(400).json({ error: 'Disposable email addresses are not allowed. Please use a real email.' });
    }

    if (p === 'signup') {
      const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(lower);
      if (exists) return res.status(409).json({ error: 'Email already registered. Please login instead.' });
    }

    const mxOk = await hasValidMX(lower);
    if (!mxOk) {
      return res.status(400).json({ error: 'This email domain does not accept mail. Please check for typos.' });
    }

    // Resend cooldown: same email can\'t request again within OTP_RESEND_MS.
    const existing = db.prepare('SELECT created_at FROM email_otps WHERE email = ?').get(lower);
    if (existing && Date.now() - existing.created_at < OTP_RESEND_MS) {
      const waitMs = OTP_RESEND_MS - (Date.now() - existing.created_at);
      return res.status(429).json({
        error: `Please wait ${Math.ceil(waitMs / 1000)}s before requesting a new code.`,
        resendAfter: waitMs,
      });
    }

    if (!mailer) return res.status(503).json({ error: 'Email service not configured on server.' });

    const otp  = generateOtp();
    const now  = Date.now();
    const hash = hashOtp(otp);
    db.prepare(`
      INSERT INTO email_otps (email, otp_hash, purpose, created_at, expires_at, attempts, verified_at)
      VALUES (?, ?, ?, ?, ?, 0, NULL)
      ON CONFLICT(email) DO UPDATE SET
        otp_hash    = excluded.otp_hash,
        purpose     = excluded.purpose,
        created_at  = excluded.created_at,
        expires_at  = excluded.expires_at,
        attempts    = 0,
        verified_at = NULL
    `).run(lower, hash, p, now, now + OTP_TTL_MS);

    try {
      await sendOtpEmail(lower, otp, name);
    } catch (e) {
      console.error('sendOtpEmail failed:', e && e.message || e);
      // Drop the stored OTP so the user can retry immediately.
      db.prepare('DELETE FROM email_otps WHERE email = ?').run(lower);
      return res.status(502).json({ error: 'Could not send verification email. Please try again in a moment.' });
    }

    res.json({
      ok: true,
      expiresIn:   OTP_TTL_MS,
      resendAfter: OTP_RESEND_MS,
      maxAttempts: OTP_MAX_TRIES,
    });
  } catch (e) {
    console.error('request-otp error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/plans', (req, res) => {
  res.json({
    plans: [
      { id: 'free',    name: 'Free',    amount: 0,                 days: 0,  currency: 'INR' },
      { id: 'weekly',  name: 'Weekly',  amount: PLANS.weekly.amount,  days: 7,  currency: 'INR' },
      { id: 'monthly', name: 'Monthly', amount: PLANS.monthly.amount, days: 30, currency: 'INR' },
    ],
    razorpayKeyId: RAZORPAY_KEY_ID || null,
  });
});

app.post('/api/signup', authLimiter, async (req, res) => {
  try {
    const { name, email, password, otp } = req.body || {};
    if (!name || typeof name !== 'string' || name.length > 80) return res.status(400).json({ error: 'Invalid name' });
    if (!validEmail(email))                                     return res.status(400).json({ error: 'Invalid email' });
    if (!password || password.length < 6 || password.length > 200)
      return res.status(400).json({ error: 'Password must be 6–200 chars' });
    if (!otp || !/^\d{6}$/.test(String(otp))) return res.status(400).json({ error: 'Enter the 6-digit code we emailed you.' });

    const lower = email.trim().toLowerCase();

    if (isDisposableEmail(lower)) {
      return res.status(400).json({ error: 'Disposable email addresses are not allowed.' });
    }

    const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(lower);
    if (exists) return res.status(409).json({ error: 'Email already registered' });

    // ── Verify OTP ──
    const row = db.prepare('SELECT * FROM email_otps WHERE email = ?').get(lower);
    if (!row) return res.status(400).json({ error: 'No verification code found. Please request a new one.' });
    if (row.expires_at < Date.now()) {
      db.prepare('DELETE FROM email_otps WHERE email = ?').run(lower);
      return res.status(400).json({ error: 'Verification code expired. Please request a new one.' });
    }
    if (row.attempts >= OTP_MAX_TRIES) {
      db.prepare('DELETE FROM email_otps WHERE email = ?').run(lower);
      return res.status(429).json({ error: 'Too many incorrect attempts. Please request a new code.' });
    }
    const submittedHash = hashOtp(String(otp));
    if (submittedHash !== row.otp_hash) {
      db.prepare('UPDATE email_otps SET attempts = attempts + 1 WHERE email = ?').run(lower);
      const left = OTP_MAX_TRIES - (row.attempts + 1);
      return res.status(400).json({
        error: left > 0
          ? `Incorrect code. ${left} attempt${left === 1 ? '' : 's'} remaining.`
          : 'Too many incorrect attempts. Please request a new code.',
      });
    }
    // OTP good — consume it.
    db.prepare('DELETE FROM email_otps WHERE email = ?').run(lower);

    const hash = await bcrypt.hash(password, 11);
    const info = db.prepare(
      'INSERT INTO users (email, name, password_hash, plan, plan_expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(lower, name.trim(), hash, 'free', 0, Date.now());

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    const token = signToken(user.id);
    res.json({ token, user: publicUser(user) });
  } catch (e) {
    console.error('signup error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!validEmail(email) || !password) return res.status(400).json({ error: 'Invalid credentials' });

    const lower = email.trim().toLowerCase();
    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(lower);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const token = signToken(user.id);
    res.json({ token, user: publicUser(user) });
  } catch (e) {
    console.error('login error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/me', authRequired, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

app.get('/api/download-status', authRequired, (req, res) => {
  try {
    const snap = getDownloadSnapshot(req.user);
    res.json(serializeSnapshot(snap));
  } catch (e) {
    console.error('download-status error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/track-download', authRequired, (req, res) => {
  try {
    const snap = getDownloadSnapshot(req.user);

    if (snap.unlimited) {
      return res.json({ ok: true, ...serializeSnapshot(snap) });
    }

    if (snap.used >= snap.limit) {
      return res.status(429).json({
        ok: false,
        error: 'Daily free limit reached',
        ...serializeSnapshot(snap),
      });
    }

    const now = Date.now();
    db.prepare(`
      INSERT INTO downloads_daily (user_id, day_key, count, updated_at)
      VALUES (?, ?, 1, ?)
      ON CONFLICT(user_id, day_key)
      DO UPDATE SET count = count + 1, updated_at = excluded.updated_at
    `).run(req.user.id, snap.dayKey, now);

    const updated = getDownloadSnapshot(req.user);
    res.json({ ok: true, ...serializeSnapshot(updated) });
  } catch (e) {
    console.error('track-download error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/create-order', authRequired, async (req, res) => {
  try {
    if (!razorpay) return res.status(500).json({ error: 'Razorpay not configured on server' });

    const { plan } = req.body || {};
    const p = PLANS[plan];
    if (!p) return res.status(400).json({ error: 'Invalid plan' });

    const order = await razorpay.orders.create({
      amount: p.amount,
      currency: 'INR',
      receipt: `pps_${req.user.id}_${Date.now()}`,
      notes: { userId: String(req.user.id), plan: p.id },
    });

    db.prepare(
      'INSERT INTO payments (user_id, razorpay_order_id, plan, amount, status, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(req.user.id, order.id, p.id, p.amount, 'created', Date.now());

    res.json({
      orderId:  order.id,
      amount:   order.amount,
      currency: order.currency,
      keyId:    RAZORPAY_KEY_ID,
      plan:     p.id,
      user: { name: req.user.name, email: req.user.email },
    });
  } catch (e) {
    console.error('create-order error:', e);
    res.status(500).json({ error: 'Could not create order' });
  }
});

app.post('/api/verify-payment', authRequired, (req, res) => {
  try {
    const { orderId, paymentId, signature, plan } = req.body || {};
    if (!orderId || !paymentId || !signature || !PLANS[plan]) {
      return res.status(400).json({ error: 'Missing fields' });
    }

    // Verify HMAC-SHA256(orderId + '|' + paymentId, key_secret) === signature
    const expected = crypto
      .createHmac('sha256', RAZORPAY_KEY_SECRET)
      .update(`${orderId}|${paymentId}`)
      .digest('hex');

    if (expected !== signature) {
      db.prepare('UPDATE payments SET status = ?, razorpay_payment_id = ?, razorpay_signature = ? WHERE razorpay_order_id = ? AND user_id = ?')
        .run('invalid_signature', paymentId, signature, orderId, req.user.id);
      return res.status(400).json({ error: 'Invalid signature — payment rejected' });
    }

    // Confirm the order belongs to this user and is in 'created' state
    const payment = db.prepare(
      'SELECT * FROM payments WHERE razorpay_order_id = ? AND user_id = ?'
    ).get(orderId, req.user.id);
    if (!payment) return res.status(404).json({ error: 'Order not found' });
    if (payment.plan !== plan) return res.status(400).json({ error: 'Plan mismatch' });

    const now = Date.now();
    const p = PLANS[plan];
    const expires = now + p.days * 24 * 3600 * 1000;

    const tx = db.transaction(() => {
      db.prepare(
        'UPDATE payments SET status = ?, razorpay_payment_id = ?, razorpay_signature = ?, verified_at = ? WHERE id = ?'
      ).run('paid', paymentId, signature, now, payment.id);

      db.prepare(
        'UPDATE users SET plan = ?, plan_expires_at = ? WHERE id = ?'
      ).run(plan, expires, req.user.id);
    });
    tx();

    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
    res.json({ ok: true, user: publicUser(user) });
  } catch (e) {
    console.error('verify-payment error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Generic error handler
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  console.error('unhandled:', err);
  res.status(500).json({ error: err.message || 'Server error' });
});

app.listen(PORT, () => {
  console.log(`✓ PassportPrint backend listening on port ${PORT}`);
  console.log(`  Razorpay: ${razorpay ? 'configured' : 'NOT configured'}`);
  console.log(`  Mailer:   ${mailer   ? 'configured' : 'NOT configured'}`);
  console.log(`  DB:       ${DB_PATH}`);
  console.log(`  CORS:     ${CORS_ORIGINS.join(', ')}`);
});
