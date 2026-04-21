// ════════════════════════════════════════════════════════════
// PassportPrint Studio — Backend API
// Node.js + Express + libSQL (Turso / local SQLite) + Razorpay + JWT + bcrypt
// ════════════════════════════════════════════════════════════
// Endpoints:
//   POST /api/signup                 { name, email, password }        → { token, user }
//   POST /api/login                  { email, password }              → { token, user }
//   GET  /api/me                     (Bearer token)                    → { user }
//   POST /api/delete-account         (Bearer token)                    → { ok: true }
//   POST /api/send-password-reset-otp { email }                        → { otpSent, email, expiresInSec }
//   POST /api/reset-password         { email, otp, newPassword }       → { token, user }
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
const { createClient } = require('@libsql/client');
const { AsyncLocalStorage } = require('node:async_hooks');
const Razorpay      = require('razorpay');
const rateLimit     = require('express-rate-limit');
const nodemailer    = require('nodemailer');

// ── Config ──
const PORT                = parseInt(process.env.PORT || '4000', 10);
const JWT_SECRET          = process.env.JWT_SECRET || 'dev-only-secret-change-me';
const RAZORPAY_KEY_ID     = process.env.RAZORPAY_KEY_ID || '';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';
const DB_PATH             = process.env.DB_PATH || './pps.db';
const CORS_ORIGINS        = (process.env.CORS_ORIGINS || '*').split(',').map(s => s.trim());

// libSQL / Turso connection. If TURSO_DATABASE_URL is set we use the hosted
// libSQL DB (recommended for production — survives container restarts).
// Otherwise we fall back to a local SQLite file at DB_PATH (good for dev).
const LIBSQL_URL        = process.env.TURSO_DATABASE_URL || process.env.LIBSQL_URL || ('file:' + DB_PATH);
const LIBSQL_AUTH_TOKEN = process.env.TURSO_AUTH_TOKEN   || process.env.LIBSQL_AUTH_TOKEN || '';

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

// ── SMTP / OTP ──
const SMTP_HOST   = process.env.SMTP_HOST   || 'smtp.gmail.com';
const SMTP_PORT   = parseInt(process.env.SMTP_PORT || '465', 10);
const SMTP_SECURE = (process.env.SMTP_SECURE || 'true').toLowerCase() === 'true';
const SMTP_USER   = process.env.SMTP_USER   || '';
const SMTP_PASS   = process.env.SMTP_PASS   || '';
const SMTP_FROM   = process.env.SMTP_FROM   || (SMTP_USER ? `PassportPrint Studio <${SMTP_USER}>` : '');
const OTP_TTL_MS  = Math.max(60, parseInt(process.env.OTP_TTL_SEC || '600', 10)) * 1000;

let mailer = null;
if (SMTP_USER && SMTP_PASS) {
  mailer = nodemailer.createTransport({
    host: SMTP_HOST,
    port: SMTP_PORT,
    secure: SMTP_SECURE,
    auth: { user: SMTP_USER, pass: SMTP_PASS.replace(/\s+/g, '') },
  });
  mailer.verify().then(
    () => console.log(`✓ SMTP ready (${SMTP_USER} via ${SMTP_HOST}:${SMTP_PORT})`),
    (e) => console.warn('⚠️  SMTP verify failed:', e.message)
  );
} else {
  console.warn('⚠️  SMTP not configured — OTP email verification will fail until SMTP_USER and SMTP_PASS are set.');
}

// ── DB (libSQL, async) ──
// Thin wrapper that mimics the better-sqlite3 API (`prepare().get/run/all`,
// `exec`, `pragma`, `transaction`) but is async on top of @libsql/client.
// Every call site therefore `await`s the result. Transactions pin the
// underlying tx object via AsyncLocalStorage so `db.prepare(...).run(...)`
// inside a `db.transaction(fn)` callback automatically participates.
const _client = createClient({
  url: LIBSQL_URL,
  ...(LIBSQL_AUTH_TOKEN ? { authToken: LIBSQL_AUTH_TOKEN } : {}),
});
const _txStore = new AsyncLocalStorage();
function _runner() { return _txStore.getStore() || _client; }
function _materialize(row) {
  if (!row || typeof row !== 'object') return row;
  const o = {};
  for (const k of Object.keys(row)) {
    const v = row[k];
    o[k] = typeof v === 'bigint' ? Number(v) : v;
  }
  return o;
}
const db = {
  prepare(sql) {
    return {
      async get(...args) {
        const r = await _runner().execute({ sql, args });
        return r.rows[0] ? _materialize(r.rows[0]) : undefined;
      },
      async run(...args) {
        const r = await _runner().execute({ sql, args });
        return {
          lastInsertRowid: r.lastInsertRowid == null ? 0 : Number(r.lastInsertRowid),
          changes: r.rowsAffected || 0,
        };
      },
      async all(...args) {
        const r = await _runner().execute({ sql, args });
        return r.rows.map(_materialize);
      },
    };
  },
  async exec(sqlBlock) {
    await _client.executeMultiple(sqlBlock);
  },
  async pragma(stmt) {
    // Remote libSQL ignores most pragmas; swallow failures so startup still works.
    try { await _client.execute(`PRAGMA ${stmt}`); } catch (e) { /* no-op on remote */ }
  },
  transaction(fn) {
    return async (...args) => {
      const tx = await _client.transaction('write');
      try {
        const result = await _txStore.run(tx, () => fn(...args));
        await tx.commit();
        return result;
      } catch (e) {
        try { await tx.rollback(); } catch (_) {}
        throw e;
      }
    };
  },
};

async function initDb() {
  await db.pragma('journal_mode = WAL');
  await db.exec(`
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

    CREATE TABLE IF NOT EXISTS pending_signups (
      email          TEXT PRIMARY KEY,
      name           TEXT NOT NULL,
      password_hash  TEXT NOT NULL,
      otp_hash       TEXT NOT NULL,
      attempts       INTEGER NOT NULL DEFAULT 0,
      expires_at     INTEGER NOT NULL,
      created_at     INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS password_resets (
      email          TEXT PRIMARY KEY,
      otp_hash       TEXT NOT NULL,
      attempts       INTEGER NOT NULL DEFAULT 0,
      expires_at     INTEGER NOT NULL,
      created_at     INTEGER NOT NULL
    );
  `);
}

// ── Razorpay SDK (may throw if keys missing, guard at use site) ──
let razorpay = null;
if (RAZORPAY_KEY_ID && RAZORPAY_KEY_SECRET) {
  razorpay = new Razorpay({ key_id: RAZORPAY_KEY_ID, key_secret: RAZORPAY_KEY_SECRET });
}

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
const apiLimiter  = rateLimit({ windowMs:  1 * 60 * 1000, max: 60 });
app.use('/api/', apiLimiter);

// ── Helpers ──
function signToken(userId) {
  return jwt.sign({ uid: userId }, JWT_SECRET, { expiresIn: '30d' });
}
async function authRequired(req, res, next) {
  const h = req.headers.authorization || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return res.status(401).json({ error: 'Missing Authorization header' });
  let payload;
  try {
    payload = jwt.verify(m[1], JWT_SECRET);
  } catch (e) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  try {
    const user = await db.prepare('SELECT * FROM users WHERE id = ?').get(payload.uid);
    if (!user) return res.status(401).json({ error: 'User not found' });
    req.user = user;
    next();
  } catch (e) {
    console.error('authRequired db error:', e);
    return res.status(500).json({ error: 'Server error' });
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
// Only accept official @gmail.com addresses (owner request: trademark Gmail only).
function validGmail(s) {
  if (typeof s !== 'string') return false;
  const lower = s.trim().toLowerCase();
  // local-part: letters, digits, dot, underscore, plus, minus. Must start/end alnum.
  return /^[a-z0-9][a-z0-9._+\-]{0,62}[a-z0-9]@gmail\.com$/.test(lower);
}
function genOtp() {
  // 6-digit zero-padded numeric code.
  return String(crypto.randomInt(0, 1000000)).padStart(6, '0');
}
function otpEmailBody(otp, purpose) {
  const minutes = Math.round(OTP_TTL_MS / 60000);
  const intro = purpose === 'reset'
    ? 'Use the code below to reset your password.'
    : 'Use the code below to verify your email address.';
  const subject = purpose === 'reset'
    ? `Your PassportPrint Studio password reset code: ${otp}`
    : `Your PassportPrint Studio verification code: ${otp}`;
  const text =
`${intro}

Code: ${otp}

This code expires in ${minutes} minutes.
If you did not request this, please ignore this email.`;
  const html = `
<div style="font-family:Segoe UI,Roboto,Arial,sans-serif;max-width:480px;margin:0 auto;padding:24px;background:#0d0d16;color:#e7e7f0;border-radius:12px;">
  <h2 style="margin:0 0 12px;color:#fff;font-weight:700;">PassportPrint <em style="color:#7cc4ff;font-style:normal;">Studio</em></h2>
  <p style="margin:0 0 16px;color:#bfbfd0;">${intro}</p>
  <div style="font-family:ui-monospace,Menlo,monospace;font-size:32px;letter-spacing:8px;font-weight:700;background:#1a1a26;border:1px solid #2a2a38;border-radius:10px;padding:16px 20px;text-align:center;color:#fff;">${otp}</div>
  <p style="margin:16px 0 0;color:#8c8ca0;font-size:12px;">This code expires in ${minutes} minutes. If you did not request it, you can ignore this email.</p>
</div>`;
  return { subject, text, html };
}

async function sendOtpEmail(to, otp) {
  if (!mailer) throw new Error('Email service not configured on server');
  const { subject, text, html } = otpEmailBody(otp, 'signup');
  await mailer.sendMail({ from: SMTP_FROM, to, subject, text, html });
}

async function sendPasswordResetEmail(to, otp) {
  if (!mailer) throw new Error('Email service not configured on server');
  const { subject, text, html } = otpEmailBody(otp, 'reset');
  await mailer.sendMail({ from: SMTP_FROM, to, subject, text, html });
}

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

async function getDownloadSnapshot(user) {
  const plan      = effectivePlan(user);
  const limit     = Number.isFinite(DAILY_LIMITS[plan]) ? DAILY_LIMITS[plan] : 0;
  const unlimited = limit === 0;
  const dayKey    = dayKeyFor(Date.now());
  const row = await db.prepare(
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
  res.json({ ok: true, razorpayConfigured: !!razorpay });
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

// ── Signup flow (OTP-verified) ──────────────────────────────────────────────
// Step 1: /api/send-signup-otp  — validates the Gmail address, stores a
// pending signup (with hashed password + hashed OTP) and emails the OTP.
// Step 2: /api/verify-signup-otp — checks the OTP and creates the user.
app.post('/api/send-signup-otp', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || typeof name !== 'string' || name.trim().length < 1 || name.length > 80) {
      return res.status(400).json({ error: 'Please enter your name.' });
    }
    if (!validGmail(email)) {
      return res.status(400).json({ error: 'Only @gmail.com addresses are accepted. Please use a valid Gmail account.' });
    }
    if (!password || password.length < 6 || password.length > 200) {
      return res.status(400).json({ error: 'Password must be 6–200 characters.' });
    }
    if (!mailer) {
      return res.status(503).json({ error: 'Email service is not configured on the server yet. Please try again later.' });
    }

    const lower = email.trim().toLowerCase();
    const exists = await db.prepare('SELECT id FROM users WHERE email = ?').get(lower);
    if (exists) return res.status(409).json({ error: 'This Gmail is already registered. Please login instead.' });

    const otp = genOtp();
    const [otpHash, passwordHash] = await Promise.all([
      bcrypt.hash(otp, 8),
      bcrypt.hash(password, 11),
    ]);
    const now = Date.now();
    const expiresAt = now + OTP_TTL_MS;
    await db.prepare(`
      INSERT INTO pending_signups (email, name, password_hash, otp_hash, attempts, expires_at, created_at)
      VALUES (?, ?, ?, ?, 0, ?, ?)
      ON CONFLICT(email) DO UPDATE SET
        name          = excluded.name,
        password_hash = excluded.password_hash,
        otp_hash      = excluded.otp_hash,
        attempts      = 0,
        expires_at    = excluded.expires_at,
        created_at    = excluded.created_at
    `).run(lower, name.trim(), passwordHash, otpHash, expiresAt, now);

    try {
      await sendOtpEmail(lower, otp);
    } catch (ex) {
      console.error('SMTP send failed:', ex && ex.message);
      // Roll back pending signup so the user can retry cleanly.
      await db.prepare('DELETE FROM pending_signups WHERE email = ?').run(lower);
      return res.status(502).json({
        error: 'We could not deliver a verification email to that Gmail address. Please check it and try again.',
      });
    }
    res.json({
      otpSent: true,
      email: lower,
      expiresInSec: Math.floor(OTP_TTL_MS / 1000),
    });
  } catch (e) {
    console.error('send-signup-otp error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/verify-signup-otp', authLimiter, async (req, res) => {
  try {
    const { email, otp } = req.body || {};
    if (!validGmail(email)) return res.status(400).json({ error: 'Invalid email.' });
    const code = String(otp || '').trim();
    if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Enter the 6-digit code we emailed you.' });

    const lower = email.trim().toLowerCase();
    const pending = await db.prepare('SELECT * FROM pending_signups WHERE email = ?').get(lower);
    if (!pending) return res.status(400).json({ error: 'No pending verification. Please sign up again.' });

    if (pending.expires_at < Date.now()) {
      await db.prepare('DELETE FROM pending_signups WHERE email = ?').run(lower);
      return res.status(400).json({ error: 'This code has expired. Please sign up again.' });
    }
    if (pending.attempts >= 5) {
      await db.prepare('DELETE FROM pending_signups WHERE email = ?').run(lower);
      return res.status(429).json({ error: 'Too many wrong attempts. Please sign up again.' });
    }

    const match = await bcrypt.compare(code, pending.otp_hash);
    if (!match) {
      await db.prepare('UPDATE pending_signups SET attempts = attempts + 1 WHERE email = ?').run(lower);
      return res.status(400).json({ error: 'Wrong code. Please try again.' });
    }

    // Defensive: make sure the user didn't get created in parallel.
    const existing = await db.prepare('SELECT * FROM users WHERE email = ?').get(lower);
    if (existing) {
      await db.prepare('DELETE FROM pending_signups WHERE email = ?').run(lower);
      const token = signToken(existing.id);
      return res.json({ token, user: publicUser(existing) });
    }

    const info = await db.prepare(
      'INSERT INTO users (email, name, password_hash, plan, plan_expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(lower, pending.name, pending.password_hash, 'free', 0, Date.now());
    await db.prepare('DELETE FROM pending_signups WHERE email = ?').run(lower);

    const user = await db.prepare('SELECT * FROM users WHERE id = ?').get(info.lastInsertRowid);
    const token = signToken(user.id);
    res.json({ token, user: publicUser(user) });
  } catch (e) {
    console.error('verify-signup-otp error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Legacy signup endpoint. Kept for backwards compatibility: now transparently
// kicks off the OTP flow so old clients still get a useful response.
app.post('/api/signup', authLimiter, (req, res, next) => {
  req.url = '/api/send-signup-otp';
  next('route');
});

app.post('/api/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || typeof email !== 'string') {
      return res.status(400).json({ error: 'Please enter your Gmail address.' });
    }
    if (!validGmail(email)) {
      return res.status(400).json({ error: 'Only @gmail.com addresses are accepted. Please use your Gmail account.' });
    }
    if (!password) return res.status(400).json({ error: 'Please enter your password.' });

    const lower = email.trim().toLowerCase();
    const user = await db.prepare('SELECT * FROM users WHERE email = ?').get(lower);
    if (!user) return res.status(404).json({ error: 'No account found with this Gmail. Please sign up first.' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Wrong password. Please try again.' });

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

// ── Password reset flow (OTP-verified) ─────────────────────────────────────
// Step 1: /api/send-password-reset-otp — verifies that the email belongs to a
// real user, stores a hashed OTP, and emails it.
// Step 2: /api/reset-password — checks the OTP and sets a new password,
// returning a fresh JWT so the user is logged in immediately.
app.post('/api/send-password-reset-otp', authLimiter, async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!validGmail(email)) {
      return res.status(400).json({ error: 'Only @gmail.com addresses are accepted.' });
    }
    if (!mailer) {
      return res.status(503).json({ error: 'Email service is not configured on the server yet. Please try again later.' });
    }

    const lower = email.trim().toLowerCase();
    const user = await db.prepare('SELECT id FROM users WHERE email = ?').get(lower);
    // For privacy, do not reveal whether the account exists. Pretend we sent
    // a code either way — but we only actually send/store it when the user
    // exists so attackers cannot enumerate Gmail addresses.
    if (!user) {
      return res.json({
        otpSent: true,
        email: lower,
        expiresInSec: Math.floor(OTP_TTL_MS / 1000),
      });
    }

    const otp = genOtp();
    const otpHash = await bcrypt.hash(otp, 8);
    const now = Date.now();
    const expiresAt = now + OTP_TTL_MS;
    await db.prepare(`
      INSERT INTO password_resets (email, otp_hash, attempts, expires_at, created_at)
      VALUES (?, ?, 0, ?, ?)
      ON CONFLICT(email) DO UPDATE SET
        otp_hash   = excluded.otp_hash,
        attempts   = 0,
        expires_at = excluded.expires_at,
        created_at = excluded.created_at
    `).run(lower, otpHash, expiresAt, now);

    try {
      await sendPasswordResetEmail(lower, otp);
    } catch (ex) {
      console.error('SMTP send (reset) failed:', ex && ex.message);
      await db.prepare('DELETE FROM password_resets WHERE email = ?').run(lower);
      return res.status(502).json({
        error: 'We could not deliver the reset email. Please try again in a moment.',
      });
    }
    res.json({
      otpSent: true,
      email: lower,
      expiresInSec: Math.floor(OTP_TTL_MS / 1000),
    });
  } catch (e) {
    console.error('send-password-reset-otp error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/reset-password', authLimiter, async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body || {};
    if (!validGmail(email)) return res.status(400).json({ error: 'Invalid email.' });
    const code = String(otp || '').trim();
    if (!/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Enter the 6-digit code we emailed you.' });
    if (!newPassword || newPassword.length < 6 || newPassword.length > 200) {
      return res.status(400).json({ error: 'Password must be 6–200 characters.' });
    }

    const lower = email.trim().toLowerCase();
    const pending = await db.prepare('SELECT * FROM password_resets WHERE email = ?').get(lower);
    if (!pending) return res.status(400).json({ error: 'No pending reset. Please request a new code.' });

    if (pending.expires_at < Date.now()) {
      await db.prepare('DELETE FROM password_resets WHERE email = ?').run(lower);
      return res.status(400).json({ error: 'This code has expired. Please request a new one.' });
    }
    if (pending.attempts >= 5) {
      await db.prepare('DELETE FROM password_resets WHERE email = ?').run(lower);
      return res.status(429).json({ error: 'Too many wrong attempts. Please request a new code.' });
    }

    const match = await bcrypt.compare(code, pending.otp_hash);
    if (!match) {
      await db.prepare('UPDATE password_resets SET attempts = attempts + 1 WHERE email = ?').run(lower);
      return res.status(400).json({ error: 'Wrong code. Please try again.' });
    }

    const user = await db.prepare('SELECT * FROM users WHERE email = ?').get(lower);
    if (!user) {
      await db.prepare('DELETE FROM password_resets WHERE email = ?').run(lower);
      return res.status(404).json({ error: 'Account not found.' });
    }

    const passwordHash = await bcrypt.hash(newPassword, 11);
    await db.transaction(async () => {
      await db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(passwordHash, user.id);
      await db.prepare('DELETE FROM password_resets WHERE email = ?').run(lower);
    })();

    const fresh = await db.prepare('SELECT * FROM users WHERE id = ?').get(user.id);
    const token = signToken(fresh.id);
    res.json({ token, user: publicUser(fresh) });
  } catch (e) {
    console.error('reset-password error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// Permanently delete the authenticated user's account and all associated data.
// After this succeeds the same Gmail address can be used to sign up again.
app.post('/api/delete-account', authRequired, async (req, res) => {
  try {
    const uid = req.user.id;
    const email = req.user.email;
    await db.transaction(async () => {
      await db.prepare('DELETE FROM downloads_daily WHERE user_id = ?').run(uid);
      await db.prepare('DELETE FROM payments WHERE user_id = ?').run(uid);
      await db.prepare('DELETE FROM pending_signups WHERE email = ?').run(email);
      await db.prepare('DELETE FROM users WHERE id = ?').run(uid);
    })();
    res.json({ ok: true });
  } catch (e) {
    console.error('delete-account error:', e);
    res.status(500).json({ error: 'Could not delete account' });
  }
});

app.get('/api/download-status', authRequired, async (req, res) => {
  try {
    const snap = await getDownloadSnapshot(req.user);
    res.json(serializeSnapshot(snap));
  } catch (e) {
    console.error('download-status error:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/track-download', authRequired, async (req, res) => {
  try {
    const snap = await getDownloadSnapshot(req.user);

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
    await db.prepare(`
      INSERT INTO downloads_daily (user_id, day_key, count, updated_at)
      VALUES (?, ?, 1, ?)
      ON CONFLICT(user_id, day_key)
      DO UPDATE SET count = count + 1, updated_at = excluded.updated_at
    `).run(req.user.id, snap.dayKey, now);

    const updated = await getDownloadSnapshot(req.user);
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

    await db.prepare(
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

app.post('/api/verify-payment', authRequired, async (req, res) => {
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
      await db.prepare('UPDATE payments SET status = ?, razorpay_payment_id = ?, razorpay_signature = ? WHERE razorpay_order_id = ? AND user_id = ?')
        .run('invalid_signature', paymentId, signature, orderId, req.user.id);
      return res.status(400).json({ error: 'Invalid signature — payment rejected' });
    }

    // Confirm the order belongs to this user and is in 'created' state
    const payment = await db.prepare(
      'SELECT * FROM payments WHERE razorpay_order_id = ? AND user_id = ?'
    ).get(orderId, req.user.id);
    if (!payment) return res.status(404).json({ error: 'Order not found' });
    if (payment.plan !== plan) return res.status(400).json({ error: 'Plan mismatch' });

    const now = Date.now();
    const p = PLANS[plan];
    const expires = now + p.days * 24 * 3600 * 1000;

    await db.transaction(async () => {
      await db.prepare(
        'UPDATE payments SET status = ?, razorpay_payment_id = ?, razorpay_signature = ?, verified_at = ? WHERE id = ?'
      ).run('paid', paymentId, signature, now, payment.id);

      await db.prepare(
        'UPDATE users SET plan = ?, plan_expires_at = ? WHERE id = ?'
      ).run(plan, expires, req.user.id);
    })();

    const user = await db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
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

(async () => {
  try {
    await initDb();
    app.listen(PORT, () => {
      const host = (LIBSQL_URL.startsWith('file:') ? LIBSQL_URL : (LIBSQL_URL.split('//')[1] || LIBSQL_URL).split('.')[0]);
      console.log(`✓ PassportPrint backend listening on port ${PORT}`);
      console.log(`  Razorpay: ${razorpay ? 'configured' : 'NOT configured'}`);
      console.log(`  DB:       ${host}`);
      console.log(`  CORS:     ${CORS_ORIGINS.join(', ')}`);
    });
  } catch (e) {
    console.error('Fatal: failed to initialize DB:', e);
    process.exit(1);
  }
})();
