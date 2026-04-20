// ════════════════════════════════════════════════════════════
// PassportPrint Studio — Backend API
// Node.js + Express + SQLite + Razorpay + JWT + bcrypt
// ════════════════════════════════════════════════════════════
// Endpoints:
//   POST /api/signup           { name, email, password }        → { token, user }
//   POST /api/login            { email, password }              → { token, user }
//   GET  /api/me               (Bearer token)                    → { user }
//   POST /api/create-order     (Bearer) { plan: 'weekly'|'monthly' }
//                                                               → { orderId, amount, currency, keyId }
//   POST /api/verify-payment   (Bearer) { orderId, paymentId, signature, plan }
//                                                               → { ok: true, user }
//   GET  /api/plans            → { plans: [...] }
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

// ── Config ──
const PORT                = parseInt(process.env.PORT || '4000', 10);
const JWT_SECRET          = process.env.JWT_SECRET || 'dev-only-secret-change-me';
const RAZORPAY_KEY_ID     = process.env.RAZORPAY_KEY_ID || '';
const RAZORPAY_KEY_SECRET = process.env.RAZORPAY_KEY_SECRET || '';
const DB_PATH             = process.env.DB_PATH || './pps.db';
const CORS_ORIGINS        = (process.env.CORS_ORIGINS || '*').split(',').map(s => s.trim());

const PLANS = {
  weekly:  { id: 'weekly',  name: 'Weekly',  amount: parseInt(process.env.PRICE_WEEKLY  || '4900',  10), days: 7  },
  monthly: { id: 'monthly', name: 'Monthly', amount: parseInt(process.env.PRICE_MONTHLY || '14900', 10), days: 30 },
};

if (JWT_SECRET === 'dev-only-secret-change-me') {
  console.warn('⚠️  JWT_SECRET is not set — using default. DO NOT use in production.');
}
if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
  console.warn('⚠️  Razorpay keys missing — payment endpoints will fail until configured.');
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
`);

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

app.post('/api/signup', authLimiter, async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!name || typeof name !== 'string' || name.length > 80) return res.status(400).json({ error: 'Invalid name' });
    if (!validEmail(email))                                     return res.status(400).json({ error: 'Invalid email' });
    if (!password || password.length < 6 || password.length > 200)
      return res.status(400).json({ error: 'Password must be 6–200 chars' });

    const lower = email.trim().toLowerCase();
    const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(lower);
    if (exists) return res.status(409).json({ error: 'Email already registered' });

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
  console.log(`  DB:       ${DB_PATH}`);
  console.log(`  CORS:     ${CORS_ORIGINS.join(', ')}`);
});
