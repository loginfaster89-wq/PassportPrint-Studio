# PassportPrint Studio — Backend

Node.js + Express backend for user authentication and Razorpay payments.

## Features

- ✅ Signup / Login with **bcrypt** password hashing
- ✅ **JWT** authentication (30-day tokens)
- ✅ Razorpay Orders API + **HMAC signature verification** (fraud-proof)
- ✅ SQLite database (no separate DB server needed)
- ✅ Rate limiting on auth endpoints
- ✅ CORS configured via env var

## Endpoints

| Method | Path                  | Auth    | Description                       |
|--------|-----------------------|---------|-----------------------------------|
| GET    | `/health`             | –       | Health check                      |
| GET    | `/api/plans`          | –       | List of plans + Razorpay public key |
| POST   | `/api/signup`         | –       | `{name,email,password}` → token   |
| POST   | `/api/login`          | –       | `{email,password}` → token        |
| GET    | `/api/me`             | Bearer  | Current user + plan               |
| POST   | `/api/create-order`   | Bearer  | `{plan}` → Razorpay orderId       |
| POST   | `/api/verify-payment` | Bearer  | Verify signature, activate plan   |

---

## Local setup (5 min)

```bash
# 1. Install dependencies
cd backend
npm install

# 2. Copy env template
cp .env.example .env

# 3. Get Razorpay TEST keys
# https://dashboard.razorpay.com/app/keys
# Paste them into .env (RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET)

# 4. Generate a strong JWT secret
openssl rand -hex 64
# Paste output into .env as JWT_SECRET=<that-value>

# 5. Run
npm start
# → ✓ PassportPrint backend listening on port 4000
```

Test it:
```bash
curl http://localhost:4000/health
# {"ok":true,"razorpayConfigured":true}
```

---

## Deploy to Render.com (free, recommended)

1. Push this `backend/` folder to a GitHub repo.
2. Go to https://render.com → New → **Web Service**.
3. Connect your GitHub repo, pick the `backend/` folder (or whole repo if it's alone).
4. Settings:
   - **Environment**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Plan**: Free
5. Add environment variables (Settings → Environment):
   - `JWT_SECRET` — run `openssl rand -hex 64` to generate
   - `RAZORPAY_KEY_ID` — from Razorpay dashboard
   - `RAZORPAY_KEY_SECRET` — from Razorpay dashboard
   - `CORS_ORIGINS` — `https://yourfrontend.com,https://ajaykumar581.github.io` (comma-separated)
   - `DB_PATH` — `/data/pps.db` (if you attach a disk, else leave default)
6. **(Optional but recommended)** Attach a persistent disk:
   - Add Disk → mount path `/data`, size 1 GB (free tier allows 1 GB).
   - Set `DB_PATH=/data/pps.db` so the DB survives restarts/redeploys.
7. Deploy. Note your service URL (e.g. `https://passportprint-api.onrender.com`).
8. In your `index.html`, set the `BACKEND_URL` constant at the top of the script block to that URL.

---

## Deploy to Railway.app (alternative)

1. Push to GitHub.
2. https://railway.app → New Project → Deploy from GitHub repo.
3. Add the same env vars as above (Variables tab).
4. Railway auto-detects Node + `npm start`. Done.
5. For persistent DB: attach a Volume, mount at `/data`, set `DB_PATH=/data/pps.db`.

---

## Security notes

- **Always use HTTPS** in production (Render/Railway give you this free).
- Set `CORS_ORIGINS` to only your frontend domain in production (no `*`).
- Keep `RAZORPAY_KEY_SECRET` secret — never commit it to git.
- The JWT secret should be at least 64 hex chars (256 bits of entropy).
- Rate limits: 20 login/signup attempts per 15 min per IP; 60 API calls per min per IP.
- `better-sqlite3` uses WAL mode — safe for single-instance deploys. For multi-instance horizontal scaling, migrate to Postgres (change 5 lines in `server.js`).

## Frontend integration

In the frontend's `index.html`, at the top of the `<script>` block, set:

```js
const BACKEND_URL = 'https://your-backend.onrender.com';  // ← your deployed URL
```

When `BACKEND_URL` is empty string, the frontend falls back to localStorage-only mode (no real payments, no cross-device sync).

## Razorpay webhook (optional extra safety)

Razorpay supports webhooks for async events. If you want double-verification:

1. In Razorpay Dashboard → Settings → Webhooks → Add webhook.
2. URL: `https://your-backend.onrender.com/api/razorpay-webhook` (not yet implemented — add if needed).
3. Secret: generate one in the dashboard, add to `.env` as `RAZORPAY_WEBHOOK_SECRET`.
4. Ask me and I'll add the webhook endpoint — it re-verifies payment status server-side in case the client never calls `/api/verify-payment` (e.g. user closes tab mid-payment).
