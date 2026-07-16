# Brevo transactional email API checkpoint

Date: 2026-07-16

Local backend changes:
- Added Brevo HTTPS transactional email API as the primary provider when
  BREVO_API_KEY and BREVO_SENDER_EMAIL are configured.
- OTP signup and password-reset messages share the same provider abstraction.
- SMTP remains as a fallback only when Brevo is not configured.
- SMTP is not initialized or verified when Brevo is active.
- Added a 20-second abort timeout for Brevo API requests.
- Added provider-neutral diagnostics without logging API keys.
- Added health fields: emailConfigured, emailProvider, brevoConfigured,
  while retaining smtpConfigured.
- Added empty Brevo environment placeholders and source-contract tests.

Required Render variables before production verification:
- BREVO_API_KEY
- BREVO_SENDER_EMAIL
- BREVO_SENDER_NAME=Studio Print
- Optional: BREVO_API_URL and BREVO_TIMEOUT_MS

No Git stage, commit, push, Render deployment, or frontend deployment was performed.
