# SMTP timeout and diagnostics checkpoint

Date: 2026-07-16

Local backend changes:
- Added explicit SMTP DNS, connection, greeting, and socket timeouts.
- Defaults: DNS 10s, connection 15s, greeting 10s, socket 20s.
- Added environment overrides for all four values.
- Added safe high-level SMTP error diagnostics without logging credentials.
- Added send duration and message-id logging after SMTP acceptance.
- Disabled file and URL content access in Nodemailer.
- Kept Gmail host, port, secure mode, user, password, sender and OTP logic unchanged.
- Added source-contract tests.

Expected production behavior:
- A blocked or stalled SMTP send should fail in roughly 10-20 seconds instead
  of leaving the HTTP request hanging beyond 95 seconds.
- The route should return its existing generic 502 response.
- Render logs should expose the actionable Nodemailer error code/command.

No Git stage, commit, push, Render deployment, or frontend deployment was performed.
- V2 corrects the source-contract assertion for the shared purpose template.
