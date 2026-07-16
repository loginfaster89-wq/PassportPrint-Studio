'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const serverSource = fs.readFileSync(
  path.join(__dirname, '..', 'server.js'),
  'utf8'
);

test('SMTP transport uses explicit fail-fast timeouts', () => {
  for (const marker of [
    'SMTP_CONNECTION_TIMEOUT_MS',
    'SMTP_GREETING_TIMEOUT_MS',
    'SMTP_SOCKET_TIMEOUT_MS',
    'SMTP_DNS_TIMEOUT_MS',
    'connectionTimeout: SMTP_CONNECTION_TIMEOUT_MS',
    'greetingTimeout: SMTP_GREETING_TIMEOUT_MS',
    'socketTimeout: SMTP_SOCKET_TIMEOUT_MS',
    'dnsTimeout: SMTP_DNS_TIMEOUT_MS',
  ]) {
    assert.match(serverSource, new RegExp(marker));
  }
});

test('SMTP sends use shared diagnostics and safe content options', () => {
  assert.match(serverSource, /async function sendEmailWithDiagnostics/);
  assert.match(serverSource, /disableFileAccess: true/);
  assert.match(serverSource, /disableUrlAccess: true/);
  assert.match(serverSource, /smtpErrorSummary\(ex && \(ex\.cause \|\| ex\)\)/);
  assert.doesNotMatch(
    serverSource,
    /await mailer\.sendMail\(\{ from: SMTP_FROM, to, subject, text, html \}\);/
  );
});
