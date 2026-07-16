'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const serverSource = fs.readFileSync(
  path.join(__dirname, '..', 'server.js'),
  'utf8'
);
const envSource = fs.readFileSync(
  path.join(__dirname, '..', '.env.example'),
  'utf8'
);

test('Brevo transactional email API is the primary configured provider', () => {
  for (const marker of [
    'https://api.brevo.com/v3/smtp/email',
    'const BREVO_API_KEY',
    'const BREVO_SENDER_EMAIL',
    'const BREVO_CONFIGURED',
    'async function sendBrevoEmail',
    "'api-key': BREVO_API_KEY",
    'htmlContent: message.html',
    'signal: controller.signal',
  ]) {
    assert.ok(serverSource.includes(marker), `missing marker: ${marker}`);
  }
});

test('email routes use provider-neutral configuration and diagnostics', () => {
  assert.match(serverSource, /function isEmailConfigured\(\)/);
  assert.match(serverSource, /function emailProviderName\(\)/);
  assert.match(serverSource, /emailConfigured: isEmailConfigured\(\)/);
  assert.match(serverSource, /emailProvider: emailProviderName\(\)/);
  assert.match(serverSource, /brevoConfigured: BREVO_CONFIGURED/);
  assert.match(serverSource, /'Email send failed:'/);
  assert.doesNotMatch(serverSource, /if \(!mailer\) \{/);
  assert.doesNotMatch(serverSource, /'SMTP send failed:'/);
});

test('Brevo secrets are documented only as empty environment placeholders', () => {
  assert.match(envSource, /^BREVO_API_KEY=$/m);
  assert.match(envSource, /^BREVO_SENDER_EMAIL=$/m);
  assert.match(envSource, /^BREVO_SENDER_NAME=Studio Print$/m);
  assert.doesNotMatch(serverSource, /xkeysib-[A-Za-z0-9_-]+/);
});
