const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');

const source = readFileSync('server.js', 'utf8');

test('usage is stored per account, tool, and day', () => {
  assert.match(source, /CREATE TABLE IF NOT EXISTS tool_usage_daily/);
  assert.match(source, /PRIMARY KEY\(user_id, tool_id, day_key\)/);
  assert.match(source, /app\.get\('\/api\/tool-usage\/:toolId', authRequired/);
  assert.match(source, /app\.post\('\/api\/tool-usage\/:toolId\/consume', authRequired/);
});

test('free accounts receive one final output per tool per day', () => {
  assert.match(source, /FREE_DAILY_TOOL_USES\s+\|\|\s+'1'/);
  assert.match(source, /new Set\(\['forms', 'id-print', 'passport-photo'\]\)/);
});

test('consumption is transaction backed and fails closed at the limit', () => {
  assert.match(source, /const consumeToolUsage = db\.transaction/);
  assert.match(source, /if \(snap\.used >= snap\.limit\) return \{ blocked: true/);
  assert.match(source, /DO UPDATE SET count = count \+ 1/);
  assert.match(source, /res\.status\(429\)/);
});
