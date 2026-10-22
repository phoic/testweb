const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const path = require('node:path');
const express = require('express');

const directory = mkdtempSync(path.join(tmpdir(), 'sqli-test-'));
process.env.LAB_DB_PATH = path.join(directory, 'lab.db');
const { db } = require('../db');
const router = require('../routes/sqli');
let server;
let base;
before(async () => {
  const app = express();
  app.use(express.json());
  app.use('/api/sqli', router);
  server = await new Promise(resolve => {
    const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
  });
  base = `http://127.0.0.1:${server.address().port}/api/sqli`;
});
after(async () => {
  await new Promise(resolve => server.close(resolve));
  db.close();
  rmSync(directory, { recursive: true, force: true });
});
async function compare(username, password) {
  const response = await fetch(`${base}/compare`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  assert.equal(response.status, 200, 'comparison endpoint should execute both paths');
  return response.json();
}
function checkEvidence(run) {
  assert.ok(run.executionId);
  assert.ok(Number.isFinite(Date.parse(run.executedAt)));
  for (const mode of ['vulnerable', 'safe']) {
    const result = run[mode];
    assert.equal(result.executionId, run.executionId);
    assert.deepEqual(result.input, run.input);
    assert.equal(result.matchedRows, result.accounts.length);
    assert.equal(result.success, !result.dbError && result.accounts.length > 0);
    assert.ok(result.accounts.every(account => Object.keys(account).sort().join(',') === 'id,username'));
    assert.deepEqual(result.log.map(item => item.event), [
      'request_received', 'sql_ready', result.dbError ? 'db_error' : 'db_completed',
      'rows_counted', 'auth_decided'
    ]);
    assert.ok(result.log.every(item => item.executionId === run.executionId && item.mode === mode && Number.isFinite(Date.parse(item.at))));
  }
  assert.deepEqual(run.safe.boundParams, [run.input.username, run.input.password]);
  assert.equal(run.safe.query, 'SELECT id, username FROM users WHERE username = ? AND password = ?');
}
test('normal credentials succeed in both paths without a bypass label', async () => {
  const run = await compare('alice', 'password123');
  checkEvidence(run);
  assert.equal(run.vulnerable.status, '인증 성공');
  assert.equal(run.safe.status, '인증 성공');
  assert.equal(run.vulnerable.matchedRows, 1);
  assert.equal(run.safe.matchedRows, 1);
  assert.equal(run.analysis.exactMatch, true);
  assert.equal(run.analysis.bypassObserved, false);
});
test('incorrect password fails in both paths without DB error or bypass', async () => {
  const run = await compare('alice', 'incorrect');
  checkEvidence(run);
  for (const mode of ['vulnerable', 'safe']) {
    assert.equal(run[mode].status, '인증 실패');
    assert.equal(run[mode].matchedRows, 0);
    assert.equal(run[mode].dbError, null);
  }
  assert.equal(run.analysis.bypassObserved, false);
});
test('real OR/comment SQL returns all fake accounts only through concatenation', async () => {
  const username = "' OR '1'='1' -- ";
  const run = await compare(username, 'anything');
  checkEvidence(run);
  assert.equal(run.vulnerable.query, `SELECT id, username FROM users WHERE username = '${username}' AND password = 'anything'`);
  assert.equal(run.vulnerable.status, '인증 성공');
  assert.equal(run.vulnerable.matchedRows, 3);
  assert.deepEqual(run.vulnerable.accounts.map(account => account.username).sort(), ['alice', 'bob', 'carol']);
  assert.equal(run.safe.status, '인증 실패');
  assert.equal(run.safe.matchedRows, 0);
  assert.equal(run.analysis.exactMatch, false);
  assert.equal(run.analysis.bypassObserved, true);
});
test('a lone quote is a DB error only in the concatenated path', async () => {
  const run = await compare("'", 'anything');
  checkEvidence(run);
  assert.equal(run.vulnerable.status, 'DB 오류');
  assert.ok(run.vulnerable.dbError);
  assert.equal(run.safe.status, '인증 실패');
  assert.equal(run.safe.dbError, null);
  assert.equal(run.analysis.bypassObserved, false);
});
test('keywords alone are not evidence of authentication bypass', async () => {
  const run = await compare('OR --', 'incorrect');
  assert.equal(run.vulnerable.success, false);
  assert.equal(run.analysis.bypassObserved, false);
});
test('safe-path DB errors and analysis errors remain visible', async () => {
  db.exec('ALTER TABLE users RENAME TO unavailable_users');
  try {
    const run = await compare('alice', 'password123');
    checkEvidence(run);
    assert.equal(run.safe.status, 'DB 오류');
    assert.match(run.safe.dbError, /no such table/);
    assert.equal(run.analysis.exactMatch, null);
    assert.equal(run.analysis.bypassObserved, null);
    assert.match(run.analysis.dbError, /no such table/);
  } finally { db.exec('ALTER TABLE unavailable_users RENAME TO users'); }
});
test('comparison records have unique server identifiers', async () => {
  const a = await compare('alice', 'password123');
  const b = await compare('bob', 'test1234');
  assert.notEqual(a.executionId, b.executionId);
  assert.deepEqual(a.input, { username: 'alice', password: 'password123' });
});
test('invalid input is rejected before either database path runs', async () => {
  const response = await fetch(`${base}/compare`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: [], password: 1 })
  });
  assert.equal(response.status, 400);
});
test('existing login endpoints call the same actual authentication paths', async () => {
  const input = { username: "' OR '1'='1' -- ", password: 'anything' };
  for (const mode of ['vulnerable', 'safe']) {
    const response = await fetch(`${base}/${mode}-login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input)
    });
    assert.equal(response.status, 200);
    const result = await response.json();
    assert.deepEqual(result.input, input);
    assert.equal(result.matchedRows, mode === 'vulnerable' ? 3 : 0);
    assert.equal(result.success, mode === 'vulnerable');
    assert.equal(result.accounts.length, result.matchedRows);
  }
});
test('SQL-looking text in valid credentials is never itself classified as bypass', async () => {
  db.prepare('INSERT INTO users (username, password) VALUES (?, ?)').run('OR --', 'known');
  try {
    const run = await compare('OR --', 'known');
    assert.equal(run.vulnerable.success, true);
    assert.equal(run.safe.success, true);
    assert.equal(run.analysis.exactMatch, true);
    assert.equal(run.analysis.bypassObserved, false);
  } finally { db.prepare('DELETE FROM users WHERE username = ?').run('OR --'); }
});
