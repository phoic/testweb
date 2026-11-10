const { test } = require('node:test');
const assert = require('node:assert/strict');
const express = require('express');

test('local binding stays loopback; Render binds its supplied port on all interfaces', () => {
  const { runtimeConfig } = require('../runtime');
  assert.deepEqual(runtimeConfig({}), { host: '127.0.0.1', port: 3000, requireAccess: false });
  assert.deepEqual(runtimeConfig({ RENDER: 'true', PORT: '10000' }), { host: '0.0.0.0', port: 10000, requireAccess: true });
  assert.equal(runtimeConfig({ HOST: '0.0.0.0' }).requireAccess, true);
  assert.throws(() => runtimeConfig({ PORT: 'wrong' }), /PORT/);
});
test('external access requires configured credentials for both page and API', async () => {
  const { accessGuard } = require('../runtime');
  const app = express();
  app.use('/missing', accessGuard({ requireAccess: true }, {}));
  app.use('/protected', accessGuard({ requireAccess: true }, { LAB_ACCESS_PASSWORD: 'test-only-password' }));
  app.use('/local', accessGuard({ requireAccess: false }, {}));
  app.use((req, res) => res.json({ ok: true }));
  const server = await new Promise(resolve => {
    const instance = app.listen(0, '127.0.0.1', () => resolve(instance));
  });
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    assert.equal((await fetch(base + '/missing')).status, 503);
    assert.equal((await fetch(base + '/local')).status, 200);
    for (const path of ['/protected/sqli.html', '/protected/api/sqli/compare']) {
      const denied = await fetch(base + path);
      assert.equal(denied.status, 401);
      assert.match(denied.headers.get('www-authenticate'), /Basic/);
      assert.equal((await fetch(base + path, { headers: { Authorization: 'Basic ' + Buffer.from('lab:wrong').toString('base64') } })).status, 401);
      assert.equal((await fetch(base + path, { headers: { Authorization: 'Basic ' + Buffer.from('lab:test-only-password').toString('base64') } })).status, 200);
    }
  } finally { await new Promise(resolve => server.close(resolve)); }
});
