// Sends the fixture links to a running server over HTTP.
// - If PHP is installed, this test starts php/index.php with the PHP built-in server.
// - If REDIRECTOR_URL is set (for example http://127.0.0.1:8787/), this test also checks that server.
//   The server must use the PP_PUBLIC_ID, PP_SHARED_SECRET and PP_LINK_DOMAINS values from test/fixtures.json.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { fixtures, expectedLocation, hasPhp, startPhp, send } from './helpers.js';

let php;
before(async () => {
  if (hasPhp) php = await startPhp();
});
after(() => php?.stop());

function checkServer(name, baseUrl, options) {
  for (const c of fixtures.cases) {
    test(`${name}: ${c.name}`, options, async () => {
      const response = await send(baseUrl(), c.query, c.host ?? fixtures.host);
      assert.equal(response.status, c.status, response.body);
      assert.equal(response.location, c.status === 302 ? expectedLocation(c.location) : null);
      if (c.status !== 302) assert.ok(!response.body.includes('<script>'), 'The error page must escape the url.');
    });
  }
}

checkServer('php/index.php', () => php.baseUrl, { skip: !hasPhp && 'PHP is not installed' });
checkServer('REDIRECTOR_URL', () => process.env.REDIRECTOR_URL, { skip: !process.env.REDIRECTOR_URL && 'REDIRECTOR_URL is not set' });
