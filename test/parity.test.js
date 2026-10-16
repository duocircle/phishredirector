// Sends random links (signed, changed, and badly encoded) to php/index.php and to the JavaScript code.
// The two versions must give the same status and the same Location header for each link.
// This test runs only if PHP is installed.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { handleRequest } from '../src/redirector.js';
import { fixtures, env, hasPhp, startPhp, send } from './helpers.js';

const COUNT = Number(process.env.PARITY_COUNT ?? 2000);

// A small seeded random number generator, so that a failure can be repeated with the same PARITY_SEED.
const seed = Number(process.env.PARITY_SEED ?? Date.now() % 100000);
let state = seed;
function random() {
  state = (state * 1103515245 + 12345) % 2147483648;
  return state / 2147483648;
}
const pick = (list) => list[Math.floor(random() * list.length)];
const chance = (p) => random() < p;

const urls = [
  'https://www.example.com/path/page?a=1&b=two#section',
  'https://example.com/café/日本?q=ü',
  "https://example.com/a b~c!d*e'f(g)h?x=%41&y=+",
  'http://example.com/?a=1&amp;b=2',
  '⁠https://example.com/joined',
  'http://⁠https://example.com/joined',
  'http://​example.com/zw',
  '﻿https://example.com/bom­',
  'www.example.com/no-scheme',
  'example.com:8080/port',
  'localhost:80',
  '  https://example.com/space  ',
  'HTTPS://EXAMPLE.COM/upper',
  'javascript:alert(1)',
  'JavaScript:alert(1)',
  'data:text/html,hi',
  'ftp://example.com/',
  'mailto:a@example.com?subject=Hi',
  'MAILTO:a@example.com',
  'tel:+15551234',
  'tel:911',
  'vbscript:msgbox(1)',
  'file:///etc/passwd',
  '1abc:foo',
  ':80',
  'http:///x',
  'x:12a',
  '//example.com/protocol-relative',
  'https%3A%2F%2Fexample.com%2Fencoded',
  'httpfoo:bar',
  '',
  '<script>alert(1)</script>',
];
const rcpts = ['user@example.org', 'first.last+tag@example.org', 'a&b@example.org', 'user%40example.org', 'ü@example.org', ''];
const msgids = ['b82d4225-4b0f-11e9-a4b6-f9238d66ad8e', '<CAF1234.abcd@mail.example.org>', ''];
const hosts = [fixtures.host, fixtures.host, 'old-links.example.com', 'LINKCHECK.example.com.:8443', 'other.example.com'];

const toBinary = (text) => Buffer.from(text, 'utf8').toString('latin1');
// PHP urlencode() and rawurlencode() of a binary string, written again here so the test does not use src/.
const urlencode = (bin) =>
  [...bin].map((c) => (/[A-Za-z0-9_.-]/.test(c) ? c : c === ' ' ? '+' : '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0'))).join('');
const rawurlencode = (bin) =>
  [...bin].map((c) => (/[A-Za-z0-9_.~-]/.test(c) ? c : '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0'))).join('');
const hmac = (query, length) => createHmac('sha1', fixtures.sharedSecret).update(Buffer.from(query, 'latin1')).digest('hex').slice(0, length);

function randomLink() {
  const values = {
    url: toBinary(pick(urls)),
    id: chance(0.9) ? fixtures.publicId : 'zz99',
    rcpt: toBinary(pick(rcpts)),
    tss: chance(0.9) ? '1718000000' : '',
    msgid: toBinary(pick(msgids)),
  };
  if (chance(0.3)) values.html = pick(['0', '1', '']);

  // The hash input of PhishProtection, or the variant of the first Phish Redirector version.
  const canonical = ['url', 'id', 'rcpt', 'tss', 'msgid', 'html']
    .filter((k) => k in values)
    .map((k) => `${k}=${urlencode(k === 'id' ? fixtures.publicId : values[k])}`)
    .join('&');

  // Build the link parameters in some order and with some encoding.
  const encode = pick([urlencode, urlencode, rawurlencode, (v) => urlencode(v).replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase())]);
  let keys = Object.keys(values);
  if (chance(0.3)) keys = keys.sort(() => random() - 0.5);
  if (chance(0.2)) keys = keys.filter((k) => k !== 'id');
  let parts = keys.map((k) => {
    let value = encode(values[k]);
    if ((k === 'url' || k === 'rcpt') && chance(0.15)) value = urlencode(urlencode(values[k]));
    return `${k}=${value}`;
  });
  if (chance(0.1)) parts.push('utm_source=news');
  let unsigned = parts.join('&');

  const length = pick([8, 8, 8, 12, 40, 7, 41]);
  let hash;
  const how = random();
  if (how < 0.4) hash = hmac(canonical, length);
  else if (how < 0.7) hash = hmac(unsigned, length);
  else if (how < 0.8) hash = hmac(canonical.split(urlencode(values.rcpt)).join(values.rcpt), length);
  else hash = Array.from({ length }, () => pick([...'0123456789abcdef'])).join('');

  let query = chance(0.1) ? `h=${hash}&${unsigned}` : `${unsigned}&h=${hash}`;
  if (chance(0.1)) query += pick(['&utm_medium=email', '&url=https%3A%2F%2Fevil.example.net%2F', '&URL=x', '&h[]=1', '&url[]=x', '&url%00=x', '&%20url=x', '&[url]=x', '&url%5B=x']);
  if (chance(0.05)) query = query.replace('url=', 'url[]=');
  const separator = pick(['&', '&', '&', '&amp;', '&amp;amp;']);
  query = query.split('&').join(separator);

  // Change one character, so that some links have a wrong signature or a broken encoding.
  if (chance(0.15)) {
    const at = Math.floor(random() * query.length);
    query = query.slice(0, at) + pick([...'aZ09%&=+;.[]-_~!*()']) + query.slice(at + 1);
  }
  return { query, host: pick(hosts) };
}

let php;
before(async () => {
  if (hasPhp) php = await startPhp();
});
after(() => php?.stop());

test(`php/index.php and the JavaScript code give the same result for ${COUNT} random links (seed ${seed})`, { skip: !hasPhp && 'PHP is not installed' }, async () => {
  const statuses = {};
  for (let i = 0; i < COUNT; i++) {
    const { query, host } = randomLink();
    const fromPhp = await send(php.baseUrl, query, host);
    const response = await handleRequest(new Request(`https://${fixtures.host}/?${query}`, { headers: { host } }), env);
    const fromJs = { status: response.status, location: response.headers.get('Location') };
    assert.deepEqual(
      { status: fromJs.status, location: fromJs.location },
      { status: fromPhp.status, location: fromPhp.location },
      `Different result for host ${JSON.stringify(host)} and query ${JSON.stringify(query)}. PHP body: ${fromPhp.body}`,
    );
    statuses[fromJs.status] = (statuses[fromJs.status] ?? 0) + 1;
  }
  // Make sure that the random links test all the results.
  for (const status of [302, 400, 403]) {
    assert.ok((statuses[status] ?? 0) > COUNT * 0.02, `Too few links with status ${status}: ${JSON.stringify(statuses)}`);
  }
});
