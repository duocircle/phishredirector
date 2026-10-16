import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handleRequest, decodeQueryEntities, parseQuery, urlScheme, stripInvisibleFormatChars } from '../src/redirector.js';
import worker from '../src/worker.js';
import vercel from '../api/index.js';
import { fixtures, env, expectedLocation } from './helpers.js';

function request(query, host = fixtures.host) {
  return new Request(`https://${fixtures.host}/?${query}`, { headers: { host } });
}

for (const c of fixtures.cases) {
  test(c.name, async () => {
    const response = await handleRequest(request(c.query, c.host), env);
    assert.equal(response.status, c.status);
    assert.equal(response.headers.get('Location'), c.status === 302 ? expectedLocation(c.location) : null);
  });
}

test('the error page escapes the url', async () => {
  const c = fixtures.cases.find((x) => x.name === 'html in url is escaped');
  const response = await handleRequest(request(c.query), env);
  assert.equal(await response.text(), 'ERROR: could not verify URL!<br><br>&#60;script&#62;alert(1)&#60;/script&#62;');
});

test('any path works', async () => {
  const response = await handleRequest(
    new Request(`https://${fixtures.host}/some/path?${fixtures.cases[0].query}`),
    env,
  );
  assert.equal(response.status, 302);
});

test('an empty PP_LINK_DOMAINS permits all hosts', async () => {
  for (const domains of [undefined, '', ' , ']) {
    const response = await handleRequest(request(fixtures.cases[0].query, 'any.example.net'), { ...env, PP_LINK_DOMAINS: domains });
    assert.equal(response.status, 302);
  }
});

test('missing configuration gives an error', async () => {
  for (const bad of [{}, { PP_PUBLIC_ID: fixtures.publicId }, { PP_SHARED_SECRET: fixtures.sharedSecret }, undefined]) {
    const response = await handleRequest(request(fixtures.cases[0].query), bad);
    assert.equal(response.status, 500);
    assert.equal(response.headers.get('Location'), null);
  }
});

test('robots.txt blocks all crawlers', async () => {
  const response = await handleRequest(new Request(`https://${fixtures.host}/robots.txt`), env);
  assert.equal(response.status, 200);
  assert.equal(await response.text(), 'User-agent: *\nDisallow: /\n');
});

test('decodeQueryEntities stops after 5 passes', () => {
  assert.equal(decodeQueryEntities('a&' + 'amp;'.repeat(7) + 'b'), 'a&' + 'amp;'.repeat(2) + 'b');
  assert.equal(decodeQueryEntities('a&amp;amp;amp;b'), 'a&b');
});

test('parseQuery follows PHP parse_str', () => {
  const params = parseQuery('a=1&b.c=2&d+e=3&f[]=4&g[=5&a=6&h');
  assert.deepEqual([...params.keys()], ['a', 'b_c', 'd_e', 'f', 'g_', 'h']);
  assert.equal(params.get('a'), '6');
  assert.equal(params.get('h'), '');
  assert.equal(typeof params.get('f'), 'symbol');
});

test('urlScheme follows PHP parse_url', () => {
  assert.equal(urlScheme('javascript:alert(1)'), 'javascript');
  assert.equal(urlScheme('example.com:8080/x'), null);
  assert.equal(urlScheme('localhost:80'), null);
  assert.equal(urlScheme('x:12a'), 'x');
  assert.equal(urlScheme('//example.com/a'), null);
});

test('stripInvisibleFormatChars removes U+2060 and the added http://', () => {
  const wj = '\xE2\x81\xA0';
  assert.equal(stripInvisibleFormatChars(`http://${wj}https://example.com/`), 'https://example.com/');
  assert.equal(stripInvisibleFormatChars(`http://${wj}example.com/`), 'http://example.com/');
  assert.equal(stripInvisibleFormatChars(`${wj}https://example.com/${wj}`), 'https://example.com/');
});

test('Cloudflare entry point uses the env bindings', async () => {
  const response = await worker.fetch(request(fixtures.cases[0].query), env);
  assert.equal(response.status, 302);
  assert.equal(response.headers.get('Location'), expectedLocation(fixtures.cases[0].location));
});

test('Vercel entry point uses process.env', async () => {
  Object.assign(process.env, env);
  try {
    const response = await vercel.fetch(request(fixtures.cases[0].query));
    assert.equal(response.status, 302);
    assert.equal(response.headers.get('Location'), expectedLocation(fixtures.cases[0].location));
  } finally {
    for (const key of Object.keys(env)) delete process.env[key];
  }
});
