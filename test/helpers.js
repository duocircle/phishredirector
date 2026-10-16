import { readFileSync } from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import http from 'node:http';

export const fixtures = JSON.parse(readFileSync(new URL('./fixtures.json', import.meta.url), 'utf8'));

export const env = {
  PP_PUBLIC_ID: fixtures.publicId,
  PP_SHARED_SECRET: fixtures.sharedSecret,
  PP_LINK_DOMAINS: fixtures.linkDomains,
};

// The Location header value of a correct redirect. Bytes that are not printable ASCII are percent-encoded.
export function expectedLocation(url) {
  return String.fromCharCode(...new TextEncoder().encode(url)).replace(
    /[^\x21-\x7e]/g,
    (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0'),
  );
}

export const hasPhp = spawnSync('php', ['--version']).status === 0;

// Start php/index.php with the PHP built-in server and the fixture configuration.
export async function startPhp(extraEnv = {}) {
  const port = 18000 + Math.floor(Math.random() * 1000);
  const child = spawn('php', ['-S', `127.0.0.1:${port}`, 'index.php'], {
    cwd: fileURLToPath(new URL('../php/', import.meta.url)),
    env: { ...process.env, ...env, ...extraEnv },
    stdio: 'ignore',
  });
  const baseUrl = `http://127.0.0.1:${port}/`;
  for (let i = 0; i < 50; i++) {
    try {
      await send(baseUrl, '', fixtures.host);
      return { baseUrl, stop: () => child.kill() };
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  child.kill();
  throw new Error('The PHP built-in server did not start.');
}

// Send a GET request with a raw query string and a Host header. Returns the status and the Location header.
export function send(baseUrl, query, host) {
  const target = new URL(baseUrl);
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: target.hostname,
        port: target.port,
        path: target.pathname + (query === '' ? '' : '?' + query),
        headers: { Host: host },
        agent: false,
      },
      (response) => {
        let body = '';
        response.setEncoding('latin1');
        response.on('data', (chunk) => (body += chunk));
        response.on('end', () => resolve({ status: response.statusCode, location: response.headers.location ?? null, body }));
      },
    );
    request.on('error', reject);
    request.end();
  });
}
