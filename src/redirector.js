// Shared redirect logic for the Cloudflare Workers and Vercel versions.
// This code gives the same result as php/index.php, byte for byte. It follows the link check of
// the PhishProtection app (QueryStringHelper::verifyQueryString() and APIService::prepareParams()).
// All strings that hold bytes are "binary strings": one character for each byte (0-255).

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const keyCache = new Map();

const MIN_HASH_LENGTH = 8;
// A signed field must not occur after "&h=", and it must not be an array.
const CRITICAL_FIELDS = ['id', 'url', 'rcpt', 'msgid', 'tss', 'html', 'h'];
const HASHING_REQUIRED_FIELDS = ['id', 'url', 'rcpt', 'msgid', 'tss'];
const HASHING_FIELDS = [...HASHING_REQUIRED_FIELDS, 'html'];
// An array value from parse_str(), for example from "url[]=x".
const ARRAY = Symbol('array');
// The destination URL schemes that Phish Redirector sends the browser to. A URL without a scheme gets "http://".
const PERMITTED_SCHEMES = ['http', 'https', 'mailto', 'ftp', 'tel'];

// Decode the same entities as PHP htmlspecialchars_decode() with ENT_QUOTES | ENT_HTML401.
export function htmlSpecialCharsDecode(bin) {
  const named = { amp: '&', quot: '"', lt: '<', gt: '>' };
  const numeric = { 34: '"', 38: '&', 39: "'", 60: '<', 62: '>' };
  return bin.replace(/&(?:(amp|quot|lt|gt)|#(?:([0-9]+)|[xX]([0-9A-Fa-f]+)));/g, (match, name, dec, hex) => {
    if (name) return named[name];
    const code = dec !== undefined ? parseInt(dec, 10) : parseInt(hex, 16);
    return numeric[code] ?? match;
  });
}

// Some mail clients deliver "&amp;" (or "&amp;amp;") between the parameters. Decode until the
// result stops changing, the same as APIService::decodeQueryEntities().
export function decodeQueryEntities(bin) {
  for (let pass = 0; pass < 5; pass++) {
    const decoded = htmlSpecialCharsDecode(bin);
    if (decoded === bin) break;
    bin = decoded;
  }
  return bin;
}

// Decode %XX sequences and "+" the same as PHP urldecode(). Returns a binary string.
export function phpUrlDecode(raw) {
  return raw.replace(/\+/g, ' ').replace(/%([0-9A-Fa-f]{2})/g, (m, hex) => String.fromCharCode(parseInt(hex, 16)));
}

// Encode a binary string the same as PHP urlencode().
// PHP keeps only A-Z, a-z, 0-9, "-", "_" and "." as they are, and changes a space to "+".
export function phpUrlEncode(bin) {
  return bin.replace(/[^A-Za-z0-9_.-]/g, (c) =>
    c === ' ' ? '+' : '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0'),
  );
}

// Return the variable name that PHP parse_str() makes from a decoded key, and if the value is an array.
function phpVariableName(key) {
  key = key.replace(/^ +/, '');
  const open = key.indexOf('[');
  if (open > 0 && key.indexOf(']', open) !== -1) {
    return { name: key.slice(0, open).replace(/[. ]/g, '_'), isArray: true };
  }
  if (open > 0) {
    return { name: key.slice(0, open).replace(/[. ]/g, '_') + '_' + key.slice(open + 1), isArray: false };
  }
  return { name: key.replace(/[. ]/g, '_'), isArray: false };
}

// Parse a query string into a Map of binary strings, the same as PHP parse_str() and $_GET.
// The Map keeps the position of the first occurrence of a key and the value of the last occurrence.
export function parseQuery(rawQuery) {
  const params = new Map();
  for (const part of rawQuery.split('&')) {
    if (part === '') continue;
    const eq = part.indexOf('=');
    const { name, isArray } = phpVariableName(phpUrlDecode(eq === -1 ? part : part.slice(0, eq)));
    if (name === '') continue;
    params.set(name, isArray ? ARRAY : eq === -1 ? '' : phpUrlDecode(part.slice(eq + 1)));
  }
  return params;
}

// Build the query string the same as PHP http_build_query(). PHP skips keys with a null value.
function buildQuery(pairs) {
  return pairs
    .filter(([, value]) => value !== undefined)
    .map(([key, value]) => phpUrlEncode(key) + '=' + phpUrlEncode(value))
    .join('&');
}

function binaryToBytes(bin) {
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function utf8ToBinary(text) {
  return String.fromCharCode(...encoder.encode(text));
}

function binaryToUtf8(bin) {
  return decoder.decode(binaryToBytes(bin));
}

async function hmacKey(secret) {
  let key = keyCache.get(secret);
  if (!key) {
    key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-1' },
      false,
      ['sign'],
    );
    keyCache.set(secret, key);
  }
  return key;
}

// Return HMAC-SHA1(query, secret) as 40 lowercase hex characters.
async function hmacHex(query, secret) {
  const signature = await crypto.subtle.sign('HMAC', await hmacKey(secret), binaryToBytes(query));
  return Array.from(new Uint8Array(signature), (b) => b.toString(16).padStart(2, '0')).join('');
}

// Return true if the link hash is the start of the HMAC, with a length of 8 to 40 characters.
async function hashMatches(query, secret, linkHash) {
  if (typeof linkHash !== 'string' || linkHash.length < MIN_HASH_LENGTH) return false;
  const expected = (await hmacHex(query, secret)).slice(0, linkHash.length);
  if (expected.length !== linkHash.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ linkHash.charCodeAt(i);
  return diff === 0;
}

// Some clients encode url and rcpt two times. Decode them one time, the same as
// QueryStringHelper::normaliseParams().
function normaliseParams(params) {
  const result = new Map(params);
  const url = result.get('url');
  if (typeof url === 'string' && /^https?%3A/i.test(url)) result.set('url', phpUrlDecode(url));
  const rcpt = result.get('rcpt');
  if (typeof rcpt === 'string' && rcpt.includes('%40')) result.set('rcpt', phpUrlDecode(rcpt));
  return result;
}

// Return true if the link signature is correct. "query" is the query string after decodeQueryEntities().
export async function verify(query, params, publicId, sharedSecret) {
  for (const field of CRITICAL_FIELDS) {
    if (params.get(field) === ARRAY) return false;
  }
  const linkHash = params.get('h');
  if (typeof linkHash !== 'string' || linkHash.length < MIN_HASH_LENGTH) return false;

  // Method 1: the hash of the query string as it is, without the h parameter.
  // The "s" flag makes "." match a newline, so a newline cannot hide an unsigned prefix (PHISH-984).
  const match = /^(.*?)&h=([^&]+)(&.*|$)/s.exec(query);
  if (match) {
    const [, signed, rawHash, trailing] = match;
    // Refuse a signed field after "&h=". PHP uses the last value, so it would not be the signed value.
    for (const name of parseQuery(trailing).keys()) {
      if (CRITICAL_FIELDS.includes(name.toLowerCase())) return false;
    }
    const unsigned = [signed, trailing.replace(/^&+/, '')].join('&').replace(/&+$/, '');
    if (await hashMatches(unsigned, sharedSecret, rawHash)) return true;
  }

  // Method 2: rebuild the query from the parsed values, in the order of the link.
  if (HASHING_REQUIRED_FIELDS.every((field) => params.has(field))) {
    const pairs = [...normaliseParams(params)].filter(([name]) => HASHING_FIELDS.includes(name));
    if (await hashMatches(buildQuery(pairs), sharedSecret, linkHash)) return true;
  }

  // Method 3: the check of the first Phish Redirector version. It uses the configured Public ID,
  // so links without an id parameter also work.
  const pairs = [
    ['url', params.get('url')],
    ['id', utf8ToBinary(publicId)],
    ['rcpt', params.get('rcpt')],
    ['tss', params.get('tss')],
    ['msgid', params.get('msgid')],
  ];
  if (params.has('html')) pairs.push(['html', params.get('html')]);
  let legacy = buildQuery(pairs);
  if (await hashMatches(legacy, sharedSecret, linkHash)) return true;

  // Some links have a hash that used the email address without URL encoding.
  const rcpt = params.get('rcpt') ?? '';
  const encodedRcpt = phpUrlEncode(rcpt);
  if (encodedRcpt !== '') {
    legacy = legacy.split(encodedRcpt).join(rcpt);
    if (await hashMatches(legacy, sharedSecret, linkHash)) return true;
  }
  return false;
}

// Remove invisible format characters that break a rewritten URL, the same as
// Helper::stripInvisibleFormatChars() (PHISH-961). The pattern matches UTF-8 bytes.
export function stripInvisibleFormatChars(bin) {
  const chars = '(?:\\xC2\\xAD|\\xE2\\x80[\\x8B-\\x8F\\xAA-\\xAE]|\\xE2\\x81[\\xA0-\\xA4\\xA6-\\xA9]|\\xEF\\xBB\\xBF)';
  bin = bin.replace(new RegExp(`^${chars}+|${chars}+$`, 'g'), '');
  const match = new RegExp(`^http://${chars}+(.*)$`, 's').exec(bin);
  if (match) bin = /^https?:\/\//i.test(match[1]) ? match[1] : 'http://' + match[1];
  return bin;
}

// Return the lowercase URL scheme, or null if there is none. php/index.php uses the same rule.
// "host:port" (for example "example.com:8080/path") has no scheme, but a permitted scheme is always a scheme.
export function urlScheme(bin) {
  const match = /^([A-Za-z][A-Za-z0-9+.-]*):(.*)$/s.exec(bin);
  if (!match) return null;
  const scheme = match[1].toLowerCase();
  if (!PERMITTED_SCHEMES.includes(scheme) && /^[0-9]{1,5}(?:[/?#]|$)/.test(match[2])) return null;
  return scheme;
}

// Return the destination URL (a binary string) from the verified parameters, the same as
// APIService::prepareParams(), or null if it is not a permitted URL.
export function destination(params) {
  const normalised = normaliseParams(params);
  let url = stripInvisibleFormatChars(normalised.get('url') ?? '');
  url = url.replace(/^[ \t\n\r\0\x0B]+|[ \t\n\r\0\x0B]+$/g, '');
  if (url === '') return null;
  // Refuse a scheme that is not permitted, for example "javascript:". Add "http://" if there is no scheme.
  const scheme = urlScheme(url);
  if (scheme === null) url = 'http://' + url;
  else if (!PERMITTED_SCHEMES.includes(scheme)) return null;
  if (normalised.get('html') === '1') url = htmlSpecialCharsDecode(url);
  return url;
}

// Make a host comparable, the same as Helper::normalizeHost(): lowercase, no port, no trailing dot.
export function normalizeHost(host) {
  return host.trim().toLowerCase().replace(/:\d+$/, '').replace(/\.+$/, '');
}

// Return the link check domains from PP_LINK_DOMAINS. An empty list permits all hosts.
export function linkDomains(value) {
  return (value ?? '').split(/[\s,]+/).map(normalizeHost).filter((host) => host !== '');
}

function escapeHtml(text) {
  return text.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
}

// Percent-encode the bytes that are not permitted in an HTTP header value.
function toHeaderValue(bin) {
  return bin.replace(/[^\x21-\x7e]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase().padStart(2, '0'));
}

function htmlResponse(status, body) {
  return new Response(body, {
    status,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}

// Return the raw query string of a request URL, without "?" and without the fragment.
function rawQuery(requestUrl) {
  const start = requestUrl.indexOf('?');
  if (start === -1) return '';
  const end = requestUrl.indexOf('#', start);
  return requestUrl.slice(start + 1, end === -1 ? undefined : end);
}

// Handle one request. "env" holds PP_PUBLIC_ID, PP_SHARED_SECRET and PP_LINK_DOMAINS.
export async function handleRequest(request, env) {
  const url = new URL(request.url);

  if (url.pathname === '/robots.txt') {
    return new Response('User-agent: *\nDisallow: /\n', { headers: { 'Content-Type': 'text/plain' } });
  }

  const publicId = env?.PP_PUBLIC_ID ?? '';
  const sharedSecret = env?.PP_SHARED_SECRET ?? '';
  if (publicId === '' || sharedSecret === '') {
    return htmlResponse(500, 'ERROR: PP_PUBLIC_ID and PP_SHARED_SECRET are not set.');
  }

  // A link is valid only on a link check domain (PHISH-964).
  const domains = linkDomains(env?.PP_LINK_DOMAINS);
  const host = normalizeHost(request.headers.get('host') ?? url.host);
  if (domains.length > 0 && !domains.includes(host)) {
    return htmlResponse(403, 'ERROR: This link is not valid on this domain.');
  }

  const query = decodeQueryEntities(rawQuery(request.url));
  const params = parseQuery(query);
  const shownUrl = () => {
    const value = params.get('url');
    return escapeHtml(typeof value === 'string' ? binaryToUtf8(value) : '');
  };

  if (!(await verify(query, params, publicId, sharedSecret))) {
    return htmlResponse(403, 'ERROR: could not verify URL!<br><br>' + shownUrl());
  }

  const target = destination(params);
  if (target === null) {
    return htmlResponse(400, 'ERROR: invalid URL!<br><br>' + shownUrl());
  }

  return new Response(null, {
    status: 302,
    headers: { Location: toHeaderValue(target), 'Cache-Control': 'no-store' },
  });
}
