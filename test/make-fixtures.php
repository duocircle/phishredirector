<?php
// Writes test/fixtures.json: signed test links and the result that each link must give.
// The links are signed the same way as the PhishProtection app signs them.
// Run: php test/make-fixtures.php

$publicId    = 'a1c3';
$secret      = 'test-shared-secret-0123456789abcdef';
$linkDomains = 'linkcheck.example.com, old-links.example.com.';
$host        = 'linkcheck.example.com';

function hmac(string $query, string $secret, int $length = 8): string
{
    return substr(hash_hmac('sha1', $query, $secret), 0, $length);
}

// The hash input of PhishProtection: url, id, rcpt, tss, msgid, and html if it is set.
function hashInput(array $params, string $publicId): string
{
    $hashed = ['url' => $params['url'], 'id' => $publicId, 'rcpt' => $params['rcpt'], 'tss' => $params['tss'], 'msgid' => $params['msgid']];
    if (isset($params['html'])) {
        $hashed['html'] = $params['html'];
    }
    return http_build_query($hashed);
}

// A link as the PhishProtection rewrite makes it: the hash input, then "&h=".
function signedLink(array $params, string $publicId, string $secret, int $length = 8): string
{
    $query = hashInput($params, $publicId);
    return $query . '&h=' . hmac($query, $secret, $length);
}

$base = [
    'url'   => 'https://www.example.com/path/page?a=1&b=two#section',
    'rcpt'  => 'user@example.org',
    'tss'   => '1718000000',
    'msgid' => 'b82d4225-4b0f-11e9-a4b6-f9238d66ad8e',
];
$h        = hmac(hashInput($base, $publicId), $secret);
$baseLink = signedLink($base, $publicId, $secret);

$cases = [];
$ok = function (string $name, string $query, string $location, array $extra = []) use (&$cases) {
    $cases[] = ['name' => $name, 'query' => $query, 'status' => 302, 'location' => $location] + $extra;
};
$fail = function (string $name, string $query, int $status = 403, array $extra = []) use (&$cases) {
    $cases[] = ['name' => $name, 'query' => $query, 'status' => $status] + $extra;
};

// Links that the PhishProtection rewrite makes.
foreach ([
    'basic link'                  => $base,
    'html parameter'              => $base + ['html' => '0'],
    'plus sign in recipient'      => ['rcpt' => 'first.last+tag@example.org'] + $base,
    'ampersand in recipient'      => ['rcpt' => 'a&b@example.org'] + $base,
    'non-ASCII characters in url' => ['url' => 'https://example.com/café/日本?q=ü'] + $base,
    'special characters in url'   => ['url' => "https://example.com/a b~c!d*e'f(g)h?x=%41&y=+"] + $base,
    'empty msgid'                 => ['msgid' => ''] + $base,
] as $name => $params) {
    $ok($name, signedLink($params, $publicId, $secret), $params['url']);
}

// The hash can be 8 to 40 characters.
foreach ([12, 40] as $length) {
    $ok("$length character hash", signedLink($base, $publicId, $secret, $length), $base['url']);
}

// The first Phish Redirector version also accepted these links.
$params = ['rcpt' => 'first.last+tag@example.org'] + $base;
$legacy = str_replace(urlencode($params['rcpt']), $params['rcpt'], hashInput($params, $publicId));
$ok('hash with unencoded recipient', http_build_query($params) . '&h=' . hmac($legacy, $secret), $params['url']);
$ok('40 character hash with unencoded recipient', http_build_query($params) . '&h=' . hmac($legacy, $secret, 40), $params['url']);
$ok('link without id', http_build_query($base) . '&h=' . $h, $base['url']);
$ok('hash first, without id', http_build_query(['h' => $h] + $base), $base['url']);

// Method 1: the hash of the raw query string.
$raw = 'id=' . $publicId . '&url=' . rawurlencode($base['url']) . '&tss=' . $base['tss'] . '&msgid=' . $base['msgid'] . '&rcpt=' . rawurlencode($base['rcpt']);
$ok('raw query in a different order', $raw . '&h=' . hmac($raw, $secret), $base['url']);
$raw = preg_replace_callback('/%[0-9A-F]{2}/', function ($m) { return strtolower($m[0]); }, $raw);
$ok('raw query with lowercase hex', $raw . '&h=' . hmac($raw, $secret), $base['url']);
$withUtm = hashInput($base, $publicId) . '&utm_source=news';
$ok('tracking parameter signed after the hash', hashInput($base, $publicId) . '&h=' . hmac($withUtm, $secret) . '&utm_source=news', $base['url']);

// Method 2: rebuild in the order of the link, with the id from the link. Other parameters are ignored.
$ordered = ['id' => $publicId, 'msgid' => $base['msgid'], 'url' => $base['url'], 'tss' => $base['tss'], 'rcpt' => $base['rcpt']];
$ok('parsed values in a different order', http_build_query($ordered) . '&h=' . hmac(http_build_query($ordered), $secret), $base['url']);
$ok('tracking parameter after the hash', $baseLink . '&utm_source=news', $base['url']);

// Mail clients that encode the separators as HTML entities (APIService::decodeQueryEntities()).
$ok('&amp; separators', str_replace('&', '&amp;', $baseLink), $base['url']);
$ok('&amp;amp; separators', str_replace('&', '&amp;amp;', $baseLink), $base['url']);

// Clients that encode url and rcpt two times (QueryStringHelper::normaliseParams()).
$double = 'url=' . urlencode(urlencode($base['url'])) . '&id=' . $publicId . '&rcpt=' . urlencode(urlencode($base['rcpt'])) . '&tss=' . $base['tss'] . '&msgid=' . $base['msgid'];
$ok('url and rcpt encoded two times', $double . '&h=' . $h, $base['url']);

// The destination URL (APIService::prepareParams()).
$params = ['url' => "\u{2060}https://example.com/joined"] + $base;
$ok('invisible character before the url', signedLink($params, $publicId, $secret), 'https://example.com/joined');
$params = ['url' => "http://\u{2060}https://example.com/joined"] + $base;
$ok('invisible character after an added http://', signedLink($params, $publicId, $secret), 'https://example.com/joined');
$params = ['url' => 'www.example.com/no-scheme'] + $base;
$ok('url without a scheme', signedLink($params, $publicId, $secret), 'http://www.example.com/no-scheme');
$params = ['url' => 'example.com:8080/port'] + $base;
$ok('url with a port and without a scheme', signedLink($params, $publicId, $secret), 'http://example.com:8080/port');
$params = ['url' => '  https://example.com/space  '] + $base;
$ok('spaces around the url', signedLink($params, $publicId, $secret), 'https://example.com/space');
$params = ['url' => 'https://example.com/?a=1&amp;b=2', 'html' => '1'] + $base;
$ok('html=1 decodes entities in the url', signedLink($params, $publicId, $secret), 'https://example.com/?a=1&b=2');
$params = ['url' => 'https://example.com/?a=1&amp;b=2', 'html' => '0'] + $base;
$ok('html=0 keeps entities in the url', signedLink($params, $publicId, $secret), 'https://example.com/?a=1&amp;b=2');

foreach (['javascript:alert(1)', 'data:text/html,hi', 'ftp://example.com/', 'mailto:a@example.com'] as $url) {
    $fail("signed $url is refused", signedLink(['url' => $url] + $base, $publicId, $secret), 400);
}
$fail('signed empty url is refused', signedLink(['url' => ''] + $base, $publicId, $secret), 400);

// Links that must not redirect.
$fail('changed url', http_build_query(['url' => 'https://evil.example.net/'] + $base) . '&h=' . $h);
$fail('wrong hash', hashInput($base, $publicId) . '&h=00000000');
$fail('missing hash', hashInput($base, $publicId));
$fail('7 character hash', hashInput($base, $publicId) . '&h=' . substr($h, 0, 7));
$fail('41 character hash', signedLink($base, $publicId, $secret, 40) . '0');
$fail('long hash with a wrong end', hashInput($base, $publicId) . '&h=' . $h . '0000');
$fail('uppercase hash', hashInput($base, $publicId) . '&h=' . strtoupper($h));
$fail('html parameter added', hashInput($base, $publicId) . '&html=1&h=' . $h);
$fail('url added after the hash', $baseLink . '&url=' . urlencode('https://evil.example.net/'));
$fail('URL added after the hash', $baseLink . '&URL=' . urlencode('https://evil.example.net/'));
$fail('array url after the hash', $baseLink . '&url[]=' . urlencode('https://evil.example.net/'));
$fail('hash as an array', hashInput($base, $publicId) . '&h[]=' . $h);
$fail('url as an array', str_replace('url=', 'url[]=', $baseLink));
$fail('html in url is escaped', http_build_query(['url' => '<script>alert(1)</script>'] + $base) . '&h=' . $h);

// Link check domains (PHISH-964).
$ok('second link check domain', $baseLink, $base['url'], ['host' => 'old-links.example.com']);
$ok('host with uppercase, a trailing dot, and a port', $baseLink, $base['url'], ['host' => 'LinkCheck.Example.com.:443']);
$fail('other host', $baseLink, 403, ['host' => 'other.example.com']);
$fail('subdomain of a link check domain', $baseLink, 403, ['host' => 'a.linkcheck.example.com']);

$fixtures = ['publicId' => $publicId, 'sharedSecret' => $secret, 'linkDomains' => $linkDomains, 'host' => $host, 'cases' => $cases];
file_put_contents(__DIR__ . '/fixtures.json', json_encode($fixtures, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
echo count($cases) . " cases written to test/fixtures.json\n";
