<?php
////////////////////////////////////////////////////////////////
// Find these values on the company profile in PhishProtection (Settings > Company).
// Set them here, or set the PP_PUBLIC_ID, PP_SHARED_SECRET and PP_LINK_DOMAINS environment variables.
$pp_public_id     = '';
$pp_shared_secret = '';
// Optional. The link check domains that this server accepts links on, separated by commas.
// Leave it empty to accept links on all domains.
$pp_link_domains  = '';
////////////////////////////////////////////////////////////////
// The link check follows the PhishProtection app: QueryStringHelper::verifyQueryString() and
// APIService::prepareParams(). src/redirector.js has the same logic for Cloudflare Workers and Vercel.

const PP_MIN_HASH_LENGTH = 8;
// A signed field must not occur after "&h=", and it must not be an array.
const PP_CRITICAL_FIELDS = ['id', 'url', 'rcpt', 'msgid', 'tss', 'html', 'h'];
const PP_HASHING_REQUIRED_FIELDS = ['id', 'url', 'rcpt', 'msgid', 'tss'];
const PP_HASHING_FIELDS = ['id', 'url', 'rcpt', 'msgid', 'tss', 'html'];

function pp_fail($status, $message)
{
    http_response_code($status);
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store');
    die($message);
}

// Return true if the link hash is the start of the HMAC-SHA1 hex value, with 8 to 40 characters.
function pp_hash_matches($query, $secret, $h)
{
    if (!is_string($h) || strlen($h) < PP_MIN_HASH_LENGTH) {
        return false;
    }
    return hash_equals(substr(hash_hmac('sha1', $query, $secret), 0, strlen($h)), $h);
}

// Some clients encode url and rcpt two times. Decode them one time (QueryStringHelper::normaliseParams()).
function pp_normalise_params(array $params)
{
    if (isset($params['url']) && is_string($params['url']) && 1 === preg_match('{^https?%3A}i', $params['url'])) {
        $params['url'] = urldecode($params['url']);
    }
    if (isset($params['rcpt']) && is_string($params['rcpt']) && false !== strpos($params['rcpt'], '%40')) {
        $params['rcpt'] = urldecode($params['rcpt']);
    }
    return $params;
}

// Some mail clients deliver "&amp;" (or "&amp;amp;") between the parameters (APIService::decodeQueryEntities()).
function pp_decode_query_entities($query)
{
    for ($pass = 0; $pass < 5; $pass++) {
        $decoded = htmlspecialchars_decode($query, ENT_QUOTES | ENT_HTML401);
        if ($decoded === $query) {
            break;
        }
        $query = $decoded;
    }
    return $query;
}

// Return true if the link signature is correct.
function pp_verify($query, array $params, $publicId, $secret)
{
    foreach (PP_CRITICAL_FIELDS as $field) {
        if (array_key_exists($field, $params) && !is_string($params[$field])) {
            return false;
        }
    }
    $h = isset($params['h']) ? $params['h'] : null;
    if (!is_string($h) || strlen($h) < PP_MIN_HASH_LENGTH) {
        return false;
    }

    // Method 1: the hash of the query string as it is, without the h parameter.
    // The "s" flag makes "." match a newline, so a newline cannot hide an unsigned prefix (PHISH-984).
    if (1 === preg_match('/^(?<qs>.*?)&h=(?<h>[^&]+)(?<tr>(&.*|$))/s', $query, $matches)) {
        // Refuse a signed field after "&h=". PHP uses the last value, so it would not be the signed value.
        $trailing = [];
        parse_str(ltrim($matches['tr'], '&'), $trailing);
        if (array_intersect(array_map('strtolower', array_keys($trailing)), PP_CRITICAL_FIELDS)) {
            return false;
        }
        $unsigned = rtrim(implode('&', [$matches['qs'], ltrim($matches['tr'], '&')]), '&');
        if (pp_hash_matches($unsigned, $secret, $matches['h'])) {
            return true;
        }
    }

    // Method 2: rebuild the query from the parsed values, in the order of the link.
    if (!array_diff(PP_HASHING_REQUIRED_FIELDS, array_keys($params))) {
        $hashed = array_intersect_key(pp_normalise_params($params), array_flip(PP_HASHING_FIELDS));
        if (pp_hash_matches(http_build_query($hashed), $secret, $h)) {
            return true;
        }
    }

    // Method 3: the check of the first Phish Redirector version. It uses the configured Public ID,
    // so links without an id parameter also work.
    $get = function ($field) use ($params) {
        return isset($params[$field]) ? $params[$field] : null;
    };
    $legacy = [
        'url'   => $get('url'),
        'id'    => $publicId,
        'rcpt'  => $get('rcpt'),
        'tss'   => $get('tss'),
        'msgid' => $get('msgid'),
    ];
    if (isset($params['html'])) {
        $legacy['html'] = $params['html'];
    }
    $legacyQuery = http_build_query($legacy);
    if (pp_hash_matches($legacyQuery, $secret, $h)) {
        return true;
    }

    // Some links have a hash that used the email address without URL encoding.
    $rcpt = (string) $get('rcpt');
    if ('' !== urlencode($rcpt)) {
        if (pp_hash_matches(str_replace(urlencode($rcpt), $rcpt, $legacyQuery), $secret, $h)) {
            return true;
        }
    }
    return false;
}

// Remove invisible format characters that break a rewritten URL (Helper::stripInvisibleFormatChars(), PHISH-961).
function pp_strip_invisible_format_chars($url)
{
    $chars = '(?:\xC2\xAD|\xE2\x80[\x8B-\x8F\xAA-\xAE]|\xE2\x81[\xA0-\xA4\xA6-\xA9]|\xEF\xBB\xBF)';
    $url = preg_replace('/\A' . $chars . '+|' . $chars . '+\z/', '', $url);
    if (1 === preg_match('{\Ahttp://' . $chars . '+(.*)\z}s', $url, $matches)) {
        $url = 1 === preg_match('{\Ahttps?://}i', $matches[1]) ? $matches[1] : 'http://' . $matches[1];
    }
    return $url;
}

// Return the destination URL from the verified parameters (APIService::prepareParams()),
// or null if it is not a permitted URL.
function pp_destination(array $params)
{
    $params = pp_normalise_params($params);
    $url = trim(pp_strip_invisible_format_chars(isset($params['url']) ? $params['url'] : ''));
    if ('' === $url) {
        return null;
    }
    // Refuse a scheme other than http or https, for example "javascript:".
    $scheme = parse_url($url, PHP_URL_SCHEME);
    if ($scheme !== null && !in_array(strtolower((string) $scheme), ['http', 'https'], true)) {
        return null;
    }
    if (0 === preg_match('/^https?/i', $url)) {
        $url = 'http://' . $url;
    }
    if (isset($params['html']) && $params['html'] === '1') {
        $url = htmlspecialchars_decode($url, ENT_QUOTES | ENT_HTML401);
    }
    return $url;
}

// Make a host comparable (Helper::normalizeHost()): lowercase, no port, no trailing dot.
function pp_normalize_host($host)
{
    return rtrim((string) preg_replace('/:\d+$/', '', strtolower(trim($host))), '.');
}

if ($pp_public_id === '') {
    $pp_public_id = (string) getenv('PP_PUBLIC_ID');
}
if ($pp_shared_secret === '') {
    $pp_shared_secret = (string) getenv('PP_SHARED_SECRET');
}
if ($pp_link_domains === '') {
    $pp_link_domains = (string) getenv('PP_LINK_DOMAINS');
}
if ($pp_public_id === '' || $pp_shared_secret === '') {
    pp_fail(500, 'ERROR: PP_PUBLIC_ID and PP_SHARED_SECRET are not set.');
}

// A link is valid only on a link check domain (PHISH-964). An empty list permits all hosts.
$domains = array_values(array_filter(
    array_map('pp_normalize_host', preg_split('/[\s,]+/', $pp_link_domains)),
    function ($host) {
        return $host !== '';
    }
));
$host = pp_normalize_host(isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '');
if ($domains && !in_array($host, $domains, true)) {
    pp_fail(403, 'ERROR: This link is not valid on this domain.');
}

$query = pp_decode_query_entities(isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '');
$params = [];
parse_str($query, $params);
$shownUrl = isset($params['url']) && is_string($params['url']) ? htmlentities($params['url']) : '';

if (!pp_verify($query, $params, $pp_public_id, $pp_shared_secret)) {
    pp_fail(403, 'ERROR: could not verify URL!<br><br>' . $shownUrl);
}

$target = pp_destination($params);
if ($target === null) {
    pp_fail(400, 'ERROR: invalid URL!<br><br>' . $shownUrl);
}

// Percent-encode the bytes that are not permitted in an HTTP header value.
$target = preg_replace_callback('/[^\x21-\x7e]/', function ($m) {
    return sprintf('%%%02X', ord($m[0]));
}, $target);
header('Cache-Control: no-store');
header('Location: ' . $target, true, 302);
