<?php
////////////////////////////////////////////////////////////////
// these values are found on the company profile in PhishProtection
$pp_public_id     = '';
$pp_shared_secret = '';
////////////////////////////////////////////////////////////////
$query = http_build_query([
        'url'   => $_GET['url'],
        'id'    => $pp_public_id,
        'rcpt'  => $_GET['rcpt'],
        'tss'   => $_GET['tss'],
        'msgid' => $_GET['msgid'],
]);
$hash = substr(hash_hmac('sha1', $query, $pp_shared_secret),0,8);
if ( $hash !== $_GET['h'] ) {
    // try again, accounting for incorrect encoding of email address
    $rcpt = urlencode($_GET['rcpt']);
    $query = str_replace($rcpt, $_GET['rcpt'], $query);
    $hash = substr(hash_hmac('sha1', $query, $pp_shared_secret),0,8);
    if ( $hash !== $_GET['h'] ) {
        die('ERROR: could not verify URL!<br><br>' . htmlentities($_GET['url']));
    }
}
header("Location: " . $_GET['url']);