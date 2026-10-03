<?php
// user/link_preview.php - SSRF module.
//
// AJAX endpoint behind the ticket composer's "paste a link" feature
// (user/tickets.php): fetches a user-supplied URL server-side and
// returns a short preview, the same real pattern Slack/Jira/etc. use
// for link unfurling. The server doing the fetching - not the user's
// own browser - is exactly what makes this a server-side request
// forgery surface: whatever the server can reach, this endpoint can be
// made to reach, regardless of what the submitting user's browser could
// reach directly.
require_once dirname(__FILE__) . '/../includes/auth.php';
require_once dirname(__FILE__) . '/../includes/db.php';
require_login();

header('Content-Type: application/json');
$difficulty = get_difficulty($conn);

function preview_error($message) {
    echo json_encode(array('error' => $message));
    exit;
}

$url = isset($_POST['url']) ? trim($_POST['url']) : '';
if ($url === '') {
    preview_error('url required');
}

// Hand-rolled private/reserved-range check - deliberately NOT using
// PHP's filter_var(..., FILTER_FLAG_NO_RES_RANGE), which actually does
// cover link-local (169.254.0.0/16) out of the box. A developer who
// writes their own blocklist instead of reaching for that flag - a very
// common real pattern - is exactly how the expert-tier gap below
// happens for real, not a contrived omission.
function ssrf_is_blocked_host($ip) {
    $long = ip2long($ip);
    if ($long === false) {
        return true; // not a plain IPv4 literal - be conservative
    }
    $ranges = array(
        array('10.0.0.0', '10.255.255.255'),
        array('172.16.0.0', '172.31.255.255'),
        array('192.168.0.0', '192.168.255.255'),
        array('127.0.0.0', '127.255.255.255'),
        array('0.0.0.0', '0.255.255.255'),
        // NOTE: 169.254.0.0/16 (link-local - includes the cloud
        // metadata address 169.254.169.254) is deliberately NOT in this
        // list - see README / the Challenges page for this module.
    );
    foreach ($ranges as $r) {
        if ($long >= ip2long($r[0]) && $long <= ip2long($r[1])) {
            return true;
        }
    }
    return false;
}

function ssrf_fetch($url, $allow_redirects_unchecked) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, $allow_redirects_unchecked);
    if ($allow_redirects_unchecked) {
        curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
    }
    $body = curl_exec($ch);
    $info = curl_getinfo($ch);
    curl_close($ch);
    return array('body' => $body, 'info' => $info);
}

// Re-validates a host against ssrf_is_blocked_host(), resolving it first -
// used both for the initial URL (every tier from intermediate on) and,
// at expert tier only, for every redirect hop too.
function ssrf_host_allowed($url) {
    $host = parse_url($url, PHP_URL_HOST);
    if (!$host) {
        return false;
    }
    $ip = filter_var($host, FILTER_VALIDATE_IP) ? $host : gethostbyname($host);
    return !ssrf_is_blocked_host($ip);
}

if ($difficulty === 'simple') {
    // No validation at all, and no protocol restriction either - curl's
    // default protocol set includes file://, so local file disclosure is
    // reachable through this same endpoint, not just internal HTTP.
    $result = ssrf_fetch($url, true);
    echo json_encode(array('preview' => substr($result['body'], 0, 500), 'http_code' => $result['info']['http_code']));

} elseif ($difficulty === 'intermediate') {
    // file:// and friends are closed - only http(s) now. But the host
    // check is a plain substring blacklist, so "127.1" or "0177.0.0.1"
    // (both legitimate ways to write 127.0.0.1 that a browser and curl
    // both still resolve correctly) sail straight through, since neither
    // string literally contains "localhost" or "127.0.0.1".
    $blacklist = array('localhost', '127.0.0.1');
    foreach ($blacklist as $b) {
        if (stripos($url, $b) !== false) {
            preview_error('That host is not allowed.');
        }
    }
    if (!preg_match('#^https?://#i', $url)) {
        preview_error('Only http/https URLs are allowed.');
    }
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
    curl_setopt($ch, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    $body = curl_exec($ch);
    $info = curl_getinfo($ch);
    curl_close($ch);
    echo json_encode(array('preview' => substr($body, 0, 500), 'http_code' => $info['http_code']));

} elseif ($difficulty === 'hard') {
    // The *initial* host is now properly resolved and checked against a
    // real private/reserved-range list, not a substring guess - "127.1"
    // and friends are correctly caught here. But CURLOPT_FOLLOWLOCATION
    // is still on, and nothing re-validates where a 3xx redirect actually
    // points - an attacker-controlled external URL that 302s to an
    // internal address still reaches it, since only the URL the user
    // submitted was ever checked.
    if (!preg_match('#^https?://#i', $url)) {
        preview_error('Only http/https URLs are allowed.');
    }
    if (!ssrf_host_allowed($url)) {
        preview_error('That host is not allowed.');
    }
    $result = ssrf_fetch($url, true);
    echo json_encode(array('preview' => substr($result['body'], 0, 500), 'http_code' => $result['info']['http_code'], 'final_url' => $result['info']['url']));

} else { // expert
    // Redirects are now followed manually, one hop at a time, re-checking
    // the host at every step - the hard-tier bypass is closed. What's
    // left is the blocklist itself: it was hand-rolled instead of using
    // a comprehensive reserved-range check, and link-local
    // (169.254.0.0/16, which includes the cloud metadata address
    // 169.254.169.254) was never added to it.
    if (!preg_match('#^https?://#i', $url)) {
        preview_error('Only http/https URLs are allowed.');
    }
    $current = $url;
    $body = '';
    $http_code = 0;
    for ($hop = 0; $hop < 5; $hop++) {
        if (!ssrf_host_allowed($current)) {
            preview_error('That host is not allowed.');
        }
        $result = ssrf_fetch($current, false);
        $http_code = $result['info']['http_code'];
        if ($http_code >= 300 && $http_code < 400 && !empty($result['info']['redirect_url'])) {
            $current = $result['info']['redirect_url'];
            continue;
        }
        $body = $result['body'];
        break;
    }
    echo json_encode(array('preview' => substr($body, 0, 500), 'http_code' => $http_code, 'final_url' => $current));
}
