<?php
// api/auth_token.php - exchanges a user's api_key for a signed JWT,
// modeling a "generate an API token for your helpdesk integration"
// feature. Like api/tickets.php, this is a JSON API that gets less
// scrutiny than the UI - but it's just as reachable with curl/Burp.
//
// Issuance always signs a correct HS256 token (see includes/jwt.php) -
// the bugs this endpoint demonstrates are in how hard it is to brute-
// force a wrong api_key, not in how the resulting token is built.
require_once dirname(__FILE__) . '/../includes/db.php';
require_once dirname(__FILE__) . '/../includes/jwt.php';

header('Content-Type: application/json');
$difficulty = get_difficulty($conn);
$secret = get_jwt_secret($conn);

function token_error($code, $message) {
    http_response_code_compat($code);
    echo json_encode(array('error' => $message));
    exit;
}
// http_response_code() needs PHP 5.4+; this file is standalone (doesn't
// load includes/auth.php), so it gets its own tiny local wrapper, same
// as api/tickets.php and api/ticket_update.php.
function http_response_code_compat($code) {
    $texts = array(400 => 'Bad Request', 401 => 'Unauthorized', 429 => 'Too Many Requests');
    $text = isset($texts[$code]) ? $texts[$code] : '';
    header('HTTP/1.1 ' . $code . ' ' . $text);
}

$username = isset($_POST['username']) ? $_POST['username'] : '';
$api_key = isset($_POST['api_key']) ? $_POST['api_key'] : '';

if ($username === '' || $api_key === '') {
    token_error(400, 'username and api_key are both required');
}

// ---------------------------------------------------------------
// Rate limiting on failed exchange attempts - see README / Challenges
// for the "API Token Request - Rate Limiting" module.
// ---------------------------------------------------------------
if ($difficulty !== 'simple') {
    // intermediate/hard/expert all get this same (still bypassable)
    // lockout - this module's own two challenge tiers are simple/hard,
    // the other two difficulties just inherit the hard-tier behavior.
    //
    // Two separate weaknesses, each enough on its own to defeat this:
    //  1. Keyed by the EXACT, case-sensitive username - varying the case
    //     of a known username (e.g. "Alice" vs "alice") is treated as a
    //     different account with its own fresh attempt counter.
    //  2. The "client IP" trusts the attacker-supplied X-Forwarded-For
    //     header outright - sending a different value on every request
    //     resets the IP half of the lockout key too.
    $client_ip = isset($_SERVER['HTTP_X_FORWARDED_FOR'])
        ? trim(explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0])
        : (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown');

    // BINARY forces a byte-exact comparison - deliberately, so that
    // varying the case of a known username (see weakness #1 above)
    // really does land on a separate, fresh counter instead of MySQL's
    // default case-insensitive collation accidentally closing that gap.
    $stmt = mysqli_prepare($conn, "SELECT COUNT(*) AS n FROM activity_log WHERE action = 'api_token_fail' AND BINARY username = ? AND ip = ? AND logged_at > (NOW() - INTERVAL 5 MINUTE)");
    mysqli_stmt_bind_param($stmt, 'ss', $username, $client_ip);
    mysqli_stmt_execute($stmt);
    $row = stmt_fetch_one($stmt);
    if ($row && (int)$row['n'] >= 5) {
        token_error(429, 'Too many attempts for this account - try again later');
    }
}
// simple tier: no rate limiting of any kind - the api_key itself is the
// only thing standing between a caller and a valid token, with no limit
// on how many guesses they get.

$stmt = mysqli_prepare($conn, "SELECT id, username, role, api_key FROM users WHERE username = ?");
mysqli_stmt_bind_param($stmt, 's', $username);
mysqli_stmt_execute($stmt);
$user = stmt_fetch_one($stmt);

if (!$user || $user['api_key'] === null || !hash_equals($user['api_key'], $api_key)) {
    log_activity($conn, $username, 'api_token_fail');
    token_error(401, 'Invalid username or api_key');
}

$payload = array(
    'sub' => (int)$user['id'],
    'username' => $user['username'],
    'role' => $user['role'],
    'iat' => time(),
    'exp' => time() + 900, // 15 minutes - only actually enforced at expert tier, see includes/jwt.php
);
$token = jwt_encode($payload, $secret);
log_activity($conn, $username, 'api_token_issued');

echo json_encode(array('token' => $token, 'expires_in' => 900));
