<?php
// api/tickets.php - a small JSON API, deliberately separate from the
// browser-facing user/tickets.php page. Real APIs often get less
// scrutiny than the UI that calls them, since "nobody" browses to them
// directly - but every request here is just as reachable with curl/Burp
// as any HTML page. This demonstrates Broken Object Level Authorization
// (BOLA) - the API-specific name for the same IDOR pattern elsewhere in
// this app, applied to a JSON endpoint instead of an HTML page.
require_once dirname(__FILE__) . '/../includes/db.php';
require_once dirname(__FILE__) . '/../includes/jwt.php';
if (session_id() === '') { session_start(); }

header('Content-Type: application/json');
$difficulty = get_difficulty($conn);

function api_error($code, $message) {
    http_response_code_compat($code);
    echo json_encode(array('error' => $message));
    exit;
}
// http_response_code() itself needs PHP 5.4+; compat.php already polyfills
// it as part of includes/auth.php's 403 handling, but api.php doesn't load
// auth.php, so a tiny local wrapper keeps this file standalone.
function http_response_code_compat($code) {
    $texts = array(401 => 'Unauthorized', 403 => 'Forbidden', 404 => 'Not Found');
    $text = isset($texts[$code]) ? $texts[$code] : '';
    header('HTTP/1.1 ' . $code . ' ' . $text);
}

// ---------------------------------------------------------------
// Auth context: a browser session cookie OR a Bearer JWT (see
// api/auth_token.php / includes/jwt.php) - a real API often supports
// both a logged-in UI and a token-based integration client, and this
// app now does too. Whichever one authenticates (if either) sets
// $auth_user_id/$auth_role, which everything below uses in place of
// reading $_SESSION directly. The JWT path's own bugs (alg confusion,
// missing expiry, no revocation) live entirely in jwt_verify() -
// nothing here changes because of them.
//
// 2FA Bypass module (intermediate tier): index.php sets $_SESSION['user_id']
// for a totp-enabled account as soon as the password check succeeds,
// before the 2FA code is verified - require_login() (includes/auth.php)
// knows to also check $_SESSION['totp_verified'] before letting such a
// session through, but this file was built to check $_SESSION directly
// and never calls require_login() at all, so a session mid-2FA-verification
// authenticates here exactly as if it were fully logged in.
// ---------------------------------------------------------------
$auth_user_id = isset($_SESSION['user_id']) ? (int)$_SESSION['user_id'] : null;
$auth_role = isset($_SESSION['role']) ? $_SESSION['role'] : null;

// hard/expert: this endpoint now applies the same partial-auth check
// require_login() does, closing the gap above for the session-cookie
// path specifically - a Bearer token (below) is a wholly separate auth
// mechanism with no 2FA state of its own, so it's untouched by this.
if (($difficulty === 'hard' || $difficulty === 'expert')
    && isset($_SESSION['totp_verified']) && $_SESSION['totp_verified'] === false) {
    $auth_user_id = null;
    $auth_role = null;
}

$auth_header = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : '';
if ($auth_header !== '' && stripos($auth_header, 'Bearer ') === 0) {
    $bearer_token = trim(substr($auth_header, 7));
    $claims = jwt_verify($bearer_token, get_jwt_secret($conn), $difficulty);
    if ($claims !== null && isset($claims['sub'])) {
        $auth_user_id = (int)$claims['sub'];
        $auth_role = isset($claims['role']) ? $claims['role'] : null;
    }
}

if ($difficulty === 'simple') {
    // No authentication check at all. Anyone who can reach this URL -
    // logged in or not - can pull any ticket by ID.
    // (falls through to the query below)

} elseif ($difficulty === 'intermediate') {
    // Requires *a* valid session or token - but any valid one works for
    // any ticket, since there's still no ownership check.
    if ($auth_user_id === null) {
        api_error(401, 'Login required');
    }

} elseif ($difficulty === 'hard') {
    if ($auth_user_id === null) {
        api_error(401, 'Login required');
    }
    // Ownership IS checked below for a single ticket by id - but the
    // "list mode" (no id given) was added later and never got the same
    // check applied to it.

} else { // expert
    if ($auth_user_id === null) {
        api_error(401, 'Login required');
    }
    // Both single-ticket and list mode are properly scoped below.
}

$id = isset($_GET['id']) ? (int)$_GET['id'] : null;

if ($id !== null) {
    // ---- single ticket by id ----
    $res = mysqli_query($conn, "SELECT id, user_id, subject, message, status, created_at FROM tickets WHERE id = " . $id);
    $ticket = $res ? mysqli_fetch_assoc($res) : null;

    if (!$ticket) {
        api_error(404, 'Ticket not found');
    }

    if ($difficulty === 'hard' || $difficulty === 'expert') {
        $is_owner = ($auth_user_id !== null && (int)$ticket['user_id'] === $auth_user_id);
        $is_staff = ($auth_role !== null && in_array($auth_role, array('support', 'admin'), true));
        if (!$is_owner && !$is_staff) {
            api_error(403, 'Not your ticket');
        }
    }
    // simple/intermediate: no ownership check at all - BOLA.

    echo json_encode($ticket);

} else {
    // ---- list mode ----
    if ($difficulty === 'expert') {
        // Properly scoped to the caller's own tickets only.
        $stmt = mysqli_prepare($conn, "SELECT id, user_id, subject, status, created_at FROM tickets WHERE user_id = ?");
        mysqli_stmt_bind_param($stmt, 'i', $auth_user_id);
        mysqli_stmt_execute($stmt);
        $rows = stmt_fetch_all($stmt);
    } else {
        // simple/intermediate/hard: list mode was bolted on without an
        // ownership filter at all - returns EVERY ticket regardless of
        // who's asking, even at hard tier where the single-ticket lookup
        // above is correctly scoped.
        $res = mysqli_query($conn, "SELECT id, user_id, subject, status, created_at FROM tickets");
        $rows = array();
        if ($res) {
            while ($row = mysqli_fetch_assoc($res)) { $rows[] = $row; }
        }
    }
    echo json_encode($rows);
}
