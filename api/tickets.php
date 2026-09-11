<?php
// api/tickets.php - a small JSON API, deliberately separate from the
// browser-facing user/tickets.php page. Real APIs often get less
// scrutiny than the UI that calls them, since "nobody" browses to them
// directly - but every request here is just as reachable with curl/Burp
// as any HTML page. This demonstrates Broken Object Level Authorization
// (BOLA) - the API-specific name for the same IDOR pattern elsewhere in
// this app, applied to a JSON endpoint instead of an HTML page.
require_once dirname(__FILE__) . '/../includes/db.php';
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

if ($difficulty === 'simple') {
    // No authentication check at all. Anyone who can reach this URL -
    // logged in or not - can pull any ticket by ID.
    // (falls through to the query below)

} elseif ($difficulty === 'intermediate') {
    // Requires *a* valid session - but any logged-in user's session
    // works for any ticket, since there's still no ownership check.
    if (!isset($_SESSION['user_id'])) {
        api_error(401, 'Login required');
    }

} elseif ($difficulty === 'hard') {
    if (!isset($_SESSION['user_id'])) {
        api_error(401, 'Login required');
    }
    // Ownership IS checked below for a single ticket by id - but the
    // "list mode" (no id given) was added later and never got the same
    // check applied to it.

} else { // expert
    if (!isset($_SESSION['user_id'])) {
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
        $is_owner = (isset($_SESSION['user_id']) && (int)$ticket['user_id'] === (int)$_SESSION['user_id']);
        $is_staff = (isset($_SESSION['role']) && in_array($_SESSION['role'], array('support', 'admin'), true));
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
        mysqli_stmt_bind_param($stmt, 'i', $_SESSION['user_id']);
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
