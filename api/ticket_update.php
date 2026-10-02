<?php
// api/ticket_update.php - update a ticket via the API, authenticated with
// a Bearer JWT (get one from api/auth_token.php, or forge one - see
// includes/jwt.php and the Challenges page). This is the API-specific
// mass-assignment challenge: the same underlying idea as the browser-
// form mass assignment in user/profile.php (the server writes whatever
// fields it's given instead of enforcing a fixed, role-aware allowlist),
// applied to a JSON write endpoint instead of an HTML form.
require_once dirname(__FILE__) . '/../includes/db.php';
require_once dirname(__FILE__) . '/../includes/jwt.php';

header('Content-Type: application/json');
$difficulty = get_difficulty($conn);
$secret = get_jwt_secret($conn);

function api_error($code, $message) {
    http_response_code_compat($code);
    echo json_encode(array('error' => $message));
    exit;
}
function http_response_code_compat($code) {
    $texts = array(400 => 'Bad Request', 401 => 'Unauthorized', 403 => 'Forbidden', 404 => 'Not Found');
    $text = isset($texts[$code]) ? $texts[$code] : '';
    header('HTTP/1.1 ' . $code . ' ' . $text);
}

$auth_header = isset($_SERVER['HTTP_AUTHORIZATION']) ? $_SERVER['HTTP_AUTHORIZATION'] : '';
if ($auth_header === '' || stripos($auth_header, 'Bearer ') !== 0) {
    api_error(401, 'Bearer token required');
}
$bearer_token = trim(substr($auth_header, 7));

// ---------------------------------------------------------------
// CTF-only branch: deliberately never calls jwt_verify() below - it
// decodes the token's claims with jwt_decode_unsafe() and trusts them
// outright, with NO signature check at all, independent of whatever the
// configured difficulty tier is. This is the "Forge Your Way In" CTF
// flag (see challenges/index.php) - a realistic shape for this bug
// class: one endpoint's auth was wired straight to the raw decoder
// instead of the shared jwt_verify() helper every other endpoint uses,
// the same "forgot to call the shared check" pattern as
// user/profile_export.php and the tickets API's list-mode gap.
// ---------------------------------------------------------------
if (isset($_GET['admin_note'])) {
    $decoded = jwt_decode_unsafe($bearer_token);
    if ($decoded === null || !isset($decoded['payload']['role']) || $decoded['payload']['role'] !== 'admin') {
        api_error(403, 'Admin role required');
    }
    echo json_encode(array(
        'note' => 'Admin note endpoint reached with a completely unverified token.',
        'flag' => 'FLAG{alg_none_bypasses_the_admin_note}',
    ));
    exit;
}

$claims = jwt_verify($bearer_token, $secret, $difficulty);
if ($claims === null || !isset($claims['sub'])) {
    api_error(401, 'Invalid or expired token');
}
$auth_user_id = (int)$claims['sub'];
$auth_role = isset($claims['role']) ? $claims['role'] : 'user';

$ticket_id = isset($_POST['ticket_id']) ? (int)$_POST['ticket_id'] : 0;
if ($ticket_id < 1) {
    api_error(400, 'ticket_id required');
}

$res = mysqli_query($conn, "SELECT id, user_id FROM tickets WHERE id = " . $ticket_id);
$ticket = $res ? mysqli_fetch_assoc($res) : null;
if (!$ticket) {
    api_error(404, 'Ticket not found');
}

$is_owner = ((int)$ticket['user_id'] === $auth_user_id);
$is_staff = in_array($auth_role, array('support', 'admin'), true);
$full_columns = array('subject', 'message', 'status', 'user_id', 'priority');
$fields = array();

if ($difficulty === 'simple') {
    // No ownership check AND no field allowlist at all - every column in
    // $full_columns present in $_POST is written through for ANY
    // authenticated caller, including user_id (steal the ticket) and
    // priority (an admin-only field).
    foreach ($full_columns as $col) {
        if (array_key_exists($col, $_POST)) { $fields[$col] = $_POST[$col]; }
    }

} elseif ($difficulty === 'intermediate') {
    if (!$is_owner && !$is_staff) {
        api_error(403, 'Not your ticket');
    }
    // Ownership IS checked above - against the ticket's CURRENT
    // user_id - but user_id is still a writable field below, so
    // supplying a new one silently reassigns the ticket right after
    // this check passes: verify-then-trust-a-field-that-changes-what-
    // was-verified, the same shape as the change_password.php bug at
    // this same tier.
    foreach ($full_columns as $col) {
        if (array_key_exists($col, $_POST)) { $fields[$col] = $_POST[$col]; }
    }

} elseif ($difficulty === 'hard') {
    if (!$is_owner && !$is_staff) {
        api_error(403, 'Not your ticket');
    }
    // user_id is finally removed from what's writable - but the
    // admin-only 'priority' field was forgotten and stays open to any
    // authenticated caller, owner or not.
    $writable = array('subject', 'message', 'status', 'priority');
    foreach ($writable as $col) {
        if (array_key_exists($col, $_POST)) { $fields[$col] = $_POST[$col]; }
    }

} else { // expert
    if (!$is_owner && !$is_staff) {
        api_error(403, 'Not your ticket');
    }
    // user_id and priority are both correctly restricted - but this
    // privilege check only ever inspects $_POST, while the write loop
    // just below reads $_REQUEST instead. Supplying 'priority' (or
    // 'user_id') on the QUERY STRING rather than the POST body never
    // touches $_POST at all, so it sails straight past this check.
    if (isset($_POST['user_id'])) {
        api_error(403, 'user_id is not editable via this endpoint');
    }
    if (isset($_POST['priority']) && !$is_staff) {
        api_error(403, 'Only staff may set priority');
    }
    foreach ($full_columns as $col) {
        if (array_key_exists($col, $_REQUEST)) { $fields[$col] = $_REQUEST[$col]; }
    }
}

if (empty($fields)) {
    api_error(400, 'No updatable fields supplied');
}

$sets = array();
$types = '';
$values = array();
foreach ($fields as $col => $val) {
    $sets[] = $col . ' = ?';
    if ($col === 'user_id') {
        $types .= 'i';
        $values[] = (int)$val;
    } else {
        $types .= 's';
        $values[] = $val;
    }
}
$types .= 'i';
$values[] = $ticket_id;

$stmt = mysqli_prepare($conn, "UPDATE tickets SET " . implode(', ', $sets) . " WHERE id = ?");
$bind_args = array($stmt, $types);
foreach ($values as $k => $v) {
    $bind_args[] = &$values[$k];
}
call_user_func_array('mysqli_stmt_bind_param', $bind_args);
mysqli_stmt_execute($stmt);

echo json_encode(array('ok' => true, 'ticket_id' => $ticket_id, 'updated_fields' => array_keys($fields)));
