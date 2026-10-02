<?php
require_once dirname(__FILE__) . '/../includes/auth.php';
require_once dirname(__FILE__) . '/../includes/db.php';
require_login();

// This "export" endpoint was added later and the developer forgot to apply
// the same ownership check that profile.php has in hard/expert mode.
// -> Broken Access Control / IDOR, present at ALL difficulty tiers via this file.
$id = isset($_GET['id']) ? (int)$_GET['id'] : (int)$_SESSION['user_id'];

// api_key was added here for the "The Forgotten Export" CTF chain - this
// export endpoint already had no ownership check at any difficulty tier
// (see the comment above), so including the API Token (JWT) Auth
// module's credential in its output turns that pre-existing IDOR into a
// full account-takeover chain: leak another user's api_key here, then
// exchange it at /api/auth_token.php for a JWT that authenticates as them.
$res = mysqli_query($conn, "SELECT id, username, role, full_name, email, api_key, created_at FROM users WHERE id = " . $id);
$profile = $res ? mysqli_fetch_assoc($res) : null;

header('Content-Type: application/json');
if (!$profile) {
    echo json_encode(array('error' => 'not found'));
} else {
    echo json_encode($profile);
}
