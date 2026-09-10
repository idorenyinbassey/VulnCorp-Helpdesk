<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/db.php';
require_login();

// This "export" endpoint was added later and the developer forgot to apply
// the same ownership check that profile.php has in hard/expert mode.
// -> Broken Access Control / IDOR, present at ALL difficulty tiers via this file.
$id = isset($_GET['id']) ? (int)$_GET['id'] : (int)$_SESSION['user_id'];

$res = mysqli_query($conn, "SELECT id, username, role, full_name, email, created_at FROM users WHERE id = " . $id);
$profile = $res ? mysqli_fetch_assoc($res) : null;

header('Content-Type: application/json');
if (!$profile) {
    echo json_encode(array('error' => 'not found'));
} else {
    echo json_encode($profile);
}
