<?php
if (!isset($conn)) { require_once dirname(__FILE__) . '/db.php'; }

// ---------------------------------------------------------------
// Clickjacking module. Every page that includes this shared header
// gets the protection below - which is exactly why the one page that
// DOESN'T include header.php (user/verify_2fa.php, a lightweight
// single-purpose page built without the normal chrome - see its own
// comment) never gets it either, at any tier. Same "endpoint forgot
// the shared protection" shape as profile_export.php and the tickets
// API's list-mode gap elsewhere in this app.
// ---------------------------------------------------------------
$_header_difficulty = get_difficulty($conn);
if ($_header_difficulty === 'hard' || $_header_difficulty === 'expert') {
    header('X-Frame-Options: SAMEORIGIN');
}
// simple/intermediate: no header at all - every page framable by anyone.
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnCorp Helpdesk</title>
<link rel="stylesheet" href="<?php echo app_base(); ?>/assets/style.css">
</head>
<body data-difficulty="<?php echo htmlspecialchars($_header_difficulty); ?>">
<div class="topbar">
    <div class="brand">VulnCorp Helpdesk <span class="tag">[TRAINING LAB]</span></div>
    <div class="mode-badge">Mode: <strong><?php echo htmlspecialchars(get_difficulty($conn)); ?></strong></div>
    <?php if (isset($_SESSION['user_id'])): ?>
    <div class="nav">
        <span>Hi, <?php echo htmlspecialchars($_SESSION['full_name']); ?> (<?php echo htmlspecialchars($_SESSION['role']); ?>)</span>
        <a href="<?php echo app_base(); ?>/dashboard.php">Dashboard</a>
        <a href="<?php echo app_base(); ?>/logout.php">Logout</a>
    </div>
    <?php endif; ?>
</div>
<div class="container">
