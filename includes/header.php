<?php if (!isset($conn)) { require_once dirname(__FILE__) . '/db.php'; } ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnCorp Helpdesk</title>
<link rel="stylesheet" href="<?php echo app_base(); ?>/assets/style.css">
</head>
<body>
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
