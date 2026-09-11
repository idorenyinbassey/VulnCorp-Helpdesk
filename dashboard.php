<?php
require_once dirname(__FILE__) . '/includes/auth.php';
require_once dirname(__FILE__) . '/includes/db.php';
require_login();
include dirname(__FILE__) . '/includes/header.php';
?>
<h2>Dashboard</h2>
<p>Welcome, <strong><?php echo htmlspecialchars($_SESSION['full_name']); ?></strong> —
role: <span class="role-<?php echo htmlspecialchars($_SESSION['role']); ?>"><?php echo htmlspecialchars($_SESSION['role']); ?></span></p>

<ul>
<li><a href="<?php echo app_base(); ?>/user/profile.php?id=<?php echo (int)$_SESSION['user_id']; ?>">My Profile</a></li>
<li><a href="<?php echo app_base(); ?>/user/tickets.php">My Tickets</a></li>
<li><a href="<?php echo app_base(); ?>/user/upload.php">Upload Avatar</a></li>
<li><a href="<?php echo app_base(); ?>/user/change_password.php">Change Password</a></li>
<li><a href="<?php echo app_base(); ?>/user/claim_bonus.php">🎁 Claim Welcome Bonus</a></li>
<li><a href="<?php echo app_base(); ?>/api/tickets.php">🔌 Tickets API (JSON)</a></li>
<li><a href="<?php echo app_base(); ?>/challenges/index.php">🏁 Challenges</a></li>
<li><a href="<?php echo app_base(); ?>/toolkit/index.php">🧰 Toolkit — Checklists &amp; Kits</a></li>
<?php if ($_SESSION['role'] === 'support' || $_SESSION['role'] === 'admin'): ?>
<li><a href="<?php echo app_base(); ?>/support/tickets.php">Support Queue (all tickets)</a></li>
<?php endif; ?>
<?php if ($_SESSION['role'] === 'admin'): ?>
<li><a href="<?php echo app_base(); ?>/admin/index.php">Admin Panel</a></li>
<li><a href="<?php echo app_base(); ?>/admin/create_user.php">Create User</a></li>
<li><a href="<?php echo app_base(); ?>/admin/settings.php">Difficulty Settings</a></li>
<li><a href="<?php echo app_base(); ?>/admin/diagnostics.php">Network Diagnostics Tool</a></li>
<?php endif; ?>
</ul>
<?php include dirname(__FILE__) . '/includes/footer.php'; ?>
