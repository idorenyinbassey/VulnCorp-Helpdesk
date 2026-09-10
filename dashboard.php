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
<li><a href="/user/profile.php?id=<?php echo (int)$_SESSION['user_id']; ?>">My Profile</a></li>
<li><a href="/user/tickets.php">My Tickets</a></li>
<li><a href="/user/upload.php">Upload Avatar</a></li>
<li><a href="/user/change_password.php">Change Password</a></li>
<li><a href="/challenges/index.php">🏁 Challenges</a></li>
<?php if ($_SESSION['role'] === 'support' || $_SESSION['role'] === 'admin'): ?>
<li><a href="/support/tickets.php">Support Queue (all tickets)</a></li>
<?php endif; ?>
<?php if ($_SESSION['role'] === 'admin'): ?>
<li><a href="/admin/index.php">Admin Panel</a></li>
<li><a href="/admin/create_user.php">Create User</a></li>
<li><a href="/admin/settings.php">Difficulty Settings</a></li>
<li><a href="/admin/diagnostics.php">Network Diagnostics Tool</a></li>
<?php endif; ?>
</ul>
<?php include dirname(__FILE__) . '/includes/footer.php'; ?>
