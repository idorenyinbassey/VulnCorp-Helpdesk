<?php
require_once dirname(__FILE__) . '/../includes/auth.php';
require_once dirname(__FILE__) . '/../includes/db.php';
require_role('admin');

$difficulty = get_difficulty($conn);
$res = mysqli_query($conn, "SELECT id, username, role, full_name, email FROM users ORDER BY id");
include dirname(__FILE__) . '/../includes/header.php';
?>
<h2>Admin Panel — Users</h2>
<table>
<tr><th>ID</th><th>Username</th><th>Role</th><th>Full name</th><th>Email</th><th>View profile</th></tr>
<?php while ($row = mysqli_fetch_assoc($res)): ?>
<tr>
    <td><?php echo (int)$row['id']; ?></td>
    <td><?php echo htmlspecialchars($row['username']); ?></td>
    <td class="role-<?php echo htmlspecialchars($row['role']); ?>"><?php echo htmlspecialchars($row['role']); ?></td>
    <td><?php echo htmlspecialchars($row['full_name']); ?></td>
    <td><?php echo htmlspecialchars($row['email']); ?></td>
    <td><a href="<?php echo app_base(); ?>/user/profile.php?id=<?php echo (int)$row['id']; ?>">view</a></td>
</tr>
<?php endwhile; ?>
</table>

<h3>Modules</h3>
<ul>
    <li><a href="<?php echo app_base(); ?>/admin/create_user.php">Create User</a> — CSRF surface below expert tier</li>
    <li><a href="<?php echo app_base(); ?>/admin/diagnostics.php">Network Diagnostics (ping tool)</a> — command injection surface</li>
    <li><a href="<?php echo app_base(); ?>/admin/settings.php">Difficulty tier</a> — currently <strong><?php echo htmlspecialchars($difficulty); ?></strong></li>
</ul>
<?php include dirname(__FILE__) . '/../includes/footer.php'; ?>
