<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/db.php';
require_role('admin');

$difficulty = get_difficulty($conn);
$msg = '';
$err = '';

if (session_status() !== PHP_SESSION_NONE && !isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $ok = true;
    if ($difficulty === 'expert') {
        $ok = isset($_POST['csrf_token']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
        if (!$ok) { $err = 'CSRF token invalid — request rejected.'; }
    }
    // simple / intermediate / hard: no CSRF token check at all. A logged-in
    // admin who visits an attacker-controlled page can have a brand new
    // admin account silently created in their name -- a backdoor.

    if ($ok) {
        $username = $_POST['username'];
        $password = $_POST['password'];
        $full_name = $_POST['full_name'];
        $email = $_POST['email'];
        $role = in_array($_POST['role'], array('admin', 'support', 'user'), true) ? $_POST['role'] : 'user';

        if ($difficulty === 'simple') {
            // Raw concatenation on the insert - secondary SQLi surface,
            // reachable by anyone who can trigger this form (see CSRF note
            // above - this doesn't require the attacker to know admin
            // credentials, only that an admin will visit their page).
            $hash = md5($password);
            $sql = "INSERT INTO users (username, password, role, full_name, email) "
                 . "VALUES ('$username', '$hash', '$role', '$full_name', '$email')";
            if (mysqli_query($conn, $sql)) {
                $msg = "User '$username' created with role '$role'.";
            } else {
                $err = 'SQL error: ' . mysqli_error($conn);
            }
        } else {
            $hash = md5($password);
            $stmt = mysqli_prepare($conn, "INSERT INTO users (username, password, role, full_name, email) VALUES (?, ?, ?, ?, ?)");
            mysqli_stmt_bind_param($stmt, 'sssss', $username, $hash, $role, $full_name, $email);
            if (mysqli_stmt_execute($stmt)) {
                $msg = "User '$username' created with role '$role'.";
            } else {
                $err = 'Could not create user (username may already exist).';
            }
        }
        if ($msg) { log_activity($conn, $_SESSION['username'], "created user '$username' as role '$role'"); }
    }
}

include __DIR__ . '/../includes/header.php';
?>
<h2>Create User</h2>
<?php if ($msg): ?><div class="notice"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>
<?php if ($err): ?><div class="error"><?php echo htmlspecialchars($err); ?></div><?php endif; ?>
<form method="POST" style="max-width:400px;">
    <label>Username</label>
    <input type="text" name="username" required>
    <label>Temporary password</label>
    <input type="text" name="password" required>
    <label>Full name</label>
    <input type="text" name="full_name">
    <label>Email</label>
    <input type="text" name="email" id="cu-email">
    <div id="cu-email-hint" class="small" style="color:#d97706;margin-top:-10px;margin-bottom:10px;"></div>
    <label>Role</label>
    <select name="role">
        <option value="user">user</option>
        <option value="support">support</option>
        <option value="admin">admin</option>
    </select>
    <?php if ($difficulty === 'expert'): ?>
    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
    <?php endif; ?>
    <button type="submit">Create</button>
</form>
<p class="small">Mode: <?php echo htmlspecialchars($difficulty); ?>. Below expert tier this form has no CSRF
protection — see the Challenges page for the "backdoor admin account" exercise.</p>
<p><a href="/admin/index.php">&larr; Back to user list</a></p>
<?php include __DIR__ . '/../includes/footer.php'; ?>
