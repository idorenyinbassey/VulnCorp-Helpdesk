<?php
require_once dirname(__FILE__) . '/../includes/db.php';
if (session_id() === '') { session_start(); }

$difficulty = get_difficulty($conn);
$msg = '';
$err = '';
$token = isset($_GET['token']) ? $_GET['token'] : (isset($_POST['token']) ? $_POST['token'] : '');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $new_password = $_POST['new_password'];
    $confirm = $_POST['confirm_password'];

    if ($new_password !== $confirm) {
        $err = 'Passwords do not match.';
    } else {
        $safe_token = mysqli_real_escape_string($conn, $token);
        $res = mysqli_query($conn, "SELECT * FROM users WHERE reset_token = '$safe_token'");
        $user = $res ? mysqli_fetch_assoc($res) : null;

        if (!$user) {
            $err = 'Invalid or already-used reset token.';
        } elseif (strtotime($user['reset_expires']) < time()) {
            $err = 'This reset link has expired. Request a new one.';
        } else {
            $hash = md5($new_password);
            $stmt = mysqli_prepare($conn, "UPDATE users SET password = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?");
            mysqli_stmt_bind_param($stmt, 'si', $hash, $user['id']);
            mysqli_stmt_execute($stmt);
            log_activity($conn, $user['username'], 'password reset via token');
            $msg = 'Password has been reset. You can log in now.';
        }
    }
}

include dirname(__FILE__) . '/../includes/header.php';
?>
<h2>Reset Password</h2>
<?php if ($msg): ?><div class="notice"><?php echo htmlspecialchars($msg); ?> <a href="<?php echo app_base(); ?>/index.php">Log in</a></div>
<?php else: ?>
<?php if ($err): ?><div class="error"><?php echo htmlspecialchars($err); ?></div><?php endif; ?>
<form method="POST" style="max-width:360px;">
    <input type="hidden" name="token" value="<?php echo htmlspecialchars($token); ?>">
    <label>New password</label>
    <input type="password" name="new_password" required>
    <label>Confirm new password</label>
    <input type="password" name="confirm_password" required>
    <button type="submit">Reset Password</button>
</form>
<?php endif; ?>
<p class="small">Mode: <?php echo htmlspecialchars($difficulty); ?>. <a href="<?php echo app_base(); ?>/user/forgot_password.php">Request a new link</a></p>
<?php include dirname(__FILE__) . '/../includes/footer.php'; ?>
