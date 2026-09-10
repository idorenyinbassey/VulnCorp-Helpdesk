<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/db.php';
require_login();

$difficulty = get_difficulty($conn);
$msg = '';
$err = '';

if (session_status() !== PHP_SESSION_NONE && !isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
}

// Which account this form is acting on. Defaults to yourself.
$target_id = isset($_GET['id']) ? (int)$_GET['id'] : (int)$_SESSION['user_id'];

$res = mysqli_query($conn, "SELECT * FROM users WHERE id = " . (int)$target_id);
$target = $res ? mysqli_fetch_assoc($res) : null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $current_password = isset($_POST['current_password']) ? $_POST['current_password'] : '';
    $new_password = $_POST['new_password'];
    $confirm = $_POST['confirm_password'];

    if ($new_password !== $confirm) {
        $err = 'New password and confirmation do not match.';

    } elseif ($difficulty === 'simple') {
        // No CSRF token, no current-password check, no ownership check at
        // all -> anyone logged in can take over any account by ID.
        // Raw string concatenation, matching this tier's flavor elsewhere.
        $hash = md5($new_password);
        $sql = "UPDATE users SET password = '$hash' WHERE id = " . (int)$target_id;
        if (mysqli_query($conn, $sql)) {
            $msg = "Password updated for user #$target_id.";
        } else {
            $err = 'SQL error: ' . mysqli_error($conn);
        }

    } elseif ($difficulty === 'intermediate') {
        // No CSRF token. Current-password IS checked -- but only against
        // the LOGGED-IN user's own hash, while the UPDATE still targets
        // whatever ?id= was supplied. You authenticate as yourself, but
        // can overwrite anyone else's password. (Classic "verify one
        // thing, act on another" logic bug.)
        $self = null;
        $r2 = mysqli_query($conn, "SELECT password FROM users WHERE id = " . (int)$_SESSION['user_id']);
        if ($r2) { $self = mysqli_fetch_assoc($r2); }
        if ($self && $self['password'] === md5($current_password)) {
            $hash = md5($new_password);
            $stmt = mysqli_prepare($conn, "UPDATE users SET password = ? WHERE id = ?");
            mysqli_stmt_bind_param($stmt, 'si', $hash, $target_id);
            mysqli_stmt_execute($stmt);
            $msg = "Password updated for user #$target_id.";
        } else {
            $err = 'Current password is incorrect.';
        }

    } else {
        // hard & expert: ownership properly enforced, current password
        // properly checked against the TARGET account, and the update is
        // parameterized. Expert additionally requires a valid CSRF token.
        $owns = ((int)$target_id === (int)$_SESSION['user_id']);
        if (!$owns && $_SESSION['role'] !== 'admin') {
            $err = 'You can only change your own password.';
        } elseif ($difficulty === 'expert' && (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']))) {
            $err = 'CSRF token invalid — request rejected.';
        } elseif (!$target || $target['password'] !== md5($current_password)) {
            $err = 'Current password is incorrect.';
        } else {
            $hash = md5($new_password);
            $stmt = mysqli_prepare($conn, "UPDATE users SET password = ? WHERE id = ?");
            mysqli_stmt_bind_param($stmt, 'si', $hash, $target_id);
            mysqli_stmt_execute($stmt);
            $msg = 'Password updated.';
        }
    }
    if ($msg) { log_activity($conn, $_SESSION['username'], "changed password for user id=$target_id"); }
}

include __DIR__ . '/../includes/header.php';
?>
<h2>Change Password<?php if ($target && (int)$target_id !== (int)$_SESSION['user_id']) echo ' — ' . htmlspecialchars($target['username']); ?></h2>
<?php if ($msg): ?><div class="notice"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>
<?php if ($err): ?><div class="error"><?php echo htmlspecialchars($err); ?></div><?php endif; ?>

<form method="POST" style="max-width:360px;">
    <?php if ($difficulty !== 'simple'): ?>
    <label>Current password</label>
    <input type="password" name="current_password">
    <?php endif; ?>
    <label>New password</label>
    <input type="password" name="new_password" required>
    <label>Confirm new password</label>
    <input type="password" name="confirm_password" required>
    <?php if ($difficulty === 'expert'): ?>
    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
    <?php endif; ?>
    <button type="submit">Update Password</button>
</form>
<p class="small">Mode: <?php echo htmlspecialchars($difficulty); ?>. Changing another account's password? Add
<code>?id=&lt;user id&gt;</code> to the URL.</p>
<?php include __DIR__ . '/../includes/footer.php'; ?>
