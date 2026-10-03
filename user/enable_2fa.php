<?php
require_once dirname(__FILE__) . '/../includes/auth.php';
require_once dirname(__FILE__) . '/../includes/db.php';
require_once dirname(__FILE__) . '/../includes/totp.php';
require_login();

$difficulty = get_difficulty($conn);
$uid = (int)$_SESSION['user_id'];
$msg = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['enable'])) {
        $secret = totp_generate_secret();
        $stmt = mysqli_prepare($conn, "UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?");
        mysqli_stmt_bind_param($stmt, 'si', $secret, $uid);
        mysqli_stmt_execute($stmt);
        $_SESSION['_new_totp_secret'] = $secret; // one-time display only, see below
        $msg = '2FA enabled.';
    } elseif (isset($_POST['disable'])) {
        // This toggle is the intended Clickjacking-module PoC target (see
        // includes/header.php / README): below hard tier, this page has
        // no X-Frame-Options at all, so an attacker's page can overlay an
        // invisible iframe of this exact form and trick a logged-in
        // victim into disabling their own 2FA with a single disguised
        // click, never seeing this page at all.
        $stmt = mysqli_prepare($conn, "UPDATE users SET totp_enabled = 0 WHERE id = ?");
        mysqli_stmt_bind_param($stmt, 'i', $uid);
        mysqli_stmt_execute($stmt);
        $msg = '2FA disabled.';
    }
}

$res = mysqli_query($conn, "SELECT totp_enabled FROM users WHERE id = " . $uid);
$row = $res ? mysqli_fetch_assoc($res) : array('totp_enabled' => 0);
$enabled = !empty($row['totp_enabled']);

// A freshly-generated secret is shown exactly once, right after enabling -
// real authenticator-app setup flows work the same way (scan now, it's
// not shown again). Intentionally NOT reachable via GET/reload.
$shown_secret = isset($_SESSION['_new_totp_secret']) ? $_SESSION['_new_totp_secret'] : null;
unset($_SESSION['_new_totp_secret']);

include dirname(__FILE__) . '/../includes/header.php';
?>
<h2>Two-Factor Authentication</h2>
<p class="small">Status: <strong><?php echo $enabled ? 'Enabled' : 'Disabled'; ?></strong></p>

<?php if ($msg): ?><div class="notice"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>

<?php if ($shown_secret): ?>
<div class="notice">
    <strong>Your new TOTP secret (shown once):</strong>
    <p><code><?php echo htmlspecialchars($shown_secret); ?></code></p>
    <p class="small">Enter this into any TOTP authenticator app (RFC 6238 / Google Authenticator-compatible).</p>
</div>
<?php endif; ?>

<?php if ($enabled): ?>
<form method="POST">
    <button type="submit" name="disable" value="1" class="btn">Disable 2FA</button>
</form>
<?php else: ?>
<form method="POST">
    <button type="submit" name="enable" value="1" class="btn">Enable 2FA</button>
</form>
<?php endif; ?>

<?php include dirname(__FILE__) . '/../includes/footer.php'; ?>
