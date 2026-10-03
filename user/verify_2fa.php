<?php
// user/verify_2fa.php - the second login step for totp-enabled accounts.
//
// Deliberately does NOT include includes/header.php/footer.php (the
// shared page chrome every other page in this app uses) - see
// includes/header.php's own comment and the Clickjacking module in
// README for why that specific omission is this app's hard-tier
// clickjacking bug: X-Frame-Options is only ever set inside header.php,
// so a page that skips it never gets the protection either, no matter
// the difficulty tier. This page still enforces its own login check
// below; it just never got the shared header wired in when it was
// built - exactly the kind of gap a real code review has to catch page
// by page, not assume from one shared include.
require_once dirname(__FILE__) . '/../includes/db.php';
require_once dirname(__FILE__) . '/../includes/totp.php';
if (session_id() === '') { session_start(); }

if (!isset($_SESSION['user_id'])) {
    header('Location: ' . app_base() . '/index.php');
    exit;
}

$difficulty = get_difficulty($conn);
$uid = (int)$_SESSION['user_id'];
$error = '';

// Already fully verified (or this account never needed to be) - nothing
// to do here.
if (!isset($_SESSION['totp_verified']) || $_SESSION['totp_verified'] === true) {
    header('Location: ' . app_base() . '/dashboard.php');
    exit;
}

$res = mysqli_query($conn, "SELECT username, totp_secret FROM users WHERE id = " . $uid);
$user = $res ? mysqli_fetch_assoc($res) : null;
if (!$user) {
    header('Location: ' . app_base() . '/index.php');
    exit;
}

// ---------------------------------------------------------------
// expert tier only: a "trust this device" cookie, once set, skips the
// code prompt entirely on future logins. Its value is md5($username) -
// the same weak-token flavor already used for the simple-tier
// forgot-password bug elsewhere in this app - so an attacker who merely
// knows (or guesses) a target's username can forge this cookie and skip
// 2FA without ever producing a valid code.
// ---------------------------------------------------------------
$trusted_cookie_name = 'trusted_device_' . $uid;
if ($difficulty === 'expert' && isset($_COOKIE[$trusted_cookie_name])) {
    if (hash_equals(md5($user['username']), $_COOKIE[$trusted_cookie_name])) {
        $_SESSION['totp_verified'] = true;
        header('Location: ' . app_base() . '/dashboard.php');
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['code'])) {

    // hard tier only: no rate limiting on code attempts at all - a
    // 6-digit code is a 1,000,000-value space, brute-forceable given
    // enough time (Burp Intruder / a short script), the same
    // absence-of-a-control pattern as the login and API-token
    // rate-limiting modules elsewhere in this app. expert tier closes
    // this.
    if ($difficulty === 'expert') {
        $stmt = mysqli_prepare($conn, "SELECT COUNT(*) AS n FROM activity_log WHERE action = 'totp_fail' AND username = ? AND logged_at > (NOW() - INTERVAL 5 MINUTE)");
        mysqli_stmt_bind_param($stmt, 's', $user['username']);
        mysqli_stmt_execute($stmt);
        $row = stmt_fetch_one($stmt);
        if ($row && (int)$row['n'] >= 5) {
            $error = 'Too many attempts - try again later.';
        }
    }

    if ($error === '') {
        if (totp_verify($user['totp_secret'], $_POST['code'])) {
            $_SESSION['totp_verified'] = true;
            log_activity($conn, $user['username'], 'totp_success');

            if ($difficulty === 'expert' && isset($_POST['trust_device'])) {
                setcookie($trusted_cookie_name, md5($user['username']), time() + 86400 * 30, '/');
            }
            header('Location: ' . app_base() . '/dashboard.php');
            exit;
        } else {
            log_activity($conn, $user['username'], 'totp_fail');
            $error = 'Invalid code.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnCorp Helpdesk - Verify 2FA</title>
<link rel="stylesheet" href="<?php echo app_base(); ?>/assets/style.css">
</head>
<body>
<div class="container" style="max-width:400px;">
    <h2>Enter your 2FA code</h2>
    <?php if ($error): ?><div class="error"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>
    <form method="POST">
        <label>6-digit code</label>
        <input type="text" name="code" autofocus maxlength="6" pattern="[0-9]{6}">
        <?php if ($difficulty === 'expert'): ?>
        <label><input type="checkbox" name="trust_device" style="width:auto;display:inline-block;"> Trust this device for 30 days</label>
        <?php endif; ?>
        <button type="submit">Verify</button>
    </form>
</div>
</body>
</html>
