<?php
// includes/auth.php
if (session_id() === '') {
    session_start();
}

function require_login() {
    if (!isset($_SESSION['user_id'])) {
        header('Location: ' . app_base() . '/index.php');
        exit;
    }
    // 2FA gate: a totp-enabled account's session carries 'totp_verified'
    // from the moment the password check succeeds (see index.php) - it's
    // only ever missing entirely for accounts that never opted into 2FA,
    // which is why a missing key is treated as "nothing to verify" rather
    // than blocking every login. This check lives here, in the shared
    // require_login() helper - any page that rolls its own ad-hoc
    // "isset($_SESSION['user_id'])" check instead of calling this
    // function (api/tickets.php does exactly that) never learns about
    // this flag at all. See the 2FA Bypass module / README.
    if (isset($_SESSION['totp_verified']) && $_SESSION['totp_verified'] === false) {
        header('Location: ' . app_base() . '/user/verify_2fa.php');
        exit;
    }
}

// NOTE: In "simple" and "intermediate" tiers, role checks like this exist on
// the page itself but pages are still directly reachable by guessing the
// URL (broken access control / forced browsing) — that's intentional.
function require_role($roles) {
    require_login();
    if (!in_array($_SESSION['role'], (array)$roles)) {
        header('HTTP/1.1 403 Forbidden');
        echo "<h2>403 Forbidden</h2><p>Your role (" . htmlspecialchars($_SESSION['role']) . ") cannot access this page.</p>";
        echo '<a href="' . htmlspecialchars(app_base()) . '/dashboard.php">Back to dashboard</a>';
        exit;
    }
}
