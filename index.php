<?php
require_once dirname(__FILE__) . '/includes/db.php';
require_once dirname(__FILE__) . '/includes/simple_cache.php';
if (session_id() === '') { session_start(); }

$error = '';
$difficulty = get_difficulty($conn);

// ---------------------------------------------------------------
// Open Redirect module. Post-login "send the user back where they
// came from" is a very common real-world pattern (SSO flows, "log in
// to continue" links) and a very common place to find this bug.
// ---------------------------------------------------------------
function resolve_login_redirect($difficulty) {
    $redirect = isset($_REQUEST['redirect']) ? $_REQUEST['redirect'] : '';
    if ($redirect === '') {
        return app_base() . '/dashboard.php';
    }

    if ($difficulty === 'simple') {
        // No validation at all - the classic open redirect.
        return $redirect;

    } elseif ($difficulty === 'intermediate') {
        // "Validates" by requiring the target start with a single slash -
        // but a protocol-relative URL ("//evil.com") also starts with "/",
        // and browsers treat "//host" as "same scheme, different host".
        if (strpos($redirect, '/') === 0) {
            return $redirect;
        }
        return app_base() . '/dashboard.php';

    } elseif ($difficulty === 'hard') {
        // Blocks protocol-relative URLs specifically, but also "trusts"
        // any URL that merely contains the app's own name anywhere in it -
        // which an attacker-controlled domain or path can just as easily
        // contain (e.g. http://evil.com/vulnapp or http://vulnapp.evil.com).
        $is_protocol_relative = (strpos($redirect, '//') === 0);
        if (strpos($redirect, '/') === 0 && !$is_protocol_relative) {
            return $redirect;
        }
        if (!$is_protocol_relative && strpos($redirect, 'vulnapp') !== false) {
            return $redirect;
        }
        return app_base() . '/dashboard.php';

    } else { // expert
        // Whitelist of real in-app paths only - closed.
        $allowed = array('/dashboard.php', '/challenges/index.php', '/toolkit/index.php', '/user/tickets.php');
        $base = app_base();
        $path = $redirect;
        if ($base !== '' && strpos($path, $base) === 0) {
            $path = substr($path, strlen($base));
        }
        if (in_array($path, $allowed, true)) {
            return $base . $path;
        }
        return $base . '/dashboard.php';
    }
}

// ---- "Remember me" auto-login (HARD tier: cookie value used unsafely in SQL) ----
if (!isset($_SESSION['user_id']) && isset($_COOKIE['remember_token']) && $difficulty === 'hard') {
    $token = $_COOKIE['remember_token']; // NOT escaped on purpose in hard mode
    $sql = "SELECT * FROM users WHERE session_token = '$token' LIMIT 1";
    $res = mysqli_query($conn, $sql);
    if ($res && mysqli_num_rows($res) > 0) {
        $u = mysqli_fetch_assoc($res);
        $_SESSION['user_id'] = $u['id'];
        $_SESSION['username'] = $u['username'];
        $_SESSION['role'] = $u['role'];
        $_SESSION['full_name'] = $u['full_name'];
        // Session Fixation module: the password-login path below rotates
        // the session ID at hard/expert tiers (see its own comment) - this
        // auto-login path deliberately does NOT, at any tier. An attacker
        // who fixated a session before the victim's "remember me" cookie
        // was even set still wins on the victim's next visit, since this
        // branch is reachable with zero fresh user interaction at all.
        //
        // 2FA Bypass module: this auto-login still has to respect
        // totp_enabled the same way the password-login path below does -
        // without this check, a "remember me" cookie would skip 2FA
        // entirely at the hard tier (the only tier this branch runs at),
        // which isn't any of this module's four intended tiered bugs, just
        // an unrelated feature interaction.
        if (!empty($u['totp_enabled'])) {
            $_SESSION['totp_verified'] = false;
            header('Location: ' . app_base() . '/user/verify_2fa.php');
            exit;
        }
        header('Location: ' . app_base() . '/dashboard.php');
        exit;
    }
}

if (isset($_SESSION['user_id'])) {
    header('Location: ' . app_base() . '/dashboard.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'];
    $password = $_POST['password'];
    $remember = isset($_POST['remember']);
    $user = null;

    if ($difficulty === 'simple') {
        // No escaping at all. Classic auth-bypass / UNION-based SQLi.
        $sql = "SELECT * FROM users WHERE username = '$username' AND password = MD5('$password')";
        $res = mysqli_query($conn, $sql);
        if ($res === false) {
            $error = 'SQL error: ' . mysqli_error($conn); // verbose errors leak schema info
        } elseif (mysqli_num_rows($res) > 0) {
            $user = mysqli_fetch_assoc($res);
        }

    } elseif ($difficulty === 'intermediate') {
        // Weak keyword blacklist, case-sensitive lowercase only -> bypassable with UPPER/MiXeD case.
        $blacklist = array('union', 'select', '--', '#', ';');
        $clean_user = str_ireplace($blacklist, '', $username);
        // ^ str_ireplace here is case-insensitive so simple keyword swap is blocked,
        // but the developer forgot inline comments and stacked tricks like UNION/**/SELECT,
        // and forgot to filter the password field at all.
        $clean_user = mysqli_real_escape_string($conn, $clean_user);
        $sql = "SELECT * FROM users WHERE username = '$clean_user' AND password = MD5('$password')";
        $res = mysqli_query($conn, $sql);
        if ($res && mysqli_num_rows($res) > 0) {
            $user = mysqli_fetch_assoc($res);
        }

    } elseif ($difficulty === 'hard') {
        // Primary login is parameterized (safe) - the injectable surface here is the
        // remember-me cookie handled above, and predictable session tokens.
        $stmt = mysqli_prepare($conn, "SELECT * FROM users WHERE username = ? AND password = MD5(?)");
        mysqli_stmt_bind_param($stmt, 'ss', $username, $password);
        mysqli_stmt_execute($stmt);
        $user = stmt_fetch_one($stmt);

    } else { // expert
        // Fully parameterized, salted-ish hashing check, no info leakage.
        $stmt = mysqli_prepare($conn, "SELECT * FROM users WHERE username = ? AND password = MD5(?)");
        mysqli_stmt_bind_param($stmt, 'ss', $username, $password);
        mysqli_stmt_execute($stmt);
        $user = stmt_fetch_one($stmt);
        // NOTE: expert tier intentionally has NO rate limiting / lockout anywhere in
        // this app, and session tokens below are predictable -> the intended attack
        // path here is online brute force + session token prediction, not SQLi.
    }

    if ($user) {
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        $_SESSION['full_name'] = $user['full_name'];
        log_activity($conn, $user['username'], 'login_success');

        // ---------------------------------------------------------------
        // Session Fixation module. Rotating the session ID on every
        // privilege change (here: anonymous -> authenticated) is what
        // actually closes fixation - without it, an attacker who got a
        // victim to use a session ID the attacker already knows (set the
        // cookie before sending a link, or a shared/kiosk device) is just
        // as authenticated as the victim the instant login succeeds, no
        // credentials needed at all.
        // ---------------------------------------------------------------
        if ($difficulty === 'hard' || $difficulty === 'expert') {
            session_regenerate_id(true);
        }
        // simple/intermediate: the ID never rotates on login - the bug.
        // (The hard-tier "remember me" auto-login path above has the same
        // gap left open on purpose - see its own comment.)

        // ---------------------------------------------------------------
        // 2FA Bypass module. Only accounts with totp_enabled reach this
        // at all - seeded on 'carol' only (db_setup.sql), so every other
        // seeded account is completely untouched by this module, at any
        // tier, and every existing admin/sam/alice/bob challenge keeps
        // working exactly as before.
        // ---------------------------------------------------------------
        if (!empty($user['totp_enabled'])) {
            if ($difficulty === 'simple') {
                // Decorative 2FA: the "verified" flag is set to true
                // before a code was ever checked. The redirect below
                // still sends the user to the code-entry page, so the UI
                // *looks* identical to the other tiers - but nothing is
                // actually gated. Confirm by skipping the code prompt
                // entirely and browsing straight to /dashboard.php.
                $_SESSION['totp_verified'] = true;
            } else {
                $_SESSION['totp_verified'] = false;
            }
            header('Location: ' . app_base() . '/user/verify_2fa.php');
            exit;
        }

        if ($remember && ($difficulty === 'hard' || $difficulty === 'expert')) {
            if ($difficulty === 'hard') {
                $token = md5($user['username'] . time()); // predictable-ish, also used unsafely on read (see above)
            } else {
                $token = md5(uniqid('', false)); // expert: better entropy source, still worth pairing with rate-limit discussion
            }
            mysqli_query($conn, "UPDATE users SET session_token = '$token' WHERE id = " . intval($user['id']));
            setcookie('remember_token', $token, time() + 86400 * 7, '/');
        }
        header('Location: ' . resolve_login_redirect($difficulty));
        exit;
    } else {
        $error = isset($error) && $error !== '' ? $error : 'Invalid username or password.';
        log_activity($conn, $username, 'login_failed');
    }
}
// ---------------------------------------------------------------
// Cache Poisoning module. Only GET renders of this login form with no
// error are cache-eligible - a failed-login error page is never cached,
// since serving someone else's "Invalid username or password" to an
// unrelated visitor would be a real correctness bug, not just a lab
// vulnerability. See includes/simple_cache.php for the cache mechanics
// (keyed by full request URI, ignores every header - exactly the real
// CDN default behavior that makes this vulnerability class possible).
// ---------------------------------------------------------------
$cache_uri = $_SERVER['REQUEST_URI'];
$cache_eligible = ($_SERVER['REQUEST_METHOD'] === 'GET' && $error === '');

if ($cache_eligible) {
    $cached = simple_cache_get($cache_uri);
    if ($cached !== null) {
        echo $cached;
        exit;
    }
    ob_start();
}

// Unkeyed-header reflection, tiered. Neither header affects the cache
// key at any tier (see simple_cache.php) - what changes per tier is
// only how the *value* gets used once reflected.
$host_header = isset($_SERVER['HTTP_X_FORWARDED_HOST']) ? $_SERVER['HTTP_X_FORWARDED_HOST'] : $_SERVER['HTTP_HOST'];
$lang_header = isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 40) : 'en-US';

if ($difficulty === 'simple' || $difficulty === 'intermediate') {
    // Raw, unescaped reflection straight into an HTML attribute, on a
    // page the whole app caches with no variation by this header at
    // all. Poison it once with a crafted X-Forwarded-Host, and every
    // plain visitor who requests this exact URL within the cache TTL
    // gets the poisoned page back - not just you.
    $canonical_href = 'http://' . $host_header . '/';
} elseif ($difficulty === 'hard') {
    // Escaped now (closes direct markup injection) - but still used,
    // unvalidated, as the link's actual destination, so poisoning now
    // produces a cached open-redirect instead of injected markup.
    $canonical_href = htmlspecialchars('http://' . $host_header . '/', ENT_QUOTES);
} else { // expert
    // The Host-ish header no longer influences this link at all.
    $canonical_href = 'http://' . $_SERVER['SERVER_NAME'] . app_base() . '/';
}
// expert tier: Host is fixed above, but Accept-Language - a *different*
// unkeyed header - is still reflected raw into the banner below, at
// every tier. Fixing one unkeyed-input path doesn't fix the pattern.
$lang_banner = $lang_header;
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnCorp Helpdesk - Login</title>
<link rel="canonical" href="<?php echo $canonical_href; ?>">
<link rel="stylesheet" href="<?php echo app_base(); ?>/assets/style.css">
</head>
<body>
<div class="topbar">
    <div class="brand">VulnCorp Helpdesk <span class="tag">[TRAINING LAB]</span></div>
    <div class="mode-badge">Mode: <strong><?php echo htmlspecialchars($difficulty); ?></strong></div>
</div>
<div class="container" style="max-width:400px;">
    <h2>Sign in</h2>
    <p class="small">Preferred language: <?php echo $lang_banner; ?></p>
    <?php if ($error): ?><div class="error"><?php echo $error; ?></div><?php endif; ?>
    <form method="POST">
        <label>Username</label>
        <input type="text" name="username" autofocus>
        <label>Password</label>
        <input type="password" name="password">
        <?php if ($difficulty === 'hard' || $difficulty === 'expert'): ?>
        <label><input type="checkbox" name="remember" style="width:auto;display:inline-block;"> Remember me</label>
        <?php endif; ?>
        <input type="hidden" name="redirect" value="<?php echo htmlspecialchars(isset($_GET['redirect']) ? $_GET['redirect'] : ''); ?>">
        <button type="submit">Login</button>
    </form>
    <p class="small">Difficulty tier is controlled by an admin from the admin panel.</p>
    <p class="small"><a href="<?php echo app_base(); ?>/user/forgot_password.php">Forgot password?</a></p>
</div>
</body>
</html>
<?php
if ($cache_eligible) {
    $body = ob_get_clean();
    simple_cache_put($cache_uri, $body);
    echo $body;
}
