<?php
require_once dirname(__FILE__) . '/includes/db.php';
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
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnCorp Helpdesk - Login</title>
<link rel="stylesheet" href="<?php echo app_base(); ?>/assets/style.css">
</head>
<body>
<div class="topbar">
    <div class="brand">VulnCorp Helpdesk <span class="tag">[TRAINING LAB]</span></div>
    <div class="mode-badge">Mode: <strong><?php echo htmlspecialchars($difficulty); ?></strong></div>
</div>
<div class="container" style="max-width:400px;">
    <h2>Sign in</h2>
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
