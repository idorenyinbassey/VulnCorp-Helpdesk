<?php
require_once __DIR__ . '/includes/db.php';
if (session_status() === PHP_SESSION_NONE) { session_start(); }

$error = '';
$difficulty = get_difficulty($conn);

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
        header('Location: /dashboard.php');
        exit;
    }
}

if (isset($_SESSION['user_id'])) {
    header('Location: /dashboard.php');
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
        $res = mysqli_stmt_get_result($stmt);
        if ($res && mysqli_num_rows($res) > 0) {
            $user = mysqli_fetch_assoc($res);
        }

    } else { // expert
        // Fully parameterized, salted-ish hashing check, no info leakage.
        $stmt = mysqli_prepare($conn, "SELECT * FROM users WHERE username = ? AND password = MD5(?)");
        mysqli_stmt_bind_param($stmt, 'ss', $username, $password);
        mysqli_stmt_execute($stmt);
        $res = mysqli_stmt_get_result($stmt);
        if ($res && mysqli_num_rows($res) > 0) {
            $user = mysqli_fetch_assoc($res);
        }
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
        header('Location: /dashboard.php');
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
<link rel="stylesheet" href="/assets/style.css">
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
        <button type="submit">Login</button>
    </form>
    <p class="small">Difficulty tier is controlled by an admin from the admin panel.</p>
    <p class="small"><a href="/user/forgot_password.php">Forgot password?</a></p>
</div>
</body>
</html>
