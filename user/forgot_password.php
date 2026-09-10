<?php
require_once dirname(__FILE__) . '/../includes/db.php';
if (session_id() === '') { session_start(); }

$difficulty = get_difficulty($conn);
$msg = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['username'])) {
    $username = mysqli_real_escape_string($conn, $_POST['username']);
    $res = mysqli_query($conn, "SELECT id FROM users WHERE username = '$username'");
    if ($res && mysqli_num_rows($res) > 0) {
        $user = mysqli_fetch_assoc($res);

        if ($difficulty === 'simple') {
            // Token has zero secret material - it's fully derivable from
            // the username alone, with no expiry.
            $token = md5($username);
            $expires = date('Y-m-d H:i:s', time() + 3600);

        } elseif ($difficulty === 'intermediate') {
            // Token depends on today's date, which is public knowledge.
            $token = md5($username . date('Y-m-d'));
            $expires = date('Y-m-d H:i:s', time() + 3600);

        } elseif ($difficulty === 'hard') {
            // Token depends on the current unix timestamp -- unknown to an
            // attacker exactly, but only has a small effective search space
            // if they request their guess within a minute or two of you
            // requesting the real reset.
            $token = md5($username . time());
            $expires = date('Y-m-d H:i:s', time() + 3600);

        } else { // expert
            // Cryptographically random, unguessable, short-lived.
            $token = bin2hex(random_bytes(32));
            $expires = date('Y-m-d H:i:s', time() + 900);
        }

        $stmt = mysqli_prepare($conn, "UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?");
        mysqli_stmt_bind_param($stmt, 'ssi', $token, $expires, $user['id']);
        mysqli_stmt_execute($stmt);

        // In production this token would be emailed, never shown here.
        // It's echoed on screen ONLY in simple/intermediate/hard modes as
        // a deliberate lab shortcut so the "leak" is visible and the
        // predictability is something you can also derive independently
        // without needing a mail server in this lab.
        if ($difficulty !== 'expert') {
            $msg = "If that account exists, a reset link has been generated: "
                 . "<a href=\"/user/reset_password.php?token=" . htmlspecialchars($token) . "\">reset link</a>"
                 . " <span class=\"small\">(shown here only because this lab has no mail server — in a real app this would be emailed, not displayed)</span>";
        } else {
            $msg = 'If that account exists, a reset link has been sent to the address on file.';
        }
    } else {
        // Same message either way in this tier - not an enumeration oracle.
        $msg = 'If that account exists, a reset link has been generated.';
    }
}

include dirname(__FILE__) . '/../includes/header.php';
?>
<h2>Forgot Password</h2>
<?php if ($msg): ?><div class="notice"><?php echo $msg; ?></div><?php endif; ?>
<form method="POST" style="max-width:360px;">
    <label>Username</label>
    <input type="text" name="username" required>
    <button type="submit">Request reset link</button>
</form>
<p class="small">Mode: <?php echo htmlspecialchars($difficulty); ?>. <a href="/index.php">Back to login</a></p>
<?php include dirname(__FILE__) . '/../includes/footer.php'; ?>
