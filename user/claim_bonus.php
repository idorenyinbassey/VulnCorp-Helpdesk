<?php
require_once dirname(__FILE__) . '/../includes/auth.php';
require_once dirname(__FILE__) . '/../includes/db.php';
require_login();

$difficulty = get_difficulty($conn);
$msg = '';
$err = '';
$user_id = (int)$_SESSION['user_id'];

// PHP's default session handling locks the session file for the whole
// request, which serializes concurrent requests from the same browser
// regardless of how many workers the web server has - this would mask
// the race condition below even on a real multi-worker Apache/PHP-FPM
// deployment. Closing the session early (a real, commonly-recommended
// performance pattern - "don't hold the lock longer than you need it")
// releases that lock, which is what actually makes the race reachable
// with plain concurrent requests instead of only in theory. We don't
// write to $_SESSION again after this point, so nothing is lost.
session_write_close();

$res = mysqli_query($conn, "SELECT bonus_claimed, bonus_credits FROM users WHERE id = " . $user_id);
$me = $res ? mysqli_fetch_assoc($res) : array('bonus_claimed' => 0, 'bonus_credits' => 0);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['claim'])) {

    if ($difficulty === 'simple' || $difficulty === 'intermediate') {
        // Classic TOCTOU (time-of-check to time-of-use): read the flag,
        // decide based on it, THEN write - as two separate steps. If two
        // requests both read "not claimed yet" before either one writes
        // "claimed", both proceed to award credit. Simple adds a wide
        // artificial delay between check and write (simulating a slower
        // real-world operation like a payment call) so the race window is
        // generous enough to hit reliably with plain concurrent curl/browser
        // requests. Intermediate has the SAME bug with only a brief delay -
        // still enough of a window to land with a real burst of concurrent
        // requests (dozens, not two or three), but narrow enough that a
        // handful of manually-fired tabs usually won't catch it; scripted
        // concurrency (Burp Intruder in "throttled" concurrent mode, or a
        // short async script) is the realistic way to land this one.
        $uid = (int)$_SESSION['user_id'];
        $check = mysqli_query($conn, "SELECT bonus_claimed FROM users WHERE id = $uid");
        $row = mysqli_fetch_assoc($check);

        if ($difficulty === 'simple') {
            usleep(400000); // 0.4s artificial window between check and write
        } elseif ($difficulty === 'intermediate') {
            usleep(50000); // 50ms - narrower than simple, but a real burst still lands it
        }

        if ($row && (int)$row['bonus_claimed'] === 0) {
            // Two separate statements - the check result from above is
            // trusted even though time has passed and another request
            // could have run in between.
            mysqli_query($conn, "UPDATE users SET bonus_claimed = 1, bonus_credits = bonus_credits + 100 WHERE id = $uid");
            $msg = 'Bonus claimed! +100 credits.';
        } else {
            $err = 'Bonus already claimed.';
        }

    } else {
        // hard & expert: a single atomic UPDATE does the check and the
        // write in one statement, guarded by the WHERE clause itself, so
        // MySQL's row locking makes the check-and-set indivisible - only
        // one concurrent request can ever match bonus_claimed = 0.
        $uid = (int)$_SESSION['user_id'];
        mysqli_query($conn, "UPDATE users SET bonus_claimed = 1, bonus_credits = bonus_credits + 100 WHERE id = $uid AND bonus_claimed = 0");
        if (mysqli_affected_rows($conn) > 0) {
            $msg = 'Bonus claimed! +100 credits.';
        } else {
            $err = 'Bonus already claimed.';
        }
    }

    log_activity($conn, $_SESSION['username'], 'attempted bonus claim');
    $res = mysqli_query($conn, "SELECT bonus_claimed, bonus_credits FROM users WHERE id = " . (int)$_SESSION['user_id']);
    $me = $res ? mysqli_fetch_assoc($res) : $me;
}

include dirname(__FILE__) . '/../includes/header.php';
?>
<h2>Welcome Bonus</h2>
<?php if ($msg): ?><div class="notice"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>
<?php if ($err): ?><div class="error"><?php echo htmlspecialchars($err); ?></div><?php endif; ?>

<p>One-time welcome bonus: <strong>100 credits</strong>, claimable once per account.</p>
<p>Status: <strong><?php echo $me['bonus_claimed'] ? 'Already claimed' : 'Not yet claimed'; ?></strong></p>
<p>Current balance: <strong><?php echo (int)$me['bonus_credits']; ?> credits</strong></p>

<form method="POST">
    <input type="hidden" name="claim" value="1">
    <button type="submit">Claim Bonus</button>
</form>
<p class="small">Mode: <?php echo htmlspecialchars($difficulty); ?>. A balance above 100 means the one-time
limit was bypassed.</p>
<?php include dirname(__FILE__) . '/../includes/footer.php'; ?>
