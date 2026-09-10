<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/render.php';
require_role(array('support', 'admin'));

$difficulty = get_difficulty($conn);
$msg = '';

// CSRF token only enforced at expert tier.
if (session_status() !== PHP_SESSION_NONE && !isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(16));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ticket_id'], $_POST['status'])) {
    $proceed = true;
    if ($difficulty === 'expert') {
        $proceed = isset($_POST['csrf_token']) && hash_equals($_SESSION['csrf_token'], $_POST['csrf_token']);
        if (!$proceed) { $msg = 'CSRF token invalid — request rejected.'; }
    }
    // simple / intermediate / hard: no CSRF token check at all -> a support
    // agent visiting an attacker-controlled page can have ticket status
    // changed (or worse, in a fuller app) without consenting.
    if ($proceed) {
        $tid = (int)$_POST['ticket_id'];
        $status = mysqli_real_escape_string($conn, $_POST['status']);
        mysqli_query($conn, "UPDATE tickets SET status = '$status' WHERE id = $tid");
        $msg = "Ticket #$tid marked as $status.";
        log_activity($conn, $_SESSION['username'], "updated ticket #$tid to $status");
    }
}

$res = mysqli_query($conn, "SELECT t.*, u.username FROM tickets t JOIN users u ON u.id = t.user_id ORDER BY t.id DESC");
include __DIR__ . '/../includes/header.php';
?>
<h2>Support Queue</h2>
<?php if ($msg): ?><div class="notice"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>
<table>
<tr><th>ID</th><th>From</th><th>Subject</th><th>Message</th><th>Status</th><th>Action</th></tr>
<?php while ($row = mysqli_fetch_assoc($res)): ?>
<tr>
    <td><?php echo (int)$row['id']; ?></td>
    <td><?php echo htmlspecialchars($row['username']); ?></td>
    <td><?php echo render_ticket_text($row['subject'], $difficulty); ?></td>
    <td><?php echo render_ticket_text($row['message'], $difficulty); ?></td>
    <td><?php echo htmlspecialchars($row['status']); ?></td>
    <td>
        <form method="POST" style="margin:0;">
            <input type="hidden" name="ticket_id" value="<?php echo (int)$row['id']; ?>">
            <?php if ($difficulty === 'expert'): ?>
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <?php endif; ?>
            <select name="status" style="width:auto;display:inline-block;margin:0 6px;">
                <option value="open" <?php if($row['status']=='open') echo 'selected'; ?>>open</option>
                <option value="in_progress" <?php if($row['status']=='in_progress') echo 'selected'; ?>>in_progress</option>
                <option value="closed" <?php if($row['status']=='closed') echo 'selected'; ?>>closed</option>
            </select>
            <button type="submit" style="padding:4px 10px;">Update</button>
        </form>
    </td>
</tr>
<?php endwhile; ?>
</table>
<p class="small">Below <strong>expert</strong> mode, this status-update form has no CSRF token — a crafted external page can auto-submit it.</p>
<?php include __DIR__ . '/../includes/footer.php'; ?>
