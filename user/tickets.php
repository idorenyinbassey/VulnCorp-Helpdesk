<?php
require_once dirname(__FILE__) . '/../includes/auth.php';
require_once dirname(__FILE__) . '/../includes/db.php';
require_once dirname(__FILE__) . '/../includes/render.php';
require_login();

$difficulty = get_difficulty($conn);
$msg = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['subject'])) {
    $subject = $_POST['subject'];
    $message = $_POST['message'];
    $stmt = mysqli_prepare($conn, "INSERT INTO tickets (user_id, subject, message) VALUES (?, ?, ?)");
    mysqli_stmt_bind_param($stmt, 'iss', $_SESSION['user_id'], $subject, $message);
    mysqli_stmt_execute($stmt);
    $msg = 'Ticket submitted.';
}

// Reflected XSS surface (hard/expert tiers): search term echoed into an
// HTML attribute (the input's value=) without escaping.
$search = isset($_GET['q']) ? $_GET['q'] : '';

$stmt = mysqli_prepare($conn, "SELECT * FROM tickets WHERE user_id = ? ORDER BY id DESC");
mysqli_stmt_bind_param($stmt, 'i', $_SESSION['user_id']);
mysqli_stmt_execute($stmt);
$tickets = stmt_fetch_all($stmt);

include dirname(__FILE__) . '/../includes/header.php';
?>
<h2>My Tickets</h2>
<?php if ($msg): ?><div class="notice"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>

<h3>Submit a ticket</h3>
<form method="POST">
    <label>Subject</label>
    <input type="text" name="subject" required>
    <label>Message</label>
    <textarea name="message" rows="4" required></textarea>
    <button type="submit">Submit</button>
</form>

<h3>Search my tickets</h3>
<form method="GET">
    <?php if ($difficulty === 'hard' || $difficulty === 'expert'): ?>
    <!-- value= is reflected without escaping in hard/expert on purpose -->
    <input type="text" name="q" value="<?php echo $search; ?>" placeholder="search subject...">
    <?php else: ?>
    <input type="text" name="q" value="<?php echo htmlspecialchars($search); ?>" placeholder="search subject...">
    <?php endif; ?>
    <button type="submit">Search</button>
</form>

<h3>Your tickets</h3>
<table>
<tr><th>ID</th><th>Subject</th><th>Message</th><th>Status</th><th>Created</th></tr>
<?php foreach ($tickets as $row):
    if ($search !== '' && stripos($row['subject'], $search) === false) continue;
?>
<tr>
    <td><?php echo (int)$row['id']; ?></td>
    <td><?php echo render_ticket_text($row['subject'], $difficulty); ?></td>
    <td><?php echo render_ticket_text($row['message'], $difficulty); ?></td>
    <td><?php echo htmlspecialchars($row['status']); ?></td>
    <td><?php echo htmlspecialchars($row['created_at']); ?></td>
</tr>
<?php endforeach; ?>
</table>
<?php include dirname(__FILE__) . '/../includes/footer.php'; ?>
