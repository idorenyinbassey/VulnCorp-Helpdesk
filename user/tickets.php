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

// ---------------------------------------------------------------
// Business Logic module: "Request Escalation to Urgent". A user can ask
// for their own ticket to be bumped to Urgent priority - approving that
// request is meant to be a staff-only action (see
// support/escalation_approve.php for the hard/expert-tier bugs in that
// approval step). The bugs below are in the REQUEST step itself.
// ---------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['request_escalation'])) {
    $esc_ticket_id = (int)$_POST['ticket_id'];
    $check = mysqli_query($conn, "SELECT user_id FROM tickets WHERE id = " . $esc_ticket_id);
    $esc_ticket = $check ? mysqli_fetch_assoc($check) : null;

    if ($esc_ticket && (int)$esc_ticket['user_id'] === (int)$_SESSION['user_id']) {
        if ($difficulty === 'simple' || $difficulty === 'intermediate') {
            // simple: the "Request Escalation" button IS the escalation -
            // no approval step exists server-side at all.
            // intermediate: the page below now SHOWS a "pending approval"
            // state after clicking (a bit of JS disables the button and
            // relabels it) - but this handler is completely unchanged:
            // it still flips priority to urgent immediately on the same
            // request. The JS-only gate proves nothing about what the
            // server actually enforces; resending this exact POST
            // directly (curl/Burp) after the button "disables" still
            // escalates instantly.
            mysqli_query($conn, "UPDATE tickets SET priority = 'urgent', escalation_status = 'approved' WHERE id = " . $esc_ticket_id);
            $msg = 'Ticket escalated to Urgent.';
        } else {
            // hard/expert: a real pending state now exists - getting to
            // 'approved' requires a separate call to
            // support/escalation_approve.php.
            mysqli_query($conn, "UPDATE tickets SET escalation_status = 'pending' WHERE id = " . $esc_ticket_id);
            $msg = 'Escalation requested - pending staff approval.';
        }
    }
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

    <!-- SSRF module: server-side link preview, same real pattern as
         Slack/Jira link unfurling - see user/link_preview.php. -->
    <label>Paste a link to preview (optional)</label>
    <input type="text" id="link-preview-url" placeholder="https://...">
    <button type="button" id="link-preview-btn" class="btn" style="padding:4px 10px;font-size:12px;">Preview link</button>
    <div id="link-preview-result" class="small" style="margin-top:6px;"></div>

    <button type="submit">Submit</button>
</form>
<script>
document.getElementById('link-preview-btn').addEventListener('click', function () {
    var url = document.getElementById('link-preview-url').value;
    var out = document.getElementById('link-preview-result');
    if (!url) { return; }
    out.textContent = 'Loading preview...';
    var xhr = new XMLHttpRequest();
    xhr.open('POST', '<?php echo app_base(); ?>/user/link_preview.php', true);
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    xhr.onload = function () {
        try {
            var data = JSON.parse(xhr.responseText);
            out.textContent = data.error ? ('Error: ' + data.error) : ('Preview (HTTP ' + data.http_code + '): ' + data.preview);
        } catch (e) {
            out.textContent = 'Could not load preview.';
        }
    };
    xhr.send('url=' + encodeURIComponent(url));
});
</script>

<h3>Search my tickets</h3>
<!-- DOM XSS module: a "deep link to a search" banner, purely client-side
     - see assets/search-prefill.js. Visit this page with #q=<term> in
     the URL to trigger it; the server never sees the fragment at all. -->
<div id="search-prefill-banner"></div>
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
<tr><th>ID</th><th>Subject</th><th>Message</th><th>Status</th><th>Priority</th><th>Created</th><th>Escalate</th></tr>
<?php foreach ($tickets as $row):
    if ($search !== '' && stripos($row['subject'], $search) === false) continue;
?>
<tr>
    <td><?php echo (int)$row['id']; ?></td>
    <td><?php echo render_ticket_text($row['subject'], $difficulty); ?></td>
    <td><?php echo render_ticket_text($row['message'], $difficulty); ?></td>
    <td><?php echo htmlspecialchars($row['status']); ?></td>
    <td><?php echo htmlspecialchars($row['priority']); ?></td>
    <td><?php echo htmlspecialchars($row['created_at']); ?></td>
    <td>
    <?php if ($row['priority'] !== 'urgent' && $row['escalation_status'] !== 'pending'): ?>
        <form method="POST" style="display:inline;" class="escalation-form">
            <input type="hidden" name="ticket_id" value="<?php echo (int)$row['id']; ?>">
            <button type="submit" name="request_escalation" value="1" class="btn escalation-btn" style="padding:3px 9px;font-size:11px;">Request Urgent</button>
        </form>
    <?php elseif ($row['escalation_status'] === 'pending'): ?>
        <span class="small">Pending approval</span>
    <?php endif; ?>
    </td>
</tr>
<?php endforeach; ?>
</table>
<?php if ($difficulty === 'intermediate'): ?>
<script>
// Business Logic module (intermediate tier): purely cosmetic - disables
// the button after submit so the flow *looks* like a real pending/wait
// state. The server-side handler has no such gate at this tier (see the
// POST handler above) - this script changes nothing about what actually
// gets enforced.
document.querySelectorAll('.escalation-form').forEach(function (f) {
    f.addEventListener('submit', function () {
        var btn = f.querySelector('.escalation-btn');
        setTimeout(function () { btn.disabled = true; btn.textContent = 'Pending approval...'; }, 50);
    });
});
</script>
<?php endif; ?>
<script src="<?php echo app_base(); ?>/assets/search-prefill.js"></script>
<?php include dirname(__FILE__) . '/../includes/footer.php'; ?>
