<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/db.php';
require_role('admin');

$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $valid = array('simple', 'intermediate', 'hard', 'expert');
    $new = $_POST['difficulty'];
    if (in_array($new, $valid, true)) {
        mysqli_query($conn, "UPDATE settings SET difficulty = '" . mysqli_real_escape_string($conn, $new) . "' WHERE id = 1");
        $msg = "Difficulty set to $new.";
        log_activity($conn, $_SESSION['username'], "changed difficulty to $new");
    }
}
$current = get_difficulty($conn);
include __DIR__ . '/../includes/header.php';
?>
<h2>Difficulty Settings</h2>
<?php if ($msg): ?><div class="notice"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>
<p>Current mode: <strong><?php echo htmlspecialchars($current); ?></strong></p>
<form method="POST">
    <label>Select difficulty tier</label>
    <select name="difficulty">
        <option value="simple" <?php if($current=='simple') echo 'selected'; ?>>Simple — obvious, unfiltered vulns (SQLi, XSS, cmd-i, IDOR, upload)</option>
        <option value="intermediate" <?php if($current=='intermediate') echo 'selected'; ?>>Intermediate — basic/bypassable filters</option>
        <option value="hard" <?php if($current=='hard') echo 'selected'; ?>>Hard — main paths hardened, secondary/chained flaws remain</option>
        <option value="expert" <?php if($current=='expert') echo 'selected'; ?>>Expert — heavily filtered, requires advanced/blind techniques</option>
    </select>
    <button type="submit">Apply</button>
</form>
<p class="small">See README.md in the project root for what changes at each tier, per module.</p>
<?php include __DIR__ . '/../includes/footer.php'; ?>
