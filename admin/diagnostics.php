<?php
require_once __DIR__ . '/../includes/auth.php';
require_once __DIR__ . '/../includes/db.php';
require_role('admin');

$difficulty = get_difficulty($conn);
$output = '';
$cmd_shown = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $host = $_POST['host'];

    if ($difficulty === 'simple') {
        // Raw concatenation, zero filtering.
        $cmd = "ping -c 2 " . $host;
        $output = shell_exec($cmd . ' 2>&1');
        $cmd_shown = $cmd;

    } elseif ($difficulty === 'intermediate') {
        // Blacklists a few obvious separators but misses backticks, $(), and newlines.
        $bad = array(';', '&&', '||');
        $filtered = str_replace($bad, '', $host);
        $cmd = "ping -c 2 " . $filtered;
        $output = shell_exec($cmd . ' 2>&1');
        $cmd_shown = $cmd;

    } elseif ($difficulty === 'hard') {
        // Target host is escaped correctly, BUT a second "options" field
        // (meant for e.g. "-c 4") is concatenated unescaped after it.
        $safe_host = escapeshellarg($host);
        $opts = isset($_POST['opts']) ? $_POST['opts'] : '-c 2';
        $cmd = "ping " . $opts . " " . $safe_host;
        $output = shell_exec($cmd . ' 2>&1');
        $cmd_shown = $cmd;

    } else { // expert
        // Whitelist regex intended to allow only IPv4/hostnames, but it's
        // unanchored (no ^...$) so it just needs to CONTAIN a valid-looking
        // token anywhere in the string.
        if (preg_match('/[a-zA-Z0-9\.\-]+/', $host)) {
            $cmd = "ping -c 2 " . escapeshellcmd($host);
            $output = shell_exec($cmd . ' 2>&1');
            $cmd_shown = $cmd;
        } else {
            $output = "Rejected: host does not look valid.";
        }
    }
    log_activity($conn, $_SESSION['username'], "ran diagnostics on: $host");
}

include __DIR__ . '/../includes/header.php';
?>
<h2>Network Diagnostics</h2>
<p class="small">Ping a host from the server. (Mode: <?php echo htmlspecialchars($difficulty); ?>)</p>
<form method="POST">
    <label>Host</label>
    <input type="text" name="host" placeholder="e.g. 127.0.0.1" value="<?php echo htmlspecialchars(isset($_POST['host'])?$_POST['host']:''); ?>">
    <?php if ($difficulty === 'hard'): ?>
    <label>Ping options</label>
    <input type="text" name="opts" value="<?php echo htmlspecialchars(isset($_POST['opts'])?$_POST['opts']:'-c 2'); ?>">
    <?php endif; ?>
    <button type="submit">Run</button>
</form>
<?php if ($output !== ''): ?>
<h3>Output</h3>
<pre style="background:#111;color:#0f0;padding:14px;border-radius:4px;overflow:auto;"><?php echo htmlspecialchars($output); ?></pre>
<?php endif; ?>
<?php include __DIR__ . '/../includes/footer.php'; ?>
