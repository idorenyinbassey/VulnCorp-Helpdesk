<?php
// admin/import_tickets.php - XXE module.
//
// A real, common helpdesk feature: bulk-import tickets from an XML
// export (most ticketing systems support exactly this for migrations).
// Admin-only.
require_once dirname(__FILE__) . '/../includes/auth.php';
require_once dirname(__FILE__) . '/../includes/db.php';
require_role('admin');

$difficulty = get_difficulty($conn);
$msg = '';
$imported = array();
$xml_input = isset($_POST['xml']) ? $_POST['xml'] : '';

function _import_dom_tickets($dom) {
    $out = array();
    foreach ($dom->getElementsByTagName('ticket') as $t) {
        $subject_nodes = $t->getElementsByTagName('subject');
        $message_nodes = $t->getElementsByTagName('message');
        $out[] = array(
            'subject' => $subject_nodes->length ? $subject_nodes->item(0)->textContent : '',
            'message' => $message_nodes->length ? $message_nodes->item(0)->textContent : '',
        );
    }
    return $out;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && trim($xml_input) !== '') {
    $tickets_to_import = array();

    if ($difficulty === 'simple') {
        // Classic XXE: no entity-loading protection at all. This is
        // PHP's own real default behavior on PHP versions before 8.0 -
        // what this app targets (see README) - so no code is needed to
        // make this vulnerable, only code is needed to FIX it (see
        // intermediate/hard below). A crafted <!DOCTYPE> defining an
        // external general entity can read any file the web server
        // process can read, reflected straight back into the imported
        // ticket's subject/message.
        $xml = @simplexml_load_string($xml_input);
        if ($xml) {
            foreach ($xml->ticket as $t) {
                $tickets_to_import[] = array('subject' => (string)$t->subject, 'message' => (string)$t->message);
            }
        }

    } elseif ($difficulty === 'intermediate') {
        // A common real-world misconception: switching to DOMDocument
        // "because it's the modern API," passing LIBXML_NOENT thinking
        // that sounds protective. It does the opposite - it tells the
        // parser to SUBSTITUTE entity references with their defined
        // values, which is exactly what XXE needs. Still fully
        // exploitable, just via a different-looking code path.
        $dom = new DOMDocument();
        if (@$dom->loadXML($xml_input, LIBXML_NOENT)) {
            $tickets_to_import = _import_dom_tickets($dom);
        }

    } else { // hard, expert
        // External entity loading disabled correctly - the direct
        // file-disclosure path above is closed at both tiers. What's
        // NOT wired up as a live exploit in this file (matching this
        // app's existing restraint around payloads too risky to run in
        // a shared classroom lab - see the command-injection module's
        // "confirm with a harmless command" guidance) is explained on
        // the Challenges page / README instead:
        //   hard:   blind/out-of-band XXE via a parameter entity that
        //           references an attacker-hosted external DTD, used to
        //           exfiltrate data through requests the attacker's own
        //           server logs - still possible even with the MAIN
        //           document's external entities disabled, since a
        //           parameter entity's own external reference is a
        //           separate code path many real-world fixes miss.
        //   expert: entity-expansion ("billion laughs") denial of
        //           service - deeply nested internal entity definitions
        //           that need no external resource at all, just exhaust
        //           memory/CPU expanding them.
        if (function_exists('libxml_disable_entity_loader')) {
            // No-op on PHP 8+ (removed there; entities are disabled by
            // default anyway) - kept for this app's PHP 5.x targets.
            @libxml_disable_entity_loader(true);
        }
        // Rejecting any <!DOCTYPE at all - not just trying to tune
        // resolveExternals/substituteEntities - is the actual reliable
        // fix here: DOMDocument's substituteEntities=false only changes
        // the tree shape (keeps an EntityReference node instead of
        // inlining text), but ->textContent still walks into that
        // subtree and reconstructs the substituted value anyway, so
        // entity definitions - internal or external - need to never be
        // parsed in the first place if they're not a feature this
        // import needs at all.
        if (!preg_match('/<!DOCTYPE/i', $xml_input)) {
            $dom = new DOMDocument();
            if (@$dom->loadXML($xml_input, LIBXML_NONET)) {
                $tickets_to_import = _import_dom_tickets($dom);
            }
        }
    }

    foreach ($tickets_to_import as $t) {
        if ($t['subject'] === '' && $t['message'] === '') { continue; }
        $stmt = mysqli_prepare($conn, "INSERT INTO tickets (user_id, subject, message) VALUES (?, ?, ?)");
        mysqli_stmt_bind_param($stmt, 'iss', $_SESSION['user_id'], $t['subject'], $t['message']);
        mysqli_stmt_execute($stmt);
        $imported[] = $t;
    }
    $msg = count($imported) . ' ticket(s) imported.';
}

include dirname(__FILE__) . '/../includes/header.php';
?>
<h2>Bulk Import Tickets (XML)</h2>
<p class="small">Paste an XML export to bulk-create tickets - the same migration pattern many real helpdesks support.</p>
<?php if ($msg): ?><div class="notice"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>

<form method="POST">
    <label>XML</label>
    <textarea name="xml" rows="10" style="font-family:monospace;" placeholder="&lt;tickets&gt;&lt;ticket&gt;&lt;subject&gt;...&lt;/subject&gt;&lt;message&gt;...&lt;/message&gt;&lt;/ticket&gt;&lt;/tickets&gt;"><?php echo htmlspecialchars($xml_input); ?></textarea>
    <button type="submit">Import</button>
</form>

<?php if (!empty($imported)): ?>
<h3>Imported</h3>
<table>
<tr><th>Subject</th><th>Message</th></tr>
<?php foreach ($imported as $t): ?>
<tr><td><?php echo htmlspecialchars($t['subject']); ?></td><td><?php echo htmlspecialchars($t['message']); ?></td></tr>
<?php endforeach; ?>
</table>
<?php endif; ?>

<?php include dirname(__FILE__) . '/../includes/footer.php'; ?>
