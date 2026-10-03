<?php
// support/escalation_approve.php - Business Logic module.
//
// The "approve/deny" half of the Request Escalation workflow (the
// request half lives in user/tickets.php, which handles simple/
// intermediate entirely itself - this file is only ever reached at
// hard/expert tier, once a real pending state exists).
require_once dirname(__FILE__) . '/../includes/auth.php';
require_once dirname(__FILE__) . '/../includes/db.php';
require_login();

$difficulty = get_difficulty($conn);

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['ticket_id'], $_POST['action'])) {
    $ticket_id = (int)$_POST['ticket_id'];
    $action = $_POST['action'];
    $is_staff = isset($_SESSION['role']) && in_array($_SESSION['role'], array('support', 'admin'), true);

    if ($difficulty === 'hard') {
        // No role check at all - this endpoint approves/denies for
        // ANY logged-in user, not just support/admin. A regular user
        // can self-approve their own pending escalation request by
        // POSTing here directly, bypassing the Support Queue UI (which
        // only support/admin can even see) entirely.
        $allowed = true;
    } else { // expert
        $allowed = $is_staff;
    }

    if ($allowed) {
        if ($action === 'approve') {
            mysqli_query($conn, "UPDATE tickets SET priority = 'urgent', escalation_status = 'approved' WHERE id = " . $ticket_id);
            log_activity($conn, $_SESSION['username'], "approved escalation for ticket #$ticket_id");
        } elseif ($action === 'deny') {
            mysqli_query($conn, "UPDATE tickets SET escalation_status = 'denied' WHERE id = " . $ticket_id);
            log_activity($conn, $_SESSION['username'], "denied escalation for ticket #$ticket_id");
        }
    }
}

header('Location: ' . app_base() . '/support/tickets.php');
exit;
