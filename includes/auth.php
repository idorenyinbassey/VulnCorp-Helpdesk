<?php
// includes/auth.php
if (session_id() === '') {
    session_start();
}

function require_login() {
    if (!isset($_SESSION['user_id'])) {
        header('Location: /index.php');
        exit;
    }
}

// NOTE: In "simple" and "intermediate" tiers, role checks like this exist on
// the page itself but pages are still directly reachable by guessing the
// URL (broken access control / forced browsing) — that's intentional.
function require_role($roles) {
    require_login();
    if (!in_array($_SESSION['role'], (array)$roles)) {
        header('HTTP/1.1 403 Forbidden');
        echo "<h2>403 Forbidden</h2><p>Your role (" . htmlspecialchars($_SESSION['role']) . ") cannot access this page.</p>";
        echo '<a href="/dashboard.php">Back to dashboard</a>';
        exit;
    }
}
