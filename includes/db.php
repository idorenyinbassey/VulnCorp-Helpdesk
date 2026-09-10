<?php
// includes/db.php
// Intentionally minimal / weak-by-design lab app. See README.md before deploying.

require_once dirname(__FILE__) . '/compat.php';

$DB_HOST = 'localhost';
$DB_USER = 'root';        // change to a dedicated low-priv user if you prefer; see README
$DB_PASS = '';             // set this to match your MySQL root/user password on Metasploitable2
$DB_NAME = 'vulnapp';

$conn = mysqli_connect($DB_HOST, $DB_USER, $DB_PASS, $DB_NAME);
if (!$conn) {
    // Verbose errors are part of "simple" mode on purpose (info disclosure).
    die('Database connection failed: ' . mysqli_connect_error());
}

function get_difficulty($conn) {
    $res = mysqli_query($conn, "SELECT difficulty FROM settings LIMIT 1");
    if ($res && $row = mysqli_fetch_assoc($res)) {
        return $row['difficulty'];
    }
    return 'simple';
}

function log_activity($conn, $username, $action) {
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
    $stmt = mysqli_prepare($conn, "INSERT INTO activity_log (username, action, ip) VALUES (?, ?, ?)");
    mysqli_stmt_bind_param($stmt, 'sss', $username, $action, $ip);
    mysqli_stmt_execute($stmt);
}
