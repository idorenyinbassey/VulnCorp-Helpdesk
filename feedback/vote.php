<?php
// feedback/vote.php - records a one-click "how was this challenge" vote.
// Built correctly on purpose - this is trainer tooling, not part of the
// lab's intentional vulnerabilities.
require_once dirname(__FILE__) . '/../includes/auth.php';
require_once dirname(__FILE__) . '/../includes/db.php';
require_login();

$valid_ratings = array('too_easy', 'just_right', 'too_hard', 'stuck');

if ($_SERVER['REQUEST_METHOD'] === 'POST'
    && isset($_POST['challenge_id'], $_POST['rating'])
    && in_array($_POST['rating'], $valid_ratings, true)) {

    $username = $_SESSION['username'];
    $challenge_id = $_POST['challenge_id'];
    $rating = $_POST['rating'];

    $stmt = mysqli_prepare($conn,
        "INSERT INTO challenge_feedback (username, challenge_id, rating) VALUES (?, ?, ?)
         ON DUPLICATE KEY UPDATE rating = VALUES(rating)");
    mysqli_stmt_bind_param($stmt, 'sss', $username, $challenge_id, $rating);
    mysqli_stmt_execute($stmt);
}

$return_to = isset($_POST['return_to']) ? $_POST['return_to'] : (app_base() . '/challenges/index.php');
// Only ever redirect back within this app as a plain relative path -
// never trust an arbitrary external value here, unlike the lab's own
// open-redirect module elsewhere in this app.
if (strpos($return_to, '/') !== 0 || strpos($return_to, '//') === 0 || strpos($return_to, '://') !== false) {
    $return_to = app_base() . '/challenges/index.php';
}
$anchor = isset($_POST['challenge_id']) ? '#feedback-' . preg_replace('/[^a-z0-9\-]/', '', strtolower($_POST['challenge_id'])) : '';
header('Location: ' . $return_to . $anchor);
exit;
