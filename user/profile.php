<?php
require_once dirname(__FILE__) . '/../includes/auth.php';
require_once dirname(__FILE__) . '/../includes/db.php';
require_login();

$difficulty = get_difficulty($conn);
$view_id = isset($_GET['id']) ? (int)$_GET['id'] : (int)$_SESSION['user_id'];
$msg = '';
$err = '';

// ---- Access control: this is where the IDOR / mass-assignment vuln lives ----
$owns_profile = ($view_id === (int)$_SESSION['user_id']);

if ($difficulty === 'simple' || $difficulty === 'intermediate') {
    // No ownership check at all: any logged-in user can view/edit ANY id.
    $allowed_to_view = true;
    $allowed_to_edit = true;
} elseif ($difficulty === 'hard') {
    // View/edit here IS restricted to your own profile...
    $allowed_to_view = $owns_profile || $_SESSION['role'] === 'admin';
    $allowed_to_edit = $owns_profile || $_SESSION['role'] === 'admin';
    // ...but see profile_export.php, which forgets this check entirely.
} else { // expert
    $allowed_to_view = $owns_profile || $_SESSION['role'] === 'admin';
    $allowed_to_edit = $owns_profile || $_SESSION['role'] === 'admin';
}

if (!$allowed_to_view) {
    header('HTTP/1.1 403 Forbidden');
    include dirname(__FILE__) . '/../includes/header.php';
    echo '<h2>403 Forbidden</h2><p>You can only view your own profile in this mode.</p>';
    include dirname(__FILE__) . '/../includes/footer.php';
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $allowed_to_edit) {
    $full_name = $_POST['full_name'];
    $email = $_POST['email'];

    if ($difficulty === 'expert' && isset($_POST['role']) && $_SESSION['role'] !== 'admin') {
        // Mass assignment: the form below doesn't normally show a role field to
        // non-admins, but the server does not strip an unexpected 'role' param
        // if one is submitted directly (e.g. via curl/Burp) -> privilege escalation.
        $role = $_POST['role'];
        $stmt = mysqli_prepare($conn, "UPDATE users SET full_name=?, email=?, role=? WHERE id=?");
        mysqli_stmt_bind_param($stmt, 'sssi', $full_name, $email, $role, $view_id);
        mysqli_stmt_execute($stmt);
        if ($view_id === (int)$_SESSION['user_id']) { $_SESSION['role'] = $role; }
        $msg = 'Profile updated.';
    } elseif ($difficulty === 'simple') {
        // String concatenation update (secondary SQLi surface on full_name field).
        $sql = "UPDATE users SET full_name = '$full_name', email = '$email' WHERE id = $view_id";
        if (mysqli_query($conn, $sql)) { $msg = 'Profile updated.'; }
        else { $err = mysqli_error($conn); }
    } else {
        $stmt = mysqli_prepare($conn, "UPDATE users SET full_name=?, email=? WHERE id=?");
        mysqli_stmt_bind_param($stmt, 'ssi', $full_name, $email, $view_id);
        mysqli_stmt_execute($stmt);
        $msg = 'Profile updated.';
    }
    log_activity($conn, $_SESSION['username'], "updated profile id=$view_id");
}

$res = mysqli_query($conn, "SELECT * FROM users WHERE id = " . (int)$view_id);
$profile = $res ? mysqli_fetch_assoc($res) : null;

include dirname(__FILE__) . '/../includes/header.php';
?>
<h2>Profile <?php echo $owns_profile ? '(you)' : '#' . (int)$view_id; ?></h2>
<?php if ($msg): ?><div class="notice"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>
<?php if ($err): ?><div class="error">SQL error: <?php echo htmlspecialchars($err); ?></div><?php endif; ?>

<?php if (!$profile): ?>
<p>No such user.</p>
<?php else: ?>
<form method="POST">
    <label>Username</label>
    <input type="text" value="<?php echo htmlspecialchars($profile['username']); ?>" disabled>
    <label>Full name</label>
    <input type="text" name="full_name" value="<?php echo htmlspecialchars($profile['full_name']); ?>" <?php echo $allowed_to_edit?'':'disabled'; ?>>
    <label>Email</label>
    <input type="text" name="email" value="<?php echo htmlspecialchars($profile['email']); ?>" <?php echo $allowed_to_edit?'':'disabled'; ?>>
    <label>Role</label>
    <input type="text" value="<?php echo htmlspecialchars($profile['role']); ?>" disabled>
    <?php if ($difficulty === 'simple'): ?>
    <label>Password hash (exposed in simple mode — info disclosure)</label>
    <input type="text" value="<?php echo htmlspecialchars($profile['password']); ?>" disabled>
    <?php endif; ?>
    <?php if ($allowed_to_edit): ?><button type="submit">Save</button><?php endif; ?>
</form>
<p class="small">Try viewing other IDs by changing <code>?id=</code> in the URL.</p>
<?php endif; ?>
<?php include dirname(__FILE__) . '/../includes/footer.php'; ?>
