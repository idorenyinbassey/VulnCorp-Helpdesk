<?php
require_once dirname(__FILE__) . '/../includes/auth.php';
require_once dirname(__FILE__) . '/../includes/db.php';
require_login();

$difficulty = get_difficulty($conn);
$msg = '';
$err = '';
$upload_dir = dirname(__FILE__) . '/../uploads/';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['avatar'])) {
    $file = $_FILES['avatar'];
    $orig_name = basename($file['name']);
    $tmp = $file['tmp_name'];

    if ($difficulty === 'simple') {
        // No validation whatsoever. Upload a .php file and browse to it directly.
        $dest = $upload_dir . $orig_name;
        if (move_uploaded_file($tmp, $dest)) {
            $msg = "Uploaded to " . app_base() . "/uploads/$orig_name";
        } else { $err = 'Upload failed.'; }

    } elseif ($difficulty === 'intermediate') {
        // "Validates" using the client-supplied Content-Type header, which is
        // fully attacker-controlled (trivial to forge with a proxy/curl).
        $allowed_mime = array('image/jpeg', 'image/png', 'image/gif');
        if (in_array($file['type'], $allowed_mime, true)) {
            $dest = $upload_dir . $orig_name;
            if (move_uploaded_file($tmp, $dest)) {
                $msg = "Uploaded to " . app_base() . "/uploads/$orig_name";
            } else { $err = 'Upload failed.'; }
        } else {
            $err = 'File type not allowed (checked via Content-Type header).';
        }

    } elseif ($difficulty === 'hard') {
        // Validates real image structure via getimagesize() - blocks plain
        // text/php files. BUT a polyglot file (valid GIF header + trailing
        // PHP payload) still passes this check, and the original extension
        // is kept, so shell.php with a GIF89a header inside will validate
        // AND execute as PHP if uploaded with a .php name.
        $info = @getimagesize($tmp);
        if ($info !== false) {
            $dest = $upload_dir . $orig_name;
            if (move_uploaded_file($tmp, $dest)) {
                $msg = "Uploaded to " . app_base() . "/uploads/$orig_name";
            } else { $err = 'Upload failed.'; }
        } else {
            $err = 'File does not look like a valid image.';
        }

    } else { // expert
        // Validates real image structure AND strips the original filename,
        // forcing a safe generated name with a fixed .png extension.
        // This closes the direct-upload RCE path (contrast with the tiers
        // above) - the point at expert tier is to see the fix, not bypass it.
        $info = @getimagesize($tmp);
        if ($info !== false) {
            $dest = $upload_dir . 'avatar_' . $_SESSION['user_id'] . '_' . time() . '.png';
            if (move_uploaded_file($tmp, $dest)) {
                $msg = 'Uploaded and stored securely.';
            } else { $err = 'Upload failed.'; }
        } else {
            $err = 'File does not look like a valid image.';
        }
    }
    if ($msg) { log_activity($conn, $_SESSION['username'], "uploaded avatar: $orig_name"); }
}

include dirname(__FILE__) . '/../includes/header.php';
?>
<h2>Upload Avatar</h2>
<?php if ($msg): ?><div class="notice"><?php echo htmlspecialchars($msg); ?></div><?php endif; ?>
<?php if ($err): ?><div class="error"><?php echo htmlspecialchars($err); ?></div><?php endif; ?>
<form method="POST" enctype="multipart/form-data">
    <label>Choose image</label>
    <input type="file" name="avatar" id="avatar-input">
    <div id="avatar-filename" class="small"></div>
    <img id="avatar-preview" style="display:none;max-width:160px;border-radius:6px;margin:8px 0;">
    <button type="submit">Upload</button>
</form>
<p class="small">Mode: <?php echo htmlspecialchars($difficulty); ?> — see README for what's validated at this tier.</p>
<?php include dirname(__FILE__) . '/../includes/footer.php'; ?>
