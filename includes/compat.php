<?php
// includes/compat.php
//
// Metasploitable2 ships PHP 5.2.4. This app targets that environment on
// purpose (see README), so anything from PHP 5.3+ needs a polyfill here
// instead of being used directly. Everything below is guarded with
// function_exists() so it's a no-op on any newer PHP that already has
// the real thing.

// hash_equals() - added in PHP 5.6. Constant-time string comparison,
// used for the CSRF token checks (support/tickets.php, admin/create_user.php,
// user/change_password.php).
if (!function_exists('hash_equals')) {
    function hash_equals($known_string, $user_string) {
        if (!is_string($known_string) || !is_string($user_string)) {
            return false;
        }
        $known_len = strlen($known_string);
        if ($known_len !== strlen($user_string)) {
            return false;
        }
        $result = 0;
        for ($i = 0; $i < $known_len; $i++) {
            $result |= (ord($known_string[$i]) ^ ord($user_string[$i]));
        }
        return $result === 0;
    }
}

// random_bytes() - added in PHP 7.0. Used for CSRF tokens and the
// expert-tier password-reset token. Reads /dev/urandom directly, which
// has been readable from PHP since PHP4 on any Linux box (Metasploitable2
// included) - no mcrypt/openssl extension required.
if (!function_exists('random_bytes')) {
    function random_bytes($length) {
        $length = (int)$length;
        if ($length < 1) { $length = 1; }

        if (@is_readable('/dev/urandom')) {
            $fh = @fopen('/dev/urandom', 'rb');
            if ($fh) {
                $bytes = fread($fh, $length);
                fclose($fh);
                if ($bytes !== false && strlen($bytes) === $length) {
                    return $bytes;
                }
            }
        }

        // Fallback if /dev/urandom isn't available for some reason. Not
        // cryptographically ideal, but keeps the lab functional rather
        // than fatal-erroring - this app's "weak" tiers already have
        // plenty of real vulnerabilities without this being one of them.
        $bytes = '';
        for ($i = 0; $i < $length; $i++) {
            $bytes .= chr(mt_rand(0, 255));
        }
        return $bytes;
    }
}

// mysqli_stmt_get_result() needs the mysqlnd driver, which many PHP5
// builds (including common Metasploitable2 setups) don't have compiled
// in. These two helpers get the same result - an array of associative
// rows - using mysqli_stmt_bind_result()/mysqli_stmt_fetch(), which has
// worked on every mysqli build since PHP5.0.

function stmt_fetch_all($stmt) {
    $rows = array();

    if (function_exists('mysqli_stmt_get_result')) {
        $res = @mysqli_stmt_get_result($stmt);
        if ($res !== false && $res !== null) {
            while ($row = mysqli_fetch_assoc($res)) {
                $rows[] = $row;
            }
            return $rows;
        }
        // If get_result exists but returned false (no mysqlnd despite the
        // function existing, seen on some builds), fall through to the
        // bind_result path below.
    }

    $meta = mysqli_stmt_result_metadata($stmt);
    if (!$meta) {
        return $rows;
    }

    $fields = array();
    while ($field = mysqli_fetch_field($meta)) {
        $fields[$field->name] = null;
    }
    mysqli_free_result($meta);

    $bind_args = array($stmt);
    foreach ($fields as $name => &$val) {
        $bind_args[] = &$fields[$name];
    }
    unset($val);
    call_user_func_array('mysqli_stmt_bind_result', $bind_args);

    while (mysqli_stmt_fetch($stmt)) {
        $row = array();
        foreach ($fields as $name => $val) {
            $row[$name] = $val;
        }
        $rows[] = $row;
    }

    return $rows;
}

function stmt_fetch_one($stmt) {
    $rows = stmt_fetch_all($stmt);
    return isset($rows[0]) ? $rows[0] : null;
}
