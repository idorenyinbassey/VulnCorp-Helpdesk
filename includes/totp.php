<?php
// includes/totp.php
//
// Hand-rolled RFC 6238 TOTP (and RFC 4226 HOTP underneath it) for the
// 2FA Bypass module, using hash_hmac('sha1', ...) - no external library
// needed, exactly the same "no library, build it by hand" precedent
// includes/jwt.php already set for this app's crypto-ish features.
// Secrets are stored base32-encoded (the universal convention real
// authenticator apps expect), generated randomly per account that opts
// in - never a fixed value in source, same reasoning as jwt_secret.

require_once dirname(__FILE__) . '/compat.php';

$GLOBALS['_totp_base32_alphabet'] = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function totp_generate_secret($byte_length = 20) {
    $alphabet = $GLOBALS['_totp_base32_alphabet'];
    $raw = random_bytes($byte_length);
    $secret = '';
    $bits = '';
    for ($i = 0; $i < strlen($raw); $i++) {
        $bits .= str_pad(decbin(ord($raw[$i])), 8, '0', STR_PAD_LEFT);
    }
    for ($i = 0; $i + 5 <= strlen($bits); $i += 5) {
        $secret .= $alphabet[bindec(substr($bits, $i, 5))];
    }
    return $secret;
}

function _totp_base32_decode($b32) {
    $alphabet = $GLOBALS['_totp_base32_alphabet'];
    $b32 = strtoupper(preg_replace('/[^A-Za-z2-7]/', '', $b32));
    $bits = '';
    for ($i = 0; $i < strlen($b32); $i++) {
        $pos = strpos($alphabet, $b32[$i]);
        if ($pos === false) { continue; }
        $bits .= str_pad(decbin($pos), 5, '0', STR_PAD_LEFT);
    }
    $raw = '';
    for ($i = 0; $i + 8 <= strlen($bits); $i += 8) {
        $raw .= chr(bindec(substr($bits, $i, 8)));
    }
    return $raw;
}

// RFC 4226 HOTP: a counter-based one-time code, the primitive TOTP sits on top of.
function _hotp_code($secret_raw, $counter, $digits = 6) {
    // pack() has no native 64-bit big-endian format in PHP 5.2's pack();
    // build the 8-byte big-endian counter by hand instead.
    $bin_counter = '';
    for ($i = 7; $i >= 0; $i--) {
        $bin_counter = chr($counter & 0xff) . $bin_counter;
        $counter = $counter >> 8;
    }
    $hash = hash_hmac('sha1', $bin_counter, $secret_raw, true);
    $offset = ord($hash[19]) & 0x0f;
    $truncated = ((ord($hash[$offset]) & 0x7f) << 24)
        | ((ord($hash[$offset + 1]) & 0xff) << 16)
        | ((ord($hash[$offset + 2]) & 0xff) << 8)
        | (ord($hash[$offset + 3]) & 0xff);
    $code = $truncated % pow(10, $digits);
    return str_pad($code, $digits, '0', STR_PAD_LEFT);
}

// RFC 6238 TOTP: HOTP with the counter derived from the current time,
// in 30-second steps - the format every real authenticator app uses.
function totp_code_at($secret_b32, $timestamp, $step = 30, $digits = 6) {
    $secret_raw = _totp_base32_decode($secret_b32);
    $counter = (int) floor($timestamp / $step);
    return _hotp_code($secret_raw, $counter, $digits);
}

// Verifies a submitted code against the current time step, allowing one
// step of clock drift either side (the standard real-world tolerance).
function totp_verify($secret_b32, $submitted_code, $step = 30, $digits = 6) {
    $now = time();
    for ($drift = -1; $drift <= 1; $drift++) {
        $expected = totp_code_at($secret_b32, $now + ($drift * $step), $step, $digits);
        if (hash_equals($expected, (string)$submitted_code)) {
            return true;
        }
    }
    return false;
}
