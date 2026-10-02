<?php
// includes/jwt.php
//
// Hand-rolled HS256 JSON Web Token encode/verify for the "API Token (JWT)
// Auth" module (api/auth_token.php, api/ticket_update.php, and the
// Bearer-token path added to api/tickets.php). No external library is
// needed - hash_hmac('sha256', ...) has existed since PHP 5.1.2, so this
// runs unmodified on Metasploitable2's PHP 5.2.4, same as the rest of
// this app.
//
// The signing secret is generated randomly per install (see
// db_setup.sql's settings.jwt_secret, read via get_jwt_secret() in
// includes/db.php) - it is NOT a fixed value anywhere in this source
// file, so "read the secret out of the repo" is never the intended path
// for any challenge built on this file. Every JWT bug in this app is a
// verification-logic bug (alg confusion, missing expiry, no revocation),
// never a guessable secret - see challenges/index.php and README.md.

require_once dirname(__FILE__) . '/compat.php';

function _jwt_b64url_encode($data) {
    return rtrim(str_replace(array('+', '/'), array('-', '_'), base64_encode($data)), '=');
}

function _jwt_b64url_decode($data) {
    $remainder = strlen($data) % 4;
    if ($remainder) {
        $data .= str_repeat('=', 4 - $remainder);
    }
    return base64_decode(str_replace(array('-', '_'), array('+', '/'), $data));
}

// Always issues a correctly-signed HS256 token - issuance isn't where
// this module's bugs live; verification is (see jwt_verify() below).
function jwt_encode($payload, $secret) {
    $header = array('typ' => 'JWT', 'alg' => 'HS256');
    $segments = array(
        _jwt_b64url_encode(json_encode($header)),
        _jwt_b64url_encode(json_encode($payload)),
    );
    $signing_input = implode('.', $segments);
    $signature = hash_hmac('sha256', $signing_input, $secret, true);
    $segments[] = _jwt_b64url_encode($signature);
    return implode('.', $segments);
}

// Parses header+payload WITHOUT checking the signature at all. Used
// internally by jwt_verify() to see the caller's claimed 'alg' before
// deciding how (or whether) to verify - and by the always-vulnerable
// CTF branch in api/ticket_update.php, which calls this directly and
// never calls jwt_verify() at all. That "forgot to call the shared check"
// shape is the same pattern as this app's other forgotten-endpoint bugs
// (user/profile_export.php, the tickets API's list-mode gap).
function jwt_decode_unsafe($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) {
        return null;
    }
    $header = json_decode(_jwt_b64url_decode($parts[0]), true);
    $payload = json_decode(_jwt_b64url_decode($parts[1]), true);
    if (!is_array($header) || !is_array($payload)) {
        return null;
    }
    return array(
        'header' => $header,
        'payload' => $payload,
        'signature' => $parts[2],
        'signing_input' => $parts[0] . '.' . $parts[1],
    );
}

// Tiered verification - see README.md / challenges/index.php for the one
// deliberate bug left at each difficulty tier. Returns the decoded
// payload array on success, or null if the token is rejected.
function jwt_verify($token, $secret, $difficulty) {
    $decoded = jwt_decode_unsafe($token);
    if ($decoded === null) {
        return null;
    }
    $header = $decoded['header'];
    $payload = $decoded['payload'];
    $alg = isset($header['alg']) ? $header['alg'] : '';

    if ($difficulty === 'simple') {
        // No alg restriction at all - 'none' skips the signature check
        // entirely below. Classic forgeable-token bug: a caller can hand-
        // craft a token with any claims they like and no signature.
        if ($alg === 'none') {
            return $payload;
        }

    } elseif ($difficulty === 'intermediate') {
        // Blocks the literal, exact string 'none' - but the comparison
        // is case-sensitive, so 'None'/'NONE' slips straight past it,
        // landing in the same no-signature-check bypass as simple mode.
        if ($alg === 'none') {
            return null;
        }
        if (strcasecmp($alg, 'none') === 0) {
            return $payload;
        }

    } elseif ($difficulty === 'hard') {
        // Alg confusion is fully closed here - a case-insensitive
        // HS256-only allowlist, with a real signature check below. But
        // 'exp' is never inspected anywhere in this branch, so a
        // captured/leaked token - including one past its intended
        // lifetime - stays valid forever.
        if (strcasecmp($alg, 'HS256') !== 0) {
            return null;
        }

    } else { // expert
        if (strcasecmp($alg, 'HS256') !== 0) {
            return null;
        }
    }

    // Reached by every tier once alg is accepted as HS256 (every tier
    // besides the forged-token bypasses above): verify the HMAC for real.
    $expected_sig = hash_hmac('sha256', $decoded['signing_input'], $secret, true);
    if (!hash_equals(_jwt_b64url_encode($expected_sig), $decoded['signature'])) {
        return null;
    }

    if ($difficulty === 'expert') {
        if (!isset($payload['exp']) || (int)$payload['exp'] < time()) {
            return null;
        }
        // Even here: nothing anywhere checks whether the account's
        // password has changed since this token was issued - there is no
        // revocation mechanism at any tier. That absence is the expert-
        // tier finding once alg confusion and missing expiry are both
        // fixed: change your password via user/change_password.php, then
        // replay a token issued before the change - it still works.
    }
    // hard tier: the signature is genuinely valid, but 'exp' (if present
    // in the payload) is deliberately never checked above - see the
    // comment in that branch.

    return $payload;
}
