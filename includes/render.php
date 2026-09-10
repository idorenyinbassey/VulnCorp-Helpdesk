<?php
// includes/render.php
// Controls how user-supplied ticket text is rendered back to the page.
// This is the single knob that turns stored XSS on/off/filtered per tier.

function render_ticket_text($text, $difficulty) {
    if ($difficulty === 'simple') {
        // No encoding at all.
        return $text;
    }
    if ($difficulty === 'intermediate') {
        // Blacklist a couple of obvious tags, case-insensitively — but any
        // other tag/event-handler vector (img onerror, svg onload, etc.) still works.
        $bad = array('<script', '</script', 'javascript:');
        return str_ireplace($bad, '', $text);
    }
    // hard and expert: properly escaped. (Hard/expert XSS vectors in this
    // app live in the search reflection and the "signature" allowlist field
    // instead — see support/tickets.php and user/signature.php.)
    return htmlspecialchars($text, ENT_QUOTES);
}

// Naive allowlist sanitizer for the EXPERT-tier signature field.
// Intended to allow only <b>, <i>, <a href="..."> — but the attribute
// matching is sloppy and lets an attacker smuggle extra attributes
// (e.g. onmouseover=) inside a tag that otherwise looks allowed.
//
// PHP 5.2 compatibility note: this used to be a closure passed to
// preg_replace_callback(), but closures need PHP 5.3+. Metasploitable2
// ships PHP 5.2, so it's a named callback instead.
function _naive_allowlist_a_tag_callback($m) {
    // BUG: this happily keeps any attributes the original tag had,
    // including event handlers, as long as an href= substring is present.
    if (stripos($m[1], 'href') !== false) {
        return '<a ' . $m[1] . '>';
    }
    return '<a>';
}

function naive_allowlist_sanitize($html) {
    // Strip everything except a small tag allowlist...
    $allowed_tags = '<b><i><a>';
    $stripped = strip_tags($html, $allowed_tags);
    // ...then "restore" href attributes on <a> tags via regex, without
    // validating that nothing else is smuggled in alongside href.
    $stripped = preg_replace_callback('/<a\s+(.*?)>/i', '_naive_allowlist_a_tag_callback', $stripped);
    return $stripped;
}
