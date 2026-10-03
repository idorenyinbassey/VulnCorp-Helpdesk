<?php
// includes/simple_cache.php
//
// A minimal disk-based page cache for the Cache Poisoning module. Real
// CDNs/reverse-proxy caches key their cache entries by the request URL
// (path + query string) but, unless explicitly configured otherwise, do
// NOT vary the cache by request headers - that mismatch is the entire
// vulnerability class: anything an app reflects from an unkeyed header
// into a cached response gets baked into the page every subsequent
// visitor receives, until the entry expires or is overwritten.
//
// Used only by index.php's GET-render path (never the POST login
// handler, which the existing SQLi/brute-force login challenges depend
// on) - a failed-login error page must never be cached and served to an
// unrelated visitor.

define('SIMPLE_CACHE_DIR', dirname(__FILE__) . '/../cache');
define('SIMPLE_CACHE_TTL', 60); // seconds

function simple_cache_key($uri) {
    return SIMPLE_CACHE_DIR . '/' . md5($uri) . '.html';
}

// Returns the cached body for $uri if a fresh entry exists, else null.
// Keyed on the full request URI (path + query string) - exactly like a
// real cache, and exactly why a query-string cache-buster forces a
// fresh entry without that being a real fix.
function simple_cache_get($uri) {
    $path = simple_cache_key($uri);
    if (!is_file($path)) {
        return null;
    }
    if ((time() - filemtime($path)) > SIMPLE_CACHE_TTL) {
        return null; // stale
    }
    $body = @file_get_contents($path);
    return ($body !== false && $body !== '') ? $body : null;
}

// Writes $body to the cache for $uri. Writes to a uniquely-named temp
// file first, then rename()s it into place - rename() is atomic on the
// same filesystem (true since PHP 4, nothing PHP 5.2-specific here), so
// a concurrent reader never sees a half-written cache file.
function simple_cache_put($uri, $body) {
    if (!is_dir(SIMPLE_CACHE_DIR)) {
        @mkdir(SIMPLE_CACHE_DIR, 0777, true);
    }
    $final = simple_cache_key($uri);
    $tmp = $final . '.' . uniqid('', true) . '.tmp';
    if (@file_put_contents($tmp, $body) !== false) {
        @rename($tmp, $final);
    } else {
        @unlink($tmp);
    }
}
