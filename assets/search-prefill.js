// assets/search-prefill.js
//
// DOM XSS module. This is a DELIBERATE, EXPLICIT exception to
// assets/app.js's "touches no exploit-relevant field" policy - see that
// file's own header comment. A DOM-based bug structurally needs a
// client-side sink that never sends the payload to the server at all,
// so it can't live in the same "stays off exploit surfaces" file as
// everything else. If you add another DOM-based module later, give it
// its own file too, for the same reason - don't fold it into app.js.
//
// Feature: a "deep link to a search" convenience on /user/tickets.php -
// visiting #q=<term> prefills a "Showing results for: ..." banner
// purely in the browser. The server never sees the URL fragment (that's
// what makes it a *fragment* - browsers never send it in the request at
// all), so none of this app's server-side XSS protections apply here;
// whatever renders this banner is the entire defense.

document.addEventListener('DOMContentLoaded', function () {
    var banner = document.getElementById('search-prefill-banner');
    if (!banner) {
        return; // not on a page that has this feature
    }

    var match = /(?:^|&)q=([^&]*)/.exec(window.location.hash.replace(/^#/, ''));
    if (!match) {
        return;
    }
    // decodeURIComponent throws on a malformed percent-sequence (e.g. a
    // bare "%" in the fragment) - that's a plain robustness bug, not part
    // of this module's intended vulnerability, so it's guarded here same
    // as any other untrusted-input parsing would be.
    var term;
    try {
        term = decodeURIComponent(match[1].replace(/\+/g, ' '));
    } catch (e) {
        return;
    }
    if (term === '') {
        return;
    }

    var difficulty = document.body.getAttribute('data-difficulty') || 'simple';
    renderPrefillBanner(banner, term, difficulty);
});

function renderPrefillBanner(banner, term, difficulty) {
    if (difficulty === 'simple') {
        // Raw innerHTML of unsanitized, attacker-controlled text - the
        // server never sees this value, so none of render_ticket_text()'s
        // PHP-side protections (at any tier) apply to it at all.
        banner.innerHTML = 'Showing results for: ' + term;

    } else if (difficulty === 'intermediate') {
        // Blacklists the literal substring "<script" (case-insensitive) -
        // the exact same gap as render_ticket_text()'s own intermediate
        // tier, just reimplemented client-side: event-handler attributes
        // on any other tag still fire, since the filter only recognizes
        // one specific tag name.
        var stripped = term.replace(/<script/gi, '');
        banner.innerHTML = 'Showing results for: ' + stripped;

    } else if (difficulty === 'hard') {
        // A naive client-side allowlist: keeps <a href="..."> but - like
        // naive_allowlist_sanitize() in includes/render.php - never checks
        // whether OTHER attributes are riding along next to a legitimate
        // href, so an onmouseover=... alongside a real href= still runs.
        var safe = term.replace(/<(?!\/?a\b)[^>]*>/gi, function (tag) {
            return /href\s*=/i.test(tag) ? tag : '';
        });
        banner.innerHTML = 'Showing results for: ' + safe;

    } else { // expert
        // textContent never interprets its input as markup at all -
        // closed, regardless of what the fragment contains.
        banner.textContent = 'Showing results for: ' + term;
    }
}
