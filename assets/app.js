// assets/app.js
//
// Client-side UX polish ONLY. This file is deliberately NOT wired up to:
//   - /index.php (login form: username/password)
//   - /user/tickets.php, /support/tickets.php (ticket subject/message/search)
//   - /admin/diagnostics.php (host/opts fields)
//   - /user/profile.php (full_name/email fields)
// Those are the app's exploit surfaces for this lab (SQLi, XSS, command
// injection). They must reach the server exactly as typed, with zero
// client-side validation, formatting, filtering, or blocking. Every
// browser-side "validation" is trivially bypassed anyway (devtools, curl,
// Burp Repeater — the tools this lab's challenges already point students
// at) so adding it there would only teach the wrong lesson: that the
// bug is fixed when it isn't. If you extend this file, keep new behavior
// off the fields above.

document.addEventListener('DOMContentLoaded', function () {
    initPasswordMatch();
    initPasswordStrength();
    initAvatarPreview();
    initCreateUserHints();
    initChallengeProgress();
    initFlashDismiss();
});

// ---- Change Password (user/change_password.php): live match indicator ----
// Visual only — never disables the submit button, so the real server-side
// check (or lack of one, depending on tier) is still what actually decides
// whether the request succeeds.
function initPasswordMatch() {
    var np = document.getElementById('new_password');
    var cp = document.getElementById('confirm_password');
    var msg = document.getElementById('pw-match-msg');
    if (!np || !cp || !msg) return;
    function check() {
        if (!cp.value) { msg.textContent = ''; return; }
        if (np.value === cp.value) {
            msg.textContent = 'Passwords match.';
            msg.style.color = '#059669';
        } else {
            msg.textContent = 'Passwords do not match yet.';
            msg.style.color = '#dc2626';
        }
    }
    np.addEventListener('input', check);
    cp.addEventListener('input', check);
}

// ---- Change Password: cosmetic strength meter, informational only ----
function initPasswordStrength() {
    var np = document.getElementById('new_password');
    var meter = document.getElementById('pw-strength');
    if (!np || !meter) return;
    np.addEventListener('input', function () {
        var v = np.value;
        var score = 0;
        if (v.length >= 8) score++;
        if (/[A-Z]/.test(v)) score++;
        if (/[0-9]/.test(v)) score++;
        if (/[^A-Za-z0-9]/.test(v)) score++;
        var labels = ['Very weak', 'Weak', 'Okay', 'Good', 'Strong'];
        var colors = ['#dc2626', '#dc2626', '#d97706', '#2563eb', '#059669'];
        meter.textContent = v ? labels[score] : '';
        meter.style.color = colors[score] || '#666';
    });
}

// ---- Avatar upload (user/upload.php): local preview only ----
// Reads the file locally with FileReader purely to show a thumbnail.
// Does NOT check/restrict file type or extension — the upload tier's
// actual (weak) server-side validation is untouched by this.
function initAvatarPreview() {
    var input = document.getElementById('avatar-input');
    var preview = document.getElementById('avatar-preview');
    var label = document.getElementById('avatar-filename');
    if (!input || !preview) return;
    input.addEventListener('change', function () {
        var file = input.files && input.files[0];
        if (label) { label.textContent = file ? file.name : ''; }
        if (!file) { preview.style.display = 'none'; return; }
        if (file.type && file.type.indexOf('image/') === 0) {
            var reader = new FileReader();
            reader.onload = function (e) {
                preview.src = e.target.result;
                preview.style.display = 'block';
            };
            reader.readAsDataURL(file);
        } else {
            preview.style.display = 'none';
        }
    });
}

// ---- Create User (admin/create_user.php): non-blocking format hint ----
// Informational text only — the form still submits whatever was typed;
// the server does its own (tier-dependent) handling.
function initCreateUserHints() {
    var email = document.getElementById('cu-email');
    var hint = document.getElementById('cu-email-hint');
    if (!email || !hint) return;
    email.addEventListener('input', function () {
        var looksLikeEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value);
        hint.textContent = (email.value && !looksLikeEmail) ? "Doesn't look like a full email address yet." : '';
    });
}

// ---- Challenges page: local-only progress tracker ----
// Pure UX sugar — stored in this browser's localStorage, never sent to
// the server. Doesn't affect grading (there isn't any) or any exploit.
function initChallengeProgress() {
    var boxes = document.querySelectorAll('.challenge-progress-box');
    if (!boxes.length) return;
    var STORAGE_KEY = 'vulncorp_challenge_progress';
    var state = {};
    try { state = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}'); } catch (e) { state = {}; }

    function save() {
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(state)); } catch (e) {}
        updateCounter();
    }
    function updateCounter() {
        var counter = document.getElementById('challenge-progress-counter');
        if (!counter) return;
        var done = Object.keys(state).filter(function (k) { return state[k]; }).length;
        counter.textContent = done + ' / ' + boxes.length + ' marked solved (saved in this browser only)';
    }

    boxes.forEach(function (box) {
        var id = box.getAttribute('data-challenge-id');
        box.checked = !!state[id];
        var card = box.closest('.challenge-card');
        if (card && box.checked) { card.style.opacity = '0.55'; }
        box.addEventListener('change', function () {
            state[id] = box.checked;
            if (card) { card.style.opacity = box.checked ? '0.55' : '1'; }
            save();
        });
    });
    updateCounter();

    var resetBtn = document.getElementById('challenge-progress-reset');
    if (resetBtn) {
        resetBtn.addEventListener('click', function () {
            if (!confirm('Clear your local challenge progress? This only affects this browser.')) return;
            state = {};
            boxes.forEach(function (box) {
                box.checked = false;
                var card = box.closest('.challenge-card');
                if (card) { card.style.opacity = '1'; }
            });
            save();
        });
    }
}

// ---- Generic UX: let notice/error banners be dismissed by click ----
// Click-to-dismiss only (no auto-timeout) so nothing disappears before a
// student has read it — several of those banners carry exploit-relevant
// info (e.g. the raw SQL error text in simple-tier login) that must stay
// on screen until the student is done with it.
function initFlashDismiss() {
    var banners = document.querySelectorAll('.notice, .error');
    banners.forEach(function (b) {
        b.style.cursor = 'pointer';
        b.title = 'Click to dismiss';
        b.addEventListener('click', function () { b.style.display = 'none'; });
    });
}
