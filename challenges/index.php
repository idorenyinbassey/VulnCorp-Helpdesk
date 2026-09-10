<?php
require_once dirname(__FILE__) . '/../includes/auth.php';
require_once dirname(__FILE__) . '/../includes/db.php';
require_login();
$difficulty = get_difficulty($conn);

// ---------------------------------------------------------------
// Challenge definitions. Each entry maps to a real vuln in this app.
// "tools" lists the legitimate pentest tooling suited to the task.
// "steps" are the methodology a student follows.
// "clue" is a revealable hint, not the full payload — students should
// have to reason the last step out themselves.
// ---------------------------------------------------------------
$challenges = array(

'simple' => array(
    array(
        'title' => 'Auth Bypass 101',
        'module' => 'Login',
        'target' => '/index.php',
        'objective' => 'Log in as admin without knowing the password.',
        'tools' => array('Browser', 'Burp Suite (or curl)'),
        'steps' => array(
            'Try a single quote in the username field and see if the app errors out — that tells you the query is unsanitized.',
            'Think about what the login query probably looks like: <code>... WHERE username = \'$username\' AND password = MD5(\'$password\')</code>.',
            'Craft a username that makes the WHERE clause always true, and comment out the rest of the query.',
        ),
        'clue' => 'A classic payload ends a string early with a quote, then comments out everything after it with <code>-- </code> (note the trailing space).',
    ),
    array(
        'title' => 'Dump the Users Table',
        'module' => 'Login (UNION SQLi)',
        'target' => '/index.php',
        'objective' => 'Extract every username and password hash from the database through the login form alone.',
        'tools' => array('Burp Suite', 'sqlmap'),
        'steps' => array(
            'Confirm the injection point (see Auth Bypass 101).',
            'Work out the column count the SELECT returns (hint: it is <code>*</code> from <code>users</code>).',
            'Use a UNION SELECT to pull data into a field the page reflects back to you — or just point sqlmap at the POST request and let it enumerate.',
        ),
        'clue' => 'sqlmap usage: capture the login POST in Burp, save it as a .req file, then run <code>sqlmap -r login.req -p username --dump</code>.',
    ),
    array(
        'title' => 'Steal a Session', 'module' => 'Ticket Stored XSS', 'target' => '/user/tickets.php',
        'objective' => 'Get a script to execute in another user\'s browser when they view your ticket.',
        'tools' => array('Browser DevTools', 'Burp Suite'),
        'steps' => array(
            'Submit a ticket where the subject or message contains a <code>&lt;script&gt;</code> tag.',
            'View "My Tickets" and confirm the alert fires.',
            'Consider: a support agent reads every ticket in the queue — what does that make this ticket?',
        ),
        'clue' => 'In a real engagement you would swap <code>alert(1)</code> for something that exfiltrates <code>document.cookie</code> to a listener you control.',
    ),
    array(
        'title' => 'Peek at Someone Else\'s Data', 'module' => 'Profile IDOR', 'target' => '/user/profile.php',
        'objective' => 'View and edit another user\'s profile while logged in as a low-privilege user.',
        'tools' => array('Browser'),
        'steps' => array(
            'Log in as alice and open your own profile — note the URL parameter.',
            'Change that parameter to another user\'s ID.',
            'Notice what extra field is visible on this tier that should never be shown to another user.',
        ),
        'clue' => 'IDs are small sequential integers — you don\'t need a scanner, just count.',
    ),
    array(
        'title' => 'Get a Shell', 'module' => 'Admin Diagnostics — Command Injection', 'target' => '/admin/diagnostics.php',
        'objective' => 'Get the server to run an arbitrary OS command via the ping tool (admin account required).',
        'tools' => array('Browser', 'Burp Suite', 'netcat (for the bonus reverse shell)'),
        'steps' => array(
            'Submit a normal host value first and confirm the ping output.',
            'Append a shell metacharacter after a valid host to chain a second command.',
            'Confirm code execution with a harmless command before trying anything destructive.',
        ),
        'clue' => 'Semicolons, <code>&&</code>, and pipes all chain shell commands on Linux. Try <code>127.0.0.1; id</code>.',
    ),
    array(
        'title' => 'Upload a Web Shell', 'module' => 'Avatar Upload', 'target' => '/user/upload.php',
        'objective' => 'Get server-side PHP code execution via the avatar upload feature.',
        'tools' => array('Browser', 'a one-line PHP web shell for testing'),
        'steps' => array(
            'Upload a file ending in <code>.php</code> and see if it\'s accepted.',
            'Browse directly to <code>/uploads/&lt;your-filename&gt;</code>.',
            'Confirm your PHP executed rather than being displayed as text.',
        ),
        'clue' => 'A minimal test payload is <code>&lt;?php echo "pwned"; ?&gt;</code> — you don\'t need a full shell to prove the bug.',
    ),
    array(
        'title' => 'Take Over Any Account', 'module' => 'Change Password', 'target' => '/user/change_password.php',
        'objective' => 'As a low-privilege user, change another account\'s password without knowing it.',
        'tools' => array('Browser or Burp Suite'),
        'steps' => array(
            'Log in as alice and open Change Password — note there\'s no "current password" field at this tier.',
            'Add <code>?id=&lt;another user\'s id&gt;</code> to the URL.',
            'Submit a new password and confirm you can now log in as that user.',
        ),
        'clue' => 'Bob is user id 4 in the seed data — try <code>change_password.php?id=4</code>.',
    ),
    array(
        'title' => 'Guess the Reset Token', 'module' => 'Forgot Password', 'target' => '/user/forgot_password.php',
        'objective' => 'Reset someone else\'s password without ever seeing the reset link the app "sends" them.',
        'tools' => array('Browser or a scratch script to compute an MD5'),
        'steps' => array(
            'Submit the forgot-password form for a known username and look at the generated token.',
            'The token isn\'t random at this tier — work out what two pieces of public information it\'s built from.',
            'Compute the same token yourself for a *different* username, without ever requesting a reset for that account, and use it directly at <code>/user/reset_password.php?token=...</code>.',
        ),
        'clue' => 'At this tier the token is just <code>md5(username)</code> — no secret, no time component.',
    ),
    array(
        'title' => 'Silent Backdoor Admin', 'module' => 'Create User (CSRF)', 'target' => '/admin/create_user.php',
        'objective' => 'Get an admin to create a new admin account without them intending to, by getting them to load a page you control.',
        'tools' => array('Browser', 'a scratch HTML file'),
        'steps' => array(
            'Build a minimal auto-submitting HTML form pointed at <code>/admin/create_user.php</code> with <code>username</code>, <code>password</code>, <code>full_name</code>, <code>email</code>, and <code>role=admin</code> fields.',
            'While logged in as <code>admin</code> in one tab, open your crafted page in another tab.',
            'Log out, then log in with the credentials you set — confirm you now have a second, fully independent admin account.',
        ),
        'clue' => 'Same PoC shape as a CSRF form: <code>&lt;form action="http://TARGET/admin/create_user.php" method="POST"&gt;...fields...&lt;/form&gt;&lt;script&gt;document.forms[0].submit()&lt;/script&gt;</code> (replace TARGET with the app\'s actual host/path — e.g. <code>192.168.1.3/vulnapp</code> if that\'s how it\'s deployed). This is the highest-impact bug in the whole simple tier — full persistent admin access, and the admin never clicked "create user."',
    ),
),

'intermediate' => array(
    array(
        'title' => 'Bypass the Keyword Filter', 'module' => 'Login', 'target' => '/index.php',
        'objective' => 'The app now strips lowercase <code>union</code>, <code>select</code>, <code>--</code>, <code>#</code>, <code>;</code> from the username. Bypass auth anyway.',
        'tools' => array('Burp Suite'),
        'steps' => array(
            'Re-send your Auth Bypass 101 payload and confirm it now fails.',
            'Check whether the filter is case-sensitive by testing a single blocked keyword in mixed case.',
            'Note the filter never touches the OR logic itself — only certain keywords.',
        ),
        'clue' => 'The blacklist targets specific words, not logic operators — you may not even need <code>UNION</code>/<code>SELECT</code> for an auth bypass, only for data extraction.',
    ),
    array(
        'title' => 'XSS Past the Blacklist', 'module' => 'Ticket Stored XSS', 'target' => '/user/tickets.php',
        'objective' => 'The app now strips <code>&lt;script&gt;</code> tags (case-insensitively). Get JS to execute anyway.',
        'tools' => array('Browser DevTools', 'PortSwigger XSS cheat sheet (public reference)'),
        'steps' => array(
            'Confirm <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> is now neutered.',
            'Recall that XSS doesn\'t require the word "script" at all — event handlers fire JS too.',
            'Try an image tag with a broken source and an error handler, or an SVG with an onload handler.',
        ),
        'clue' => '<code>&lt;img src=x onerror=alert(1)&gt;</code> contains no <code>&lt;script&gt;</code> substring.',
    ),
    array(
        'title' => 'Forged MIME Type Upload', 'module' => 'Avatar Upload', 'target' => '/user/upload.php',
        'objective' => 'The app now checks the file\'s Content-Type — but only the header the browser sends, which you control.',
        'tools' => array('Burp Suite (Repeater)'),
        'steps' => array(
            'Try uploading a .php file normally and confirm it\'s now rejected.',
            'Intercept the upload request in Burp before it hits the server.',
            'Edit the <code>Content-Type</code> part of the multipart body for your file to a value the app allows, without changing the actual file content.',
        ),
        'clue' => 'The filename and the Content-Type field are two separate things in a multipart form — the app only ever checks the latter.',
    ),
    array(
        'title' => 'Cross-Case Command Injection', 'module' => 'Admin Diagnostics', 'target' => '/admin/diagnostics.php',
        'objective' => 'Semicolons, <code>&&</code>, and <code>||</code> are now stripped. Get command execution anyway.',
        'tools' => array('Browser', 'Burp Suite'),
        'steps' => array(
            'Confirm your simple-tier payload is now blocked.',
            'The filter is a fixed list of separators — think of other ways Linux shells chain or substitute commands.',
            'Backticks and <code>$()</code> both let you run a command inside another command\'s arguments.',
        ),
        'clue' => 'Try <code>127.0.0.1 `id`</code> or <code>127.0.0.1 $(id)</code>.',
    ),
    array(
        'title' => 'Verify Yourself, Hijack Someone Else', 'module' => 'Change Password', 'target' => '/user/change_password.php',
        'objective' => 'The form now asks for your current password. Find the mismatch between what gets checked and what gets changed.',
        'tools' => array('Browser or Burp Suite'),
        'steps' => array(
            'Confirm you can no longer change another user\'s password without a current-password value.',
            'Try entering YOUR OWN current password, but keep the <code>?id=</code> parameter pointed at someone else.',
            'Check whether the account that actually gets modified matches the account whose password you verified.',
        ),
        'clue' => 'Many real apps have this exact bug: the check is "does this password match the logged-in user," but the update statement blindly trusts a separate ID parameter for which row to modify.',
    ),
    array(
        'title' => 'Date-Based Token Guessing', 'module' => 'Forgot Password', 'target' => '/user/forgot_password.php',
        'objective' => 'The reset token is no longer just <code>md5(username)</code>. Figure out the new formula and reset an account anyway.',
        'tools' => array('Browser or a scratch script'),
        'steps' => array(
            'Request a reset for a known username and compare the resulting token against the simple-tier formula — it won\'t match anymore.',
            'Consider what OTHER piece of information, entirely public, might now be mixed in.',
            'Recompute the token for a target account using today\'s date, and use it without ever triggering a reset request for that account.',
        ),
        'clue' => 'Token = <code>md5(username . date(\'Y-m-d\'))</code> — you know the date without asking anyone.',
    ),
),

'hard' => array(
    array(
        'title' => 'Forge a Remember-Me Cookie', 'module' => 'Login (secondary surface)', 'target' => '/index.php (cookie: remember_token)',
        'objective' => 'The login form itself is now fully parameterized. Find the SQLi that got left behind elsewhere in the auth flow.',
        'tools' => array('Burp Suite'),
        'steps' => array(
            'Register interest in "Remember me" — log in normally with it checked and inspect the cookie you get back.',
            'Think about what else in this app reads a cookie value straight into a query. (Hint: re-read includes/db.php and index.php together, or just test it.)',
            'Try sending a crafted <code>remember_token</code> cookie on a fresh, logged-out session.',
        ),
        'clue' => 'If a value from a cookie is dropped into <code>WHERE session_token = \'$token\'</code> unescaped, a <code>\' OR 1=1 -- </code>-style payload in the cookie itself logs you in as the first user returned.',
    ),
    array(
        'title' => 'Reflected XSS via Search', 'module' => 'Tickets', 'target' => '/user/tickets.php?q=',
        'objective' => 'Ticket subject/body are now safely encoded. Find where user input still comes back unescaped.',
        'tools' => array('Browser', 'Burp Suite'),
        'steps' => array(
            'Try your intermediate-tier XSS payload in a ticket subject/message and confirm it\'s now escaped.',
            'Look at every other place on the page that reflects something you control — including the search box.',
            'View source after searching for something distinctive to see exactly how your input lands in the HTML.',
        ),
        'clue' => 'The search term is placed inside an HTML attribute (<code>value="..."</code>) — you don\'t need a script tag, you need to close the attribute and the input tag first.',
    ),
    array(
        'title' => 'The Endpoint They Forgot', 'module' => 'Profile — Broken Access Control', 'target' => '/user/profile_export.php',
        'objective' => 'Direct profile viewing/editing is now locked to your own account. Find the endpoint where that fix wasn\'t applied.',
        'tools' => array('Burp Suite (or a directory/endpoint wordlist + ffuf)'),
        'steps' => array(
            'Confirm <code>/user/profile.php?id=&lt;someone else&gt;</code> now 403s.',
            'This app has more than one way to read profile data — think about "export", "API", "download" style naming conventions developers commonly add later.',
            'Try the same IDOR technique against that endpoint instead.',
        ),
        'clue' => 'Check <code>/user/profile_export.php?id=4</code>.',
    ),
    array(
        'title' => 'Split-Parameter Command Injection', 'module' => 'Admin Diagnostics', 'target' => '/admin/diagnostics.php',
        'objective' => 'The host field is now properly escaped. There\'s a second field on this form now — is it?',
        'tools' => array('Browser', 'Burp Suite'),
        'steps' => array(
            'Try injecting into the host field directly and confirm <code>escapeshellarg()</code> now neutralizes it.',
            'Notice the form grew an extra "ping options" field in this mode — check whether that one is escaped too.',
            'Craft an "options" value that appends a second command after the legitimate ping options.',
        ),
        'clue' => 'The options field is concatenated into the shell command as-is, right before your (safely escaped) host — so put your injection at the *end* of the options value.',
    ),
    array(
        'title' => 'Polyglot Upload', 'module' => 'Avatar Upload', 'target' => '/user/upload.php',
        'objective' => 'The app now validates real image structure with <code>getimagesize()</code>. Get PHP execution anyway.',
        'tools' => array('exiftool or a hex editor', 'Browser'),
        'steps' => array(
            'Confirm a plain <code>.php</code> file is now rejected by <code>getimagesize()</code>.',
            'Build a file that starts with a valid image header (so <code>getimagesize()</code> is satisfied) but also contains PHP code.',
            'Save/upload that file with a <code>.php</code> extension — the app keeps whatever extension you give it at this tier.',
        ),
        'clue' => 'A GIF89a header is only 6 bytes: <code>GIF89a</code>. Prepend it to a one-line PHP payload and upload the result as <code>shell.php</code>.',
    ),
    array(
        'title' => 'Timing-Window Token Guessing', 'module' => 'Forgot Password', 'target' => '/user/forgot_password.php',
        'objective' => 'The token now depends on a unix timestamp, not the date. Reset an account by racing the clock instead of guessing a fixed value.',
        'tools' => array('Burp Intruder or a small script'),
        'steps' => array(
            'Trigger a reset request for a target account and note roughly what time you did it.',
            'Compute <code>md5(username . timestamp)</code> for every timestamp in a small window around that moment (a few seconds either direction covers request latency).',
            'Try each candidate token against <code>/user/reset_password.php?token=...</code> until one works.',
        ),
        'clue' => 'This is the same idea as the simple/intermediate tokens, just with a much smaller, timing-dependent search space instead of zero search space — the fix (expert tier) is real entropy, not a bigger secret.',
    ),
),

'expert' => array(
    array(
        'title' => 'No More SQLi — Break In Anyway', 'module' => 'Login', 'target' => '/index.php',
        'objective' => 'Every query is parameterized and there\'s no info leakage. The path in is credential/session attack, not injection.',
        'tools' => array('Hydra or Burp Intruder', 'a small wordlist'),
        'steps' => array(
            'Confirm there is no lockout after repeated failed logins.',
            'Given the seed account naming pattern in this lab, build a small candidate password list.',
            'Run an online brute-force against the login form and see how long an unthrottled login endpoint survives.',
        ),
        'clue' => 'This is exactly the class of finding you\'d write up as "Missing Rate Limiting on Authentication Endpoint" in a real bounty report — the vulnerable behavior isn\'t a payload, it\'s an absence of a control.',
    ),
    array(
        'title' => 'Attribute-Injection XSS', 'module' => 'Ticket Signature Sanitizer', 'target' => 'includes/render.php: naive_allowlist_sanitize()',
        'objective' => 'The app allows a small set of "safe" HTML tags (b, i, a) in one field via an allowlist sanitizer. Break out of it.',
        'tools' => array('Browser', 'source review — this one\'s a white-box challenge'),
        'steps' => array(
            'Read <code>naive_allowlist_sanitize()</code> in <code>includes/render.php</code> directly — this challenge is meant to be solved by reading the sanitizer\'s logic, the same way you\'d review a client\'s code in a source-available bounty program.',
            'Notice what the function checks for on an <code>&lt;a&gt;</code> tag, and what it does NOT check for.',
            'Craft an <code>&lt;a&gt;</code> tag that contains an <code>href</code> attribute (to satisfy the check) alongside an event-handler attribute (which the check never inspects).',
        ),
        'clue' => 'The function only confirms the substring "href" exists somewhere in the tag\'s attributes — it never validates that ONLY href is present.',
    ),
    array(
        'title' => 'Privilege Escalation via Mass Assignment', 'module' => 'Profile Update', 'target' => '/user/profile.php',
        'objective' => 'The profile form the browser renders has no role field for regular users. Become admin anyway.',
        'tools' => array('Burp Suite (Repeater)'),
        'steps' => array(
            'Log in as a regular user and submit a normal profile update; capture the POST request in Burp.',
            'Think about what the server-side handler does with fields it wasn\'t expecting — does it only save what the form shows, or everything submitted?',
            'Add a parameter to the captured request that the visible form never includes, with the value you want.',
        ),
        'clue' => 'Add <code>&amp;role=admin</code> to the POST body and resend.',
    ),
    array(
        'title' => 'CSRF the Support Queue', 'module' => 'Support Ticket Status', 'target' => '/support/tickets.php',
        'objective' => 'Below this tier, ticket status changes have no CSRF protection at all. At expert, prove you understand why the token stops it.',
        'tools' => array('Browser', 'a scratch HTML file'),
        'steps' => array(
            'Set the mode to <strong>hard</strong> temporarily and build a minimal auto-submitting HTML form pointed at <code>/support/tickets.php</code> with <code>ticket_id</code> and <code>status</code> fields, hosted anywhere.',
            'While logged in as <code>sam</code> in one browser tab, open your crafted page in another and confirm the ticket status changes without sam ever visiting the real app for that action.',
            'Switch the mode to <strong>expert</strong> and repeat the exact same PoC — confirm it now fails, and explain in your own write-up why the token defeats it.',
        ),
        'clue' => 'A minimal PoC is: <code>&lt;form action="http://TARGET/support/tickets.php" method="POST"&gt;&lt;input name="ticket_id" value="1"&gt;&lt;input name="status" value="closed"&gt;&lt;/form&gt;&lt;script&gt;document.forms[0].submit()&lt;/script&gt;</code> — this is a defensive PoC pattern, the same one you\'d include in a real CSRF bug report.',
    ),
    array(
        'title' => 'Confirm the Backdoor Is Closed', 'module' => 'Create User (CSRF)', 'target' => '/admin/create_user.php',
        'objective' => 'Re-run the "Silent Backdoor Admin" PoC from the simple tier against this tier and confirm it now fails — then explain why in one paragraph.',
        'tools' => array('Browser', 'the same scratch HTML file from the simple-tier challenge'),
        'steps' => array(
            'Reuse (or rebuild) the auto-submitting form that targeted <code>/admin/create_user.php</code> on the simple tier.',
            'With the app in expert mode and logged in as admin, load the page and confirm no account is created — look for the specific error the server returns.',
            'Write one paragraph explaining, in report-style language, why the token stops a request the browser would otherwise happily send with valid session cookies attached.',
        ),
        'clue' => 'The response should say "CSRF token invalid — request rejected." The key point for your write-up: the attacker\'s page can forge the request and the cookies ride along automatically, but it can\'t read the token out of your session to include it — that\'s the whole defense.',
    ),
),
);

// ---------------------------------------------------------------
// Recon & Discovery challenges — these run against THIS lab
// (the VulnCorp app + the Metasploitable2 box it sits on). Unlike
// the tier challenges above, these aren't gated by difficulty mode —
// recon is step zero regardless of what tier you're about to attack.
// ---------------------------------------------------------------
$recon = array(
    array(
        'title' => 'Map the Attack Surface', 'module' => 'Port & Service Scan', 'target' => 'the Metasploitable2 host itself',
        'objective' => 'Before touching this app, find out what else is listening on the box and confirm which port/path VulnCorp is actually on.',
        'tools' => array('nmap'),
        'steps' => array(
            'Run a full TCP port scan with service/version detection against the Metasploitable2 IP: <code>nmap -sV -p- &lt;target-ip&gt;</code>.',
            'Note every open port and guessed service/version — Metasploitable2 intentionally runs many other vulnerable services alongside this app.',
            'Confirm which port/path Apache is serving VulnCorp on (check against the vhost or subfolder you deployed to).',
        ),
        'clue' => 'A quick first pass with just <code>nmap -sV &lt;target-ip&gt;</code> (top 1000 ports) is usually enough to orient yourself before committing to a slower full-range scan.',
    ),
    array(
        'title' => 'Fingerprint the Stack', 'module' => 'Tech Fingerprinting', 'target' => 'http(s)://&lt;target&gt;/vulnapp/',
        'objective' => 'Identify the framework/language/server without being told — this shapes which vuln classes you\'d even bother testing for.',
        'tools' => array('whatweb', 'Wappalyzer (browser extension)', 'curl -I'),
        'steps' => array(
            'Run <code>whatweb http://&lt;target&gt;/vulnapp/</code> and note what it reports for server, language, and any detected framework.',
            'Cross-check with response headers manually: <code>curl -I http://&lt;target&gt;/vulnapp/index.php</code> — look at <code>Server</code> and <code>X-Powered-By</code>.',
            'Compare what you find against what you already know from the README — does recon confirm it, or find something extra (e.g. the Apache/MySQL versions Metasploitable2 ships)?',
        ),
        'clue' => 'An old, verbose <code>X-Powered-By: PHP/5.x</code>-style header is itself a finding worth noting in a real assessment — it tells you the PHP version, which narrows down which known CVEs might apply.',
    ),
    array(
        'title' => 'Find the Endpoints Nobody Linked To', 'module' => 'Content/Directory Discovery', 'target' => '/vulnapp/',
        'objective' => 'This app has at least one working endpoint that\'s never linked from any page or menu. Find it through brute-forcing, not by reading the source.',
        'tools' => array('dirb or gobuster or ffuf', 'a common wordlist (e.g. SecLists common.txt)'),
        'steps' => array(
            'Run a directory/file brute-force against the app root: <code>dirb http://&lt;target&gt;/vulnapp/</code> (or <code>ffuf -u http://&lt;target&gt;/vulnapp/FUZZ.php -w wordlist.txt</code>).',
            'Also brute-force inside the <code>user/</code> and <code>admin/</code> subfolders specifically — a flat wordlist run at the root alone will miss endpoints nested a level down.',
            'For every hit, check if it requires auth, what HTTP methods it accepts, and whether it behaves differently for different roles.',
        ),
        'clue' => 'This is exactly how you\'d discover the endpoint used in the Hard-tier "The Endpoint They Forgot" challenge below — if you find it here first, you\'ve already done half of that challenge.',
    ),
    array(
        'title' => 'Crawl the App Like a User Would', 'module' => 'Application Mapping', 'target' => '/vulnapp/',
        'objective' => 'Build a full map of pages, forms, parameters, and roles before you start testing any single bug class.',
        'tools' => array('Burp Suite (Proxy + Spider/Crawler)', 'hakrawler'),
        'steps' => array(
            'Set your browser to proxy through Burp, then click through the app logged in as each of the four seeded accounts in turn.',
            'In Burp\'s site map, note every distinct URL, every form and its parameters, and where the app branches by role (what admin sees that user/support don\'t, and vice versa).',
            'Write down the session mechanism in use (cookie-based PHP session here) and where the difficulty tier actually lives (server-side setting, not a client-side flag).',
        ),
        'clue' => 'Pay attention to which pages exist but return a 403 for your current role — that tells you forced-browsing / access-control testing is worth doing there later.',
    ),
    array(
        'title' => 'Quick Misconfig Sweep', 'module' => 'Baseline Scan', 'target' => '/vulnapp/',
        'objective' => 'Run a general-purpose scanner to catch anything obvious before manual testing — this is a sanity check, not the main event.',
        'tools' => array('Nikto'),
        'steps' => array(
            'Run <code>nikto -h http://&lt;target&gt;/vulnapp/</code> and review the output.',
            'Cross-reference any findings against what you already mapped by hand — Nikto is good at catching things like missing security headers or leftover files, but won\'t find the app-specific logic bugs (IDOR, mass assignment) this lab is really about.',
            'Decide which findings are worth pursuing manually vs. noise.',
        ),
        'clue' => 'Automated scanners are a starting point, not a substitute — everything interesting in this lab (the IDOR, the mass assignment, the CSRF) needs a human to reason about app logic.',
    ),
);

// ---------------------------------------------------------------
// Reference methodology — general bug bounty workflow, not tied to
// this lab's difficulty tiers. Useful as a checklist for real
// (authorized) engagements once these fundamentals feel comfortable.
// ---------------------------------------------------------------
$methodology = array(
    array('phase' => 'Phase 1 — Recon & Scoping', 'rows' => array(
        array('1.1', 'Read the program scope (in-scope domains, excluded endpoints, safe-harbor rules) before touching anything', 'HackerOne / Bugcrowd program page'),
        array('1.2', 'Passive recon — subdomains, DNS, WHOIS, cert transparency, Google dorks, Wayback Machine', 'amass, subfinder, crt.sh, theHarvester'),
        array('1.3', 'Active recon — port scan, tech fingerprinting, WAF/CDN detection', 'nmap, wappalyzer, whatweb, httpx'),
        array('1.4', 'Check for subdomain takeover (dead CNAMEs pointing to unclaimed SaaS)', 'subzy, chaos'),
    )),
    array('phase' => 'Phase 2 — Application Mapping', 'rows' => array(
        array('2.1', 'Crawl/spider every page, form, parameter, API endpoint', 'Burp Suite Spider, ffuf, hakrawler'),
        array('2.2', 'Identify user roles, auth flows, session mechanism (cookie vs JWT)', 'Manual + Burp'),
        array('2.3', 'Extract endpoints/params from JS files, robots.txt, sitemap.xml, API docs', 'jsbeautifier, ParamSpider, arjun'),
        array('2.4', 'Note tech stack (framework, language, CMS, CDN, WAF)', 'wappalyzer, response headers'),
    )),
);
$vuln_categories = array(
    array('Injection', 'SQLi, XSS (reflected/stored/DOM), SSTI, command injection, XXE, NoSQLi'),
    array('Broken Auth', 'Default creds, password reset flaws, 2FA bypass, session fixation, JWT issues'),
    array('Access Control', 'IDOR, horizontal/vertical privilege escalation, forced browsing, BOLA'),
    array('Business Logic', 'Race conditions, workflow bypass, price manipulation, coupon abuse'),
    array('File Upload', 'Web shells, extension bypass, path traversal, content-type spoofing'),
    array('SSRF', 'Internal IP access, cloud metadata (169.254.169.254), protocol smuggling'),
    array('CSRF', 'Missing/weak tokens, method change (POST→GET)'),
    array('Info Disclosure', 'Exposed .git/.env, verbose errors, API keys in source, directory listing'),
    array('Misconfig', 'CORS, security headers, open redirects, verbose errors, debug endpoints'),
    array('API-specific', 'Mass assignment, broken object-level auth, rate limiting, GraphQL introspection'),
    array('Client-side', 'Clickjacking, DOM XSS, prototype pollution, postMessage flaws'),
    array('Advanced', 'HTTP smuggling, deserialization, host header injection, cache poisoning'),
);
$reporting_fields = array(
    array('Title', 'Clear, specific (e.g. "IDOR in /api/v1/orders/{id} allows order data theft")'),
    array('Severity', 'CVSS 3.1 score + justification'),
    array('Steps to reproduce', 'Numbered, copy-pasteable'),
    array('PoC', 'Request/response, video, or script'),
    array('Impact', 'Business-level consequence (data breach, financial loss, etc.)'),
    array('Remediation', 'Suggested fix'),
);

$tier_order = array('simple', 'intermediate', 'hard', 'expert');
$tier_labels = array(
    'simple' => 'Simple',
    'intermediate' => 'Intermediate',
    'hard' => 'Hard',
    'expert' => 'Expert',
);

function challenge_slug($prefix, $title) {
    return $prefix . '-' . preg_replace('/[^a-z0-9]+/', '-', strtolower($title));
}

include dirname(__FILE__) . '/../includes/header.php';
?>
<h2>Challenges</h2>
<p class="small">These map directly to the vulnerabilities live in this app right now. The app's current mode is
<strong><?php echo htmlspecialchars($difficulty); ?></strong> — challenges for other tiers are shown for reference,
but you'll need an admin to flip the mode (Admin Panel → Difficulty Settings) to actually attempt them.</p>

<div style="display:flex;justify-content:space-between;align-items:center;background:#f8fafc;border:1px solid #e5e7eb;border-radius:6px;padding:10px 16px;margin-bottom:16px;">
    <span id="challenge-progress-counter" class="small">0 solved</span>
    <button type="button" id="challenge-progress-reset" class="btn" style="background:#6b7280;padding:5px 12px;font-size:12px;">Reset progress</button>
</div>

<div class="notice">
<strong>Ground rules for this lab:</strong> only attack this app and hosts you're explicitly authorized to test.
The methodology here — enumerate, hypothesize, test the smallest possible payload, confirm impact, write it up —
is exactly what a real bug bounty triage expects, whether the target is this lab or a live program.
</div>

<h3 style="margin-top:34px;">Phase 0 — Recon &amp; Discovery <span class="small">(do this first, any tier)</span></h3>
<p class="small">Not gated by difficulty — run these against the lab before you start on any tier below. Several of the harder challenges are much easier if you've already mapped the app here.</p>
<?php foreach ($recon as $c):
    $cid = challenge_slug('recon', $c['title']);
?>
<div class="challenge-card" style="border:1px solid #e5e7eb;border-radius:6px;padding:14px 18px;margin-bottom:14px;background:#fff;transition:opacity .2s;">
    <label style="display:flex;align-items:flex-start;gap:8px;cursor:pointer;">
        <input type="checkbox" class="challenge-progress-box" data-challenge-id="<?php echo htmlspecialchars($cid); ?>" style="width:auto;margin-top:4px;">
        <span>
    <strong><?php echo htmlspecialchars($c['title']); ?></strong>
    <span class="small"> — <?php echo htmlspecialchars($c['module']); ?> · target: <code><?php echo $c['target']; ?></code></span>
        </span>
    </label>
    <p><?php echo $c['objective']; ?></p>
    <p class="small"><strong>Tools:</strong> <?php echo htmlspecialchars(implode(', ', $c['tools'])); ?></p>
    <ol>
        <?php foreach ($c['steps'] as $s): ?><li><?php echo $s; ?></li><?php endforeach; ?>
    </ol>
    <details>
        <summary>Reveal clue</summary>
        <p><?php echo $c['clue']; ?></p>
    </details>
</div>
<?php endforeach; ?>


<?php foreach ($tier_order as $tier):
    $is_current = ($tier === $difficulty);
?>
<h3 style="margin-top:34px;<?php if($is_current) echo 'color:#2563eb;'; ?>">
    <?php echo htmlspecialchars($tier_labels[$tier]); ?> tier
    <?php if ($is_current): ?><span class="small">(active now)</span><?php endif; ?>
</h3>

<?php foreach ($challenges[$tier] as $c):
    $cid = challenge_slug($tier, $c['title']);
?>
<div class="challenge-card" style="border:1px solid #e5e7eb;border-radius:6px;padding:14px 18px;margin-bottom:14px;background:<?php echo $is_current ? '#f8fafc' : '#fff'; ?>;transition:opacity .2s;">
    <label style="display:flex;align-items:flex-start;gap:8px;cursor:pointer;">
        <input type="checkbox" class="challenge-progress-box" data-challenge-id="<?php echo htmlspecialchars($cid); ?>" style="width:auto;margin-top:4px;">
        <span>
    <strong><?php echo htmlspecialchars($c['title']); ?></strong>
    <span class="small"> — <?php echo htmlspecialchars($c['module']); ?> · target: <code><?php echo htmlspecialchars($c['target']); ?></code></span>
        </span>
    </label>
    <p><?php echo $c['objective']; // contains inline <code> markup by design ?></p>
    <p class="small"><strong>Tools:</strong> <?php echo htmlspecialchars(implode(', ', $c['tools'])); ?></p>
    <ol>
        <?php foreach ($c['steps'] as $s): ?><li><?php echo $s; // inline <code> markup by design ?></li><?php endforeach; ?>
    </ol>
    <details>
        <summary>Reveal clue</summary>
        <p><?php echo $c['clue']; // inline <code> markup by design ?></p>
    </details>
</div>
<?php endforeach; ?>
<?php endforeach; ?>

<h3 style="margin-top:44px;">Reference: General Bug Bounty Methodology</h3>
<p class="small">Not lab-specific — this is the workflow to carry into real (authorized) engagements once the
fundamentals above feel comfortable. Phase 1's passive-recon tools (amass, subfinder, crt.sh, theHarvester) target
public subdomains/DNS on a live program's scope — they don't apply to this local lab's single internal host, but
they're listed here because they're step one on a real target.</p>

<?php foreach ($methodology as $block): ?>
<h4 style="margin-top:22px;"><?php echo htmlspecialchars($block['phase']); ?></h4>
<table>
<tr><th style="width:50px;">Step</th><th>What you do</th><th>Tools</th></tr>
<?php foreach ($block['rows'] as $r): ?>
<tr><td><?php echo htmlspecialchars($r[0]); ?></td><td><?php echo htmlspecialchars($r[1]); ?></td><td><code><?php echo htmlspecialchars($r[2]); ?></code></td></tr>
<?php endforeach; ?>
</table>
<?php endforeach; ?>

<h4 style="margin-top:22px;">Phase 3 — Vulnerability Testing (test systematically through each category)</h4>
<table>
<tr><th style="width:30px;">#</th><th>Category</th><th>Key things to test</th></tr>
<?php foreach ($vuln_categories as $i => $v): ?>
<tr><td><?php echo $i + 1; ?></td><td><strong><?php echo htmlspecialchars($v[0]); ?></strong></td><td><?php echo htmlspecialchars($v[1]); ?></td></tr>
<?php endforeach; ?>
</table>
<p class="small">This app currently exercises rows 1, 3, 5, 7, and 10 (Injection, Access Control, File Upload, CSRF, API/mass-assignment) — the rest are worth knowing for real targets even though they're not modeled here yet.</p>

<h4 style="margin-top:22px;">Phase 4 — Exploitation &amp; Validation</h4>
<ul>
    <li>Prove impact — don't just flag a finding; demonstrate real-world consequence (RCE, data exfil, account takeover).</li>
    <li>Build a reproducible PoC (request + response, video, or script).</li>
    <li>Bypass filters if needed — for this lab, that means the intermediate/hard/expert-tier bypass techniques above; on a live target it means understanding the specific control you're up against, not evading a defender's monitoring.</li>
    <li>Chain vulnerabilities if a single one is low-impact (e.g. this lab's stored XSS + support-agent-reads-every-ticket is a chain worth calling out explicitly in a write-up).</li>
</ul>

<h4 style="margin-top:22px;">Phase 5 — Reporting</h4>
<table>
<tr><th>Element</th><th>What to include</th></tr>
<?php foreach ($reporting_fields as $f): ?>
<tr><td><strong><?php echo htmlspecialchars($f[0]); ?></strong></td><td><?php echo htmlspecialchars($f[1]); ?></td></tr>
<?php endforeach; ?>
</table>
<p class="small">Good practice: write a one-paragraph report for at least one challenge you solve in this lab, using this exact template, before you ever do it against a live program.</p>

<?php include dirname(__FILE__) . '/../includes/footer.php'; ?>
