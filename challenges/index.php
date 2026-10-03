<?php
require_once dirname(__FILE__) . '/../includes/auth.php';
require_once dirname(__FILE__) . '/../includes/db.php';
require_login();
$difficulty = get_difficulty($conn);

// This user's existing quick-votes, keyed by challenge_id, so already-voted
// challenges show their current choice instead of a blank widget.
$my_votes = array();
$stmt = mysqli_prepare($conn, "SELECT challenge_id, rating FROM challenge_feedback WHERE username = ?");
mysqli_stmt_bind_param($stmt, 's', $_SESSION['username']);
mysqli_stmt_execute($stmt);
foreach (stmt_fetch_all($stmt) as $v) {
    $my_votes[$v['challenge_id']] = $v['rating'];
}

function render_feedback_widget($cid, $my_votes) {
    $options = array(
        'too_easy' => 'Too easy',
        'just_right' => 'Just right',
        'too_hard' => 'Too hard',
        'stuck' => 'I got stuck',
    );
    $current = isset($my_votes[$cid]) ? $my_votes[$cid] : null;
    echo '<div class="small" style="margin-top:8px;padding-top:8px;border-top:1px dashed #e5e7eb;">';
    echo 'How was this one? ';
    foreach ($options as $val => $label) {
        $is_current = ($current === $val);
        echo '<form method="POST" action="' . htmlspecialchars(app_base()) . '/feedback/vote.php" style="display:inline;">';
        echo '<input type="hidden" name="challenge_id" value="' . htmlspecialchars($cid) . '">';
        echo '<input type="hidden" name="return_to" value="' . htmlspecialchars($_SERVER['REQUEST_URI']) . '">';
        echo '<button type="submit" name="rating" value="' . $val . '" class="btn" style="padding:3px 9px;font-size:11px;margin:2px 3px 2px 0;' . ($is_current ? 'background:#1e40af;' : 'background:#9ca3af;') . '">' . ($is_current ? '✓ ' : '') . $label . '</button>';
        echo '</form>';
    }
    echo '</div>';
}

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
        'difficulty' => 'Entry',
        'concept' => 'The login page builds a database query by gluing your input directly into a string of SQL code, instead of treating it as data. A single quote (<code>\'</code>) ends the text the app expected early, so anything after it gets read as part of the actual SQL command — including a condition like <code>OR \'1\'=\'1\'</code>, which is always true, and a comment marker that deletes the rest of the original query. This bug class is called SQL injection.',
        'tools' => array('Browser', 'Burp Suite (or curl)'),
        'steps' => array(
            'Try a single quote in the username field and see if the app errors out — that tells you the query is unsanitized.',
            'Think about what the login query probably looks like: <code>... WHERE username = \'$username\' AND password = MD5(\'$password\')</code>.',
            'Craft a username that makes the WHERE clause always true, and comment out the rest of the query.',
        ),
        'hints' => array(
            'nudge' => 'Try typing a single quote into the username field first — see what the app does with it before trying a full payload.',
            'answer' => 'A classic payload ends a string early with a quote, then comments out everything after it with <code>-- </code> (note the trailing space).',
        ),
    ),
    array(
        'title' => 'Dump the Users Table',
        'module' => 'Login (UNION SQLi)',
        'target' => '/index.php',
        'objective' => 'Extract every username and password hash from the database through the login form alone.',
        'difficulty' => 'Standard',
        'concept' => 'A UNION SELECT lets you stack a second, attacker-chosen query onto the one the app intended, as long as both return the same number of columns. Whatever your second query returns lands in the same output the app was already going to show you — so if the page ever echoes back part of the result (a username, a welcome message), you can redirect that output to leak rows from a totally different table, like <code>users</code>.',
        'tools' => array('Burp Suite', 'sqlmap'),
        'steps' => array(
            'Confirm the injection point (see Auth Bypass 101).',
            'Work out the column count the SELECT returns (hint: it is <code>*</code> from <code>users</code>).',
            'Use a UNION SELECT to pull data into a field the page reflects back to you — or just point sqlmap at the POST request and let it enumerate.',
        ),
        'hints' => array(
            'nudge' => 'You already know quotes break the query — now think about how to make the *broken* query return extra data instead of just skipping the password check.',
            'answer' => 'sqlmap usage: capture the login POST in Burp, save it as a .req file, then run <code>sqlmap -r login.req -p username --dump</code>.',
        ),
    ),
    array(
        'title' => 'Steal a Session', 'module' => 'Ticket Stored XSS', 'target' => '/user/tickets.php',
        'objective' => 'Get a script to execute in another user\'s browser when they view your ticket.',
        'difficulty' => 'Entry',
        'concept' => 'A browser can\'t tell the difference between "text the app wants to display" and "code the app wants to run" — it just executes any <code>&lt;script&gt;</code> tag it finds in the HTML it receives, no matter where that HTML came from. If the app saves your ticket text to the database and later prints it back into a page without neutralizing it first, your script becomes part of that page for every single person who views it — that\'s what "stored" means here: written once, executed for everyone afterward.',
        'tools' => array('Browser DevTools', 'Burp Suite'),
        'steps' => array(
            'Submit a ticket where the subject or message contains a <code>&lt;script&gt;</code> tag.',
            'View "My Tickets" and confirm the alert fires.',
            'Consider: a support agent reads every ticket in the queue — what does that make this ticket?',
        ),
        'hints' => array(
            'nudge' => 'Just try submitting a ticket with an ordinary HTML tag in it — does the app show it back to you as plain text, or as a real tag the browser renders?',
            'answer' => 'In a real engagement you would swap <code>alert(1)</code> for something that exfiltrates <code>document.cookie</code> to a listener you control.',
        ),
    ),
    array(
        'title' => 'Peek at Someone Else\'s Data', 'module' => 'Profile IDOR', 'target' => '/user/profile.php',
        'objective' => 'View and edit another user\'s profile while logged in as a low-privilege user.',
        'difficulty' => 'Entry',
        'concept' => 'The page decides whose data to show based on an ID number sitting right there in the URL — but it never checks whether that ID actually belongs to the person asking. This is an Insecure Direct Object Reference (IDOR): the app trusts that you\'ll only ever request your own ID, instead of verifying it server-side. Anything a client can see or type, a client can change.',
        'tools' => array('Browser'),
        'steps' => array(
            'Log in as alice and open your own profile — note the URL parameter.',
            'Change that parameter to another user\'s ID.',
            'Notice what extra field is visible on this tier that should never be shown to another user.',
        ),
        'hints' => array(
            'nudge' => 'Look at your own profile URL first — is there a number in it you could simply change?',
            'answer' => 'IDs are small sequential integers — you don\'t need a scanner, just count.',
        ),
    ),
    array(
        'title' => 'Get a Shell', 'module' => 'Admin Diagnostics — Command Injection', 'target' => '/admin/diagnostics.php',
        'objective' => 'Get the server to run an arbitrary OS command via the ping tool (admin account required).',
        'difficulty' => 'Standard',
        'concept' => 'To run the actual <code>ping</code> program, the server has to build a real shell command as text and hand it to the operating system — and if your input gets pasted into that text unmodified, you\'re not just supplying a hostname, you\'re supplying part of the command line itself. Characters like <code>;</code> or <code>&amp;&amp;</code> mean "and now run this next command" to a Linux shell, so anything after one of them executes with whatever permissions the web server has.',
        'tools' => array('Browser', 'Burp Suite', 'netcat (for the bonus reverse shell)'),
        'steps' => array(
            'Submit a normal host value first and confirm the ping output.',
            'Append a shell metacharacter after a valid host to chain a second command.',
            'Confirm code execution with a harmless command before trying anything destructive.',
        ),
        'hints' => array(
            'nudge' => 'The ping tool has to actually run a real system command behind the scenes — what happens if your input contains something a shell would treat as "end this command, start a new one"?',
            'answer' => 'Semicolons, <code>&&</code>, and pipes all chain shell commands on Linux. Try <code>127.0.0.1; id</code>.',
        ),
    ),
    array(
        'title' => 'Upload a Web Shell', 'module' => 'Avatar Upload', 'target' => '/user/upload.php',
        'objective' => 'Get server-side PHP code execution via the avatar upload feature.',
        'difficulty' => 'Standard',
        'concept' => 'A web server decides how to handle a file almost entirely by its extension — a <code>.jpg</code> gets served as an image, a <code>.php</code> file gets *executed* by the PHP interpreter and its output sent to you. If the app saves whatever you upload into a folder the web server can run scripts from, and never checks that it\'s actually an image, you\'ve just given the server a program to run on your behalf.',
        'tools' => array('Browser', 'a one-line PHP web shell for testing'),
        'steps' => array(
            'Upload a file ending in <code>.php</code> and see if it\'s accepted.',
            'Browse directly to <code>/uploads/&lt;your-filename&gt;</code>.',
            'Confirm your PHP executed rather than being displayed as text.',
        ),
        'hints' => array(
            'nudge' => 'Think about what actually decides whether the server treats an uploaded file as a picture versus as a program to run.',
            'answer' => 'A minimal test payload is <code>&lt;?php echo "pwned"; ?&gt;</code> — you don\'t need a full shell to prove the bug.',
        ),
    ),
    array(
        'title' => 'Take Over Any Account', 'module' => 'Change Password', 'target' => '/user/change_password.php',
        'objective' => 'As a low-privilege user, change another account\'s password without knowing it.',
        'difficulty' => 'Entry',
        'concept' => 'Same underlying idea as the IDOR above, applied somewhere more dangerous: the password-change form reads which account to update from a URL parameter, and never confirms that account is the one you\'re logged in as. Combine "no ownership check" with "no requirement to prove you know the old password" and the form will happily overwrite anyone\'s credentials on request.',
        'tools' => array('Browser or Burp Suite'),
        'steps' => array(
            'Log in as alice and open Change Password — note there\'s no "current password" field at this tier.',
            'Add <code>?id=&lt;another user\'s id&gt;</code> to the URL.',
            'Submit a new password and confirm you can now log in as that user.',
        ),
        'hints' => array(
            'nudge' => 'This form asks for a new password — does it ever ask you to prove which account you\'re changing?',
            'answer' => 'Bob is user id 4 in the seed data — try <code>change_password.php?id=4</code>.',
        ),
    ),
    array(
        'title' => 'Guess the Reset Token', 'module' => 'Forgot Password', 'target' => '/user/forgot_password.php',
        'objective' => 'Reset someone else\'s password without ever seeing the reset link the app "sends" them.',
        'difficulty' => 'Standard',
        'concept' => 'A password reset link is only as safe as the token inside it — that token is supposed to be an unguessable secret proving "yes, this person really does control that account." If the app builds the token out of information that isn\'t secret at all (like the username by itself), anyone who can do the same math the server does can produce a valid token for any account, without ever intercepting an email or a real reset request.',
        'tools' => array('Browser or a scratch script to compute an MD5'),
        'steps' => array(
            'Submit the forgot-password form for a known username and look at the generated token.',
            'The token isn\'t random at this tier — work out what two pieces of public information it\'s built from.',
            'Compute the same token yourself for a *different* username, without ever requesting a reset for that account, and use it directly at <code>/user/reset_password.php?token=...</code>.',
        ),
        'hints' => array(
            'nudge' => 'The reset link contains a token in the URL — ask yourself what information the server actually had available when it built that token.',
            'answer' => 'At this tier the token is just <code>md5(username)</code> — no secret, no time component.',
        ),
    ),
    array(
        'title' => 'Silent Backdoor Admin', 'module' => 'Create User (CSRF)', 'target' => '/admin/create_user.php',
        'objective' => 'Get an admin to create a new admin account without them intending to, by getting them to load a page you control.',
        'difficulty' => 'Stretch',
        'concept' => 'Your browser automatically attaches your saved login cookies to every request it sends to a site — including requests triggered by a page that isn\'t the site itself, like a form on an attacker\'s page that auto-submits to VulnCorp the moment it loads. The server has no way to tell "the admin clicked a button on our site" apart from "the admin\'s browser was tricked into sending this request," unless the form includes a secret, unpredictable token the attacker\'s page could never have known. Without that token, the cookies alone are enough. This is Cross-Site Request Forgery (CSRF).',
        'tools' => array('Browser', 'a scratch HTML file'),
        'steps' => array(
            'Build a minimal auto-submitting HTML form pointed at <code>/admin/create_user.php</code> with <code>username</code>, <code>password</code>, <code>full_name</code>, <code>email</code>, and <code>role=admin</code> fields.',
            'While logged in as <code>admin</code> in one tab, open your crafted page in another tab.',
            'Log out, then log in with the credentials you set — confirm you now have a second, fully independent admin account.',
        ),
        'hints' => array(
            'nudge' => 'This one isn\'t about payloads in a form field — it\'s about getting someone else\'s browser to submit a form on your behalf. What gets sent along automatically with every request a logged-in browser makes?',
            'answer' => 'Same PoC shape as a CSRF form: <code>&lt;form action="http://TARGET/admin/create_user.php" method="POST"&gt;...fields...&lt;/form&gt;&lt;script&gt;document.forms[0].submit()&lt;/script&gt;</code> (replace TARGET with the app\'s actual host/path — e.g. <code>192.168.1.3/vulnapp</code> if that\'s how it\'s deployed). This is the highest-impact bug in the whole simple tier — full persistent admin access, and the admin never clicked "create user."',
        ),
    ),
    array(
        'title' => 'Phish via the Login Page', 'module' => 'Open Redirect', 'target' => '/index.php?redirect=',
        'objective' => 'Get the login page to send a freshly-authenticated user to a site you control, right after they log in.',
        'difficulty' => 'Entry',
        'concept' => 'A "log in, then send me back where I was" redirect is extremely common in real apps (SSO flows, "continue to checkout" links) — and if the destination comes straight from a URL parameter with no validation, the app will happily send a user\'s browser anywhere at all immediately after they\'ve proven their identity. That combination (trusted login page + attacker-chosen destination) is exactly what makes open redirects useful for phishing: the link itself points at the real, trusted domain, so it looks completely safe right up until the moment it redirects.',
        'tools' => array('Browser'),
        'steps' => array(
            'Visit the login page with a <code>?redirect=</code> parameter pointing at an external site, e.g. <code>/index.php?redirect=http://example.com</code>.',
            'Log in normally with valid credentials.',
            'Watch where you land after a successful login.',
        ),
        'hints' => array(
            'nudge' => 'Look at the login form\'s HTML after loading the page with a redirect parameter — is that parameter carried through into the form at all?',
            'answer' => '<code>/index.php?redirect=http://evil.com/phish</code> — log in with any valid account and you\'ll be sent straight to evil.com. Nothing about the destination is checked.',
        ),
    ),
    array(
        'title' => 'Claim It Twice', 'module' => 'Welcome Bonus — Race Condition', 'target' => '/user/claim_bonus.php',
        'objective' => 'Claim the one-time welcome bonus more than once, ending up with more than 100 credits.',
        'difficulty' => 'Entry',
        'concept' => 'The claim handler reads "have I claimed this already?" and writes "now I have" as two separate steps, with a real gap in between. If two requests both ask the question before either one writes the answer, both get told "no, go ahead" — the check each request relied on was already stale by the time it acted on it. This is a race condition (specifically, a time-of-check to time-of-use, or TOCTOU, bug): the vulnerability isn\'t in any single request, it\'s in the gap between two steps that were never made atomic.',
        'tools' => array('Browser (multiple tabs)', 'or a few terminal windows with curl'),
        'steps' => array(
            'Claim the bonus once normally and confirm your balance goes to 100.',
            'Reset your account (or use a fresh one) and this time, open several browser tabs to the Claim Bonus page at once.',
            'Click "Claim Bonus" in all the tabs as close together as you can manage — or fire a handful of concurrent <code>curl</code> requests from separate terminals at the same instant.',
        ),
        'hints' => array(
            'nudge' => 'The page checks your status, then updates it — those are two separate moments in time. What happens if two requests both check *before* either one updates?',
            'answer' => 'At this tier the window between check and write is wide (about half a second) specifically so it\'s reachable by hand — fire 5-10 concurrent requests (multiple browser tabs clicking "Claim" at once, or several parallel <code>curl -d "claim=1" .../user/claim_bonus.php &amp;</code> commands) and check your final balance; more than one claim landing shows up as more than 100 credits.',
        ),
    ),
    array(
        'title' => 'No Login Required', 'module' => 'Tickets API — Broken Object Level Auth', 'target' => '/api/tickets.php',
        'objective' => 'Read any ticket\'s full contents — including other users\' private support messages — without ever logging in.',
        'difficulty' => 'Entry',
        'concept' => 'This is the same underlying idea as the browser-facing IDOR bugs elsewhere in this app (an ID in the request decides what data comes back, with no check on who\'s asking) — except here it\'s a JSON API rather than an HTML page. APIs often get less scrutiny than the UI that calls them, since "nobody browses to them directly" — but every API endpoint is exactly as reachable with curl or Burp as any web page, authentication or not. Broken Object Level Authorization (BOLA) is the API-specific name for this exact pattern.',
        'tools' => array('Browser or curl', 'Postman (optional, for exploring a JSON API more comfortably)'),
        'steps' => array(
            'Without logging into the app at all, request <code>/api/tickets.php</code> directly.',
            'Note that you get back ticket data for every user, not just your own (which makes sense, since you\'re nobody at this tier).',
            'Try requesting a specific ticket by ID: <code>/api/tickets.php?id=1</code>.',
        ),
        'hints' => array(
            'nudge' => 'Try hitting the API URL directly in a private/incognito window, with no session cookie at all — does it ask you to log in?',
            'answer' => '<code>curl http://TARGET/vulnapp/api/tickets.php</code> with no cookies returns every ticket in the system, and <code>?id=1</code> returns full ticket contents including the message body — no authentication check exists on this endpoint at all.',
        ),
    ),
    array(
        'title' => 'Forge Your Own Token', 'module' => 'API Token (JWT) Auth', 'target' => '/api/auth_token.php, /api/ticket_update.php (Bearer header)',
        'objective' => 'Without ever knowing anyone\'s password or api_key, craft your own JSON Web Token claiming the admin role, and use it to update a ticket via the API.',
        'difficulty' => 'Standard',
        'concept' => 'A JWT is just three base64url-encoded segments — a header, a payload, and a signature — glued together with dots. Nothing stops you from building the header and payload segments yourself; the only thing supposed to stop you is the signature, which proves the server itself produced those claims. If the server\'s verification code ever lets a token through without checking that signature at all — for example when the header claims <code>"alg":"none"</code> — then the payload you wrote by hand is trusted exactly as if the server had issued it.',
        'tools' => array('Burp Suite (or curl)', 'a scratch script to base64url-encode JSON (or python3 -c)'),
        'steps' => array(
            'Look at a real token from <code>/api/auth_token.php</code> (exchange any seeded account\'s api_key for one) and split it on the dots — note it\'s just three base64url-encoded pieces.',
            'Build your own header <code>{"typ":"JWT","alg":"none"}</code> and payload <code>{"sub":1,"username":"admin","role":"admin"}</code>, base64url-encode each, and join them with dots — leave the third (signature) segment empty.',
            'Send it as <code>Authorization: Bearer &lt;your-token&gt;</code> to <code>/api/ticket_update.php</code> with a <code>ticket_id</code> and a field to change, and confirm it\'s accepted as if you were really logged in as admin.',
        ),
        'hints' => array(
            'nudge' => 'A JWT\'s header names the algorithm the server is supposed to use to check the signature — what happens if you simply claim there isn\'t one?',
            'answer' => 'Base64url-encode <code>{"typ":"JWT","alg":"none"}</code> and <code>{"sub":1,"username":"admin","role":"admin"}</code>, join them with a dot, and append a trailing dot with nothing after it for the empty signature segment — that full three-part string is your forged token.',
        ),
    ),
    array(
        'title' => 'Hijack Any Ticket, No Field Off Limits', 'module' => 'API Ticket Update — Mass Assignment', 'target' => '/api/ticket_update.php',
        'objective' => 'Using any authenticated API token, take over someone else\'s ticket completely — reassign it to yourself and change its priority — without being staff or the owner.',
        'difficulty' => 'Standard',
        'concept' => 'An update endpoint that accepts a JSON/form body has to decide which of the submitted fields it\'s actually willing to write to the database — a real implementation enforces a fixed allowlist per role. This endpoint, at this tier, does neither: whatever field names show up in the request get written straight through, with no ownership check on the ticket and no restriction on which columns a non-staff caller can touch, including who owns the ticket and how urgent it\'s marked.',
        'tools' => array('Burp Suite or curl', 'a token from /api/auth_token.php for any seeded account'),
        'steps' => array(
            'Exchange a non-owner, non-staff account\'s api_key for a token at <code>/api/auth_token.php</code>.',
            'POST to <code>/api/ticket_update.php</code> with that token, a <code>ticket_id</code> belonging to someone else, and extra fields the visible UI never exposes: <code>user_id</code> and <code>priority</code>.',
            'Confirm the ticket\'s owner and priority both changed — you never needed to own it or be staff.',
        ),
        'hints' => array(
            'nudge' => 'This endpoint has no HTML form to tell you what fields "should" exist — what happens if you just submit the column names you\'d expect the database to have?',
            'answer' => 'POST <code>ticket_id=&lt;someone else\'s ticket&gt;&amp;user_id=&lt;your own id&gt;&amp;priority=urgent</code> with your Bearer token — every field lands, including ones no legitimate UI ever lets you set.',
        ),
    ),
    array(
        'title' => 'Guess Until You\'re Right', 'module' => 'API Token Request — Rate Limiting', 'target' => '/api/auth_token.php',
        'objective' => 'Brute-force a seeded account\'s api_key against the token-exchange endpoint, with nothing slowing you down.',
        'difficulty' => 'Entry',
        'concept' => 'An api_key is only as strong as the cost of guessing it wrong repeatedly — and that cost is entirely a function of how many guesses an attacker is allowed to make. A credential of any length is eventually brute-forceable if the endpoint checking it never slows down, locks out, or even notices repeated failures; the fix for this class of problem is a control (rate limiting), not a longer secret.',
        'tools' => array('Hydra, Burp Intruder, or a short script', 'a small wordlist of plausible api_key guesses'),
        'steps' => array(
            'Send a handful of deliberately wrong <code>api_key</code> guesses for a known username to <code>/api/auth_token.php</code> in quick succession.',
            'Confirm none of them are ever rejected with anything other than a plain "invalid" response — no lockout message, no increasing delay.',
            'Point an actual brute-force tool at it and confirm it can run as many guesses as you let it.',
        ),
        'hints' => array(
            'nudge' => 'Nothing about the response changes no matter how many times in a row you guess wrong — what does that tell you about trying a LOT of guesses?',
            'answer' => 'This is the same class of finding as the "No More SQLi — Break In Anyway" login-brute-force challenge, applied to an API credential instead of a password — write it up as "Missing Rate Limiting on API Token Exchange."',
        ),
    ),
    array(
        'title' => 'Ride In On a Known Session', 'module' => 'Session Management', 'target' => '/index.php',
        'objective' => 'Prove that logging in never issues a fresh session ID — the same cookie value that existed before authentication is still valid afterward.',
        'difficulty' => 'Standard',
        'concept' => 'A session ID is supposed to mean something different the moment you authenticate — it stops being "an anonymous visitor\'s cookie" and starts being "a credential that proves who you are." If the app keeps using the exact same ID across that boundary, anyone who already knew that ID beforehand (set it themselves, read it over an unencrypted connection, found it in a shared/kiosk browser) becomes just as authenticated as you the instant you log in, without ever touching your password. This vulnerability class applies at both simple and intermediate tiers identically — the code never rotates the session ID at either one.',
        'tools' => array('Browser DevTools or Burp Suite', 'curl (to inspect Set-Cookie headers directly)'),
        'steps' => array(
            'Visit <code>/index.php</code> anonymously and note your <code>PHPSESSID</code> cookie value.',
            'Log in normally with any seeded account.',
            'Compare the <code>PHPSESSID</code> value after login to the one from before — did the server ever send a new <code>Set-Cookie</code> at all?',
        ),
        'hints' => array(
            'nudge' => 'Most of this app\'s bugs are about what a payload can do — this one is about what the server *doesn\'t* do at a specific moment. What would you expect to change about your session the instant you prove who you are?',
            'answer' => 'Capture the <code>Set-Cookie: PHPSESSID=...</code> value (or lack of one) in Burp across the login POST — at simple/intermediate tier, no new session ID is ever issued, confirmed by the identical cookie value before and after.',
        ),
    ),
    array(
        'title' => 'Frame the 2FA Toggle', 'module' => 'Clickjacking', 'target' => '/user/enable_2fa.php',
        'objective' => 'Build a page that overlays an invisible iframe of the 2FA settings page, tricking a logged-in victim into disabling their own 2FA with a single disguised click.',
        'difficulty' => 'Standard',
        'concept' => 'A browser has no way to know that the button a user just clicked on your page is actually an invisible, perfectly-positioned iframe showing someone else\'s site underneath their cursor — "UI redress," commonly called clickjacking. The only real defense is the SERVER telling the browser "never let anyone frame this page at all" via the <code>X-Frame-Options</code> header (or a CSP <code>frame-ancestors</code> directive) — without it, every single page in this app can be framed by any attacker-controlled site, at this tier.',
        'tools' => array('Browser', 'a scratch HTML file'),
        'steps' => array(
            'Log in as <code>carol</code> (the only seeded account with 2FA enabled) and confirm <code>/user/enable_2fa.php</code> loads normally with a "Disable 2FA" button.',
            'Build a minimal HTML page with a transparent <code>&lt;iframe&gt;</code> pointed at that exact URL, positioned so its Disable button sits under an innocent-looking "Click here" button on your page.',
            'While logged in as carol in the same browser, open your crafted page and click the decoy button — confirm 2FA got disabled without ever seeing the real page.',
        ),
        'hints' => array(
            'nudge' => 'This isn\'t a payload in a form field — it\'s about getting a real click on a real button on the REAL site, just hidden underneath something else. What HTTP response header exists specifically to stop a page from being iframed at all?',
            'answer' => '<code>&lt;iframe src="http://TARGET/vulnapp/user/enable_2fa.php" style="opacity:0.001;position:absolute;top:0;left:0;width:300px;height:100px;"&gt;&lt;/iframe&gt;</code> layered under a decoy button at the same coordinates — confirm by checking the response headers for this page and noting <code>X-Frame-Options</code> is simply absent at this tier.',
        ),
    ),
    array(
        'title' => 'Read a Local File Through a Link Preview', 'module' => 'SSRF — Link Preview', 'target' => '/user/link_preview.php',
        'objective' => 'Get the server itself to read and return the contents of a local file via the ticket composer\'s "paste a link to preview" feature.',
        'difficulty' => 'Standard',
        'concept' => 'A link-preview feature has to fetch the URL you give it — that fetch happens on the SERVER, using the server\'s own network access and file permissions, not your browser\'s. If nothing restricts which protocols or hosts that fetch can target, you\'re not just previewing links anymore: you\'re asking the server to make a request on your behalf to anywhere it can reach, including its own local filesystem via a <code>file://</code> URL. This is Server-Side Request Forgery (SSRF) — the server is forging a request it never meant to make, driven entirely by attacker input.',
        'tools' => array('Browser DevTools or Burp Suite'),
        'steps' => array(
            'Log in as any user and open the ticket composer on <code>/user/tickets.php</code>.',
            'In the "Paste a link to preview" field, enter <code>file:///etc/hostname</code> (or any world-readable file path on the box) instead of a normal <code>http://</code> URL.',
            'Click Preview and confirm the file\'s contents come back in the response, not a normal web-page preview.',
        ),
        'hints' => array(
            'nudge' => 'This feature fetches whatever URL you give it — does it check that the URL is actually a web page at all, or just hand it straight to the HTTP client library?',
            'answer' => 'POST <code>url=file:///etc/hostname</code> directly to <code>/user/link_preview.php</code> — at this tier, no protocol restriction exists at all, so curl happily reads local files exactly as it would fetch a web page.',
        ),
    ),
    array(
        'title' => 'Leak a File via XML Import', 'module' => 'XXE — Bulk Ticket Import', 'target' => '/admin/import_tickets.php',
        'objective' => 'Get the server to read an arbitrary local file and reflect its contents back into an imported ticket, using nothing but a crafted XML document (admin access required).',
        'difficulty' => 'Stretch',
        'concept' => 'XML lets you define your own custom shorthand codes — "entities" — right at the top of a document, including ones that mean "go read this external resource and paste it in right here." A parser that resolves those definitions without restriction will fetch whatever a <code>SYSTEM</code> entity points at — a local file, an internal URL, anything the server process can reach — and substitute its contents directly into the parsed document, which this app then saves straight into the new ticket. This is XML External Entity (XXE) injection, and on PHP versions before 8.0 (what this app targets — see README), it\'s the parser\'s own default behavior, not something a developer has to opt into.',
        'tools' => array('Browser', 'a text editor for crafting the XML payload'),
        'steps' => array(
            'Log in as <code>admin</code> and open <code>/admin/import_tickets.php</code>.',
            'Build an XML document whose <code>&lt;!DOCTYPE&gt;</code> defines an external general entity pointing at a local file (e.g. <code>/etc/hostname</code>), and reference that entity inside a <code>&lt;message&gt;</code> element.',
            'Submit the import and check the "Imported" table — the ticket\'s message should contain the target file\'s actual contents instead of your literal entity reference.',
        ),
        'hints' => array(
            'nudge' => 'XML lets a document define its own custom placeholders near the top, before the real content starts — what happens if one of those placeholders is defined as "go read this local file" instead of a plain string?',
            'answer' => '<code>&lt;?xml version="1.0"?&gt;&lt;!DOCTYPE tickets [&lt;!ENTITY xxe SYSTEM "file:///etc/hostname"&gt;]&gt;&lt;tickets&gt;&lt;ticket&gt;&lt;subject&gt;leak&lt;/subject&gt;&lt;message&gt;&amp;xxe;&lt;/message&gt;&lt;/ticket&gt;&lt;/tickets&gt;</code> — the imported ticket\'s message becomes the file\'s contents.',
        ),
    ),
    array(
        'title' => 'Fire Script From a URL Fragment', 'module' => 'DOM XSS — Search Prefill', 'target' => '/user/tickets.php#q=',
        'objective' => 'Get JavaScript to execute purely in the browser via a "deep link to a search" feature — without the payload ever reaching the server at all.',
        'difficulty' => 'Entry',
        'concept' => 'Everything after a <code>#</code> in a URL is a "fragment" — browsers deliberately never send it to the server in the actual HTTP request, which is exactly what makes it fast to use for client-side deep-linking. But that also means none of this app\'s server-side defenses (not even at hard/expert tier) ever get a chance to see or sanitize it — whatever JavaScript on the page reads <code>location.hash</code> and writes it into the DOM is the *entire* defense, for better or worse. At this tier, it writes it in completely raw.',
        'tools' => array('Browser address bar — no proxy tooling needed'),
        'steps' => array(
            'Visit <code>/user/tickets.php</code> normally and confirm the page loads.',
            'Append <code>#q=&lt;script&gt;alert(1)&lt;/script&gt;</code> to the URL and reload.',
            'Confirm the script executes — then check the Network tab and note the fragment never appeared in any request the browser actually sent.',
        ),
        'hints' => array(
            'nudge' => 'Try the exact same payload that worked for the server-side stored XSS challenge, but put it after a <code>#</code> in the URL instead of in a ticket field — does it still fire, and did the server ever see it this time?',
            'answer' => '<code>/user/tickets.php#q=&lt;script&gt;alert(1)&lt;/script&gt;</code> — the "Showing results for" banner writes this straight into <code>innerHTML</code> with zero filtering at this tier.',
        ),
    ),
    array(
        'title' => 'The Code Prompt That Isn\'t Checked', 'module' => '2FA Bypass', 'target' => '/user/verify_2fa.php',
        'objective' => 'Log in as the one seeded 2FA-enabled account and reach the dashboard without ever entering a valid code.',
        'difficulty' => 'Entry',
        'concept' => 'Adding a second login step to the UI doesn\'t automatically mean the SERVER actually requires it — those are two different things. If the "fully logged in" flag gets set the moment your password checks out, and the redirect to the code-entry page is just where the flow happens to send you next, then the 2FA prompt is purely cosmetic: everywhere else in the app only cares about that one flag, which was already true before you ever saw a code field.',
        'tools' => array('Browser'),
        'steps' => array(
            'Log in as <code>carol</code> / <code>carol123</code> — the only seeded account with 2FA enabled.',
            'Confirm you land on a "Enter your 2FA code" page instead of the dashboard.',
            'Without entering anything, navigate directly to <code>/dashboard.php</code> in the address bar.',
        ),
        'hints' => array(
            'nudge' => 'The redirect to the code page happens right after your password is accepted — ask yourself what, specifically, changed in your session at that exact moment, and whether the code you haven\'t typed yet had anything to do with it.',
            'answer' => 'Browse straight to <code>/dashboard.php</code> after the password step — you\'re already in. At this tier, the "verified" flag is set to true before the code is ever checked, purely so the UI flow looks consistent with the other tiers.',
        ),
    ),
    array(
        'title' => 'Poison the Login Page for Everyone', 'module' => 'Cache Poisoning', 'target' => '/index.php',
        'objective' => 'Confirm that a header you control gets baked unescaped into the login page\'s HTML.',
        'difficulty' => 'Standard',
        'concept' => 'This app caches the rendered login page to disk for a short time, keyed only by the URL — exactly like a real CDN or reverse-proxy cache, which by default does NOT vary its cache by request headers unless specifically configured to. If the page reflects a header value into its HTML, and that header never affects the cache key, then whatever you send in that header gets baked into a response that gets served to the NEXT visitor who requests the same URL — not just you.',
        'tools' => array('Burp Suite or curl (to set a custom request header)'),
        'steps' => array(
            'Request <code>/index.php</code> normally with curl and view the page source — note the <code>&lt;link rel="canonical"&gt;</code> tag in the <code>&lt;head&gt;</code>.',
            'Resend the exact same request, this time adding a header: <code>X-Forwarded-Host: evil.example</code>.',
            'View the response and confirm the canonical link now contains <code>evil.example</code>, unescaped, directly in the HTML.',
        ),
        'hints' => array(
            'nudge' => 'Look at where the canonical link\'s URL comes from — is it built from something fixed about this server, or from something in the request itself?',
            'answer' => '<code>curl -H "X-Forwarded-Host: evil.example" http://TARGET/vulnapp/</code> — the canonical href becomes <code>http://evil.example/</code>, completely unescaped. (The next challenge tier asks you to prove this actually gets cached and served to someone else.)',
        ),
    ),
    array(
        'title' => 'Escalate Your Own Ticket', 'module' => 'Business Logic — Escalation Workflow', 'target' => '/user/tickets.php',
        'objective' => 'Bump your own ticket straight to Urgent priority using the "Request Escalation" feature meant to require staff approval.',
        'difficulty' => 'Entry',
        'concept' => 'A button labeled "Request" implies there\'s a separate step where someone else decides whether to grant it — that\'s the whole point of an approval workflow. If the handler behind that button just performs the privileged action directly, with no actual approval gate anywhere in the server-side code, then the feature\'s name is describing a workflow that doesn\'t exist yet, not one that\'s actually been built.',
        'tools' => array('Browser'),
        'steps' => array(
            'Log in as any regular user and submit a ticket (or use an existing one).',
            'Click "Request Urgent" next to the ticket.',
            'Reload and confirm the ticket\'s priority is now <code>urgent</code> — immediately, with no staff ever involved.',
        ),
        'hints' => array(
            'nudge' => 'The button is labeled "Request" — does anything in this app actually represent a separate, staff-controlled approval step at this tier, or does clicking it just directly do the thing?',
            'answer' => 'Click "Request Urgent" and check the ticket\'s priority column immediately afterward — it\'s already <code>urgent</code>, and <code>escalation_status</code> is already <code>approved</code>, with zero staff involvement.',
        ),
    ),
),

'intermediate' => array(
    array(
        'title' => 'Bypass the Keyword Filter', 'module' => 'Login', 'target' => '/index.php',
        'objective' => 'The app now strips lowercase <code>union</code>, <code>select</code>, <code>--</code>, <code>#</code>, <code>;</code> from the username. Bypass auth anyway.',
        'difficulty' => 'Standard',
        'concept' => 'A blacklist filter can only block what its author thought of. This one matches specific keywords as literal lowercase text, but PHP\'s string functions here are case-sensitive — so the filter itself has no concept of "this word, in any capitalization." More importantly, the *auth bypass* from the Simple tier never actually needed the blocked words at all; it only needs an OR condition and a comment, neither of which this filter touches.',
        'tools' => array('Burp Suite'),
        'steps' => array(
            'Re-send your Auth Bypass 101 payload and confirm it now fails.',
            'Check whether the filter is case-sensitive by testing a single blocked keyword in mixed case.',
            'Note the filter never touches the OR logic itself — only certain keywords.',
        ),
        'hints' => array(
            'nudge' => 'The filter blocks certain exact words — does it care about how those words are capitalized?',
            'answer' => 'The blacklist targets specific words, not logic operators — you may not even need <code>UNION</code>/<code>SELECT</code> for an auth bypass, only for data extraction.',
        ),
    ),
    array(
        'title' => 'XSS Past the Blacklist', 'module' => 'Ticket Stored XSS', 'target' => '/user/tickets.php',
        'objective' => 'The app now strips <code>&lt;script&gt;</code> tags (case-insensitively). Get JS to execute anyway.',
        'difficulty' => 'Standard',
        'concept' => 'The browser doesn\'t care whether JavaScript arrives inside a <code>&lt;script&gt;</code> tag or as an event-handler attribute on some other tag — <code>onerror</code>, <code>onload</code>, <code>onmouseover</code> and dozens more all run JS the instant their event fires. A filter that only recognizes one specific tag name is filtering the *label* on the bug, not the underlying capability.',
        'tools' => array('Browser DevTools', 'PortSwigger XSS cheat sheet (public reference)'),
        'steps' => array(
            'Confirm <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> is now neutered.',
            'Recall that XSS doesn\'t require the word "script" at all — event handlers fire JS too.',
            'Try an image tag with a broken source and an error handler, or an SVG with an onload handler.',
        ),
        'hints' => array(
            'nudge' => 'The filter is only looking for one specific tag name — are there other HTML attributes that run JavaScript without using that tag at all?',
            'answer' => '<code>&lt;img src=x onerror=alert(1)&gt;</code> contains no <code>&lt;script&gt;</code> substring.',
        ),
    ),
    array(
        'title' => 'Forged MIME Type Upload', 'module' => 'Avatar Upload', 'target' => '/user/upload.php',
        'objective' => 'The app now checks the file\'s Content-Type — but only the header the browser sends, which you control.',
        'difficulty' => 'Standard',
        'concept' => 'A multipart file upload sends two separate, independent pieces of information: the file\'s actual bytes, and a Content-Type label describing what the browser *claims* those bytes are. Normally your browser sets that label honestly based on the file extension — but nothing stops a proxy like Burp from editing just the label while leaving the real file content (and its real, executable extension) untouched. The server is trusting a claim, not verifying a fact.',
        'tools' => array('Burp Suite (Repeater)'),
        'steps' => array(
            'Try uploading a .php file normally and confirm it\'s now rejected.',
            'Intercept the upload request in Burp before it hits the server.',
            'Edit the <code>Content-Type</code> part of the multipart body for your file to a value the app allows, without changing the actual file content.',
        ),
        'hints' => array(
            'nudge' => 'A file upload sends more than just the file\'s bytes — what else does the request tell the server about the file, and who actually controls that value?',
            'answer' => 'The filename and the Content-Type field are two separate things in a multipart form — the app only ever checks the latter.',
        ),
    ),
    array(
        'title' => 'Cross-Case Command Injection', 'module' => 'Admin Diagnostics', 'target' => '/admin/diagnostics.php',
        'objective' => 'Semicolons, <code>&&</code>, and <code>||</code> are now stripped. Get command execution anyway.',
        'difficulty' => 'Standard',
        'concept' => 'Linux shells have more than one way to run "a second thing" inside a command line — semicolons and <code>&amp;&amp;</code> are only the most obvious. Backticks and <code>$()</code> both mean "run this and substitute its output right here," which still counts as executing an arbitrary command, just via a different syntax the filter\'s author didn\'t enumerate. A blacklist of symbols will always be incomplete against a shell with this many ways to express the same idea.',
        'tools' => array('Browser', 'Burp Suite'),
        'steps' => array(
            'Confirm your simple-tier payload is now blocked.',
            'The filter is a fixed list of separators — think of other ways Linux shells chain or substitute commands.',
            'Backticks and <code>$()</code> both let you run a command inside another command\'s arguments.',
        ),
        'hints' => array(
            'nudge' => 'The obvious separator characters are blocked — Linux shells have more than one syntax for "run this other thing first."',
            'answer' => 'Try <code>127.0.0.1 `id`</code> or <code>127.0.0.1 $(id)</code>.',
        ),
    ),
    array(
        'title' => 'Verify Yourself, Hijack Someone Else', 'module' => 'Change Password', 'target' => '/user/change_password.php',
        'objective' => 'The form now asks for your current password. Find the mismatch between what gets checked and what gets changed.',
        'difficulty' => 'Stretch',
        'concept' => 'Adding an authentication check doesn\'t automatically fix an authorization bug — those are two different questions. "Does this password match the logged-in user?" (authentication: who are you) is not the same question as "which account\'s row is the UPDATE statement about to modify?" (authorization: what are you allowed to touch). This code answers the first question correctly and then answers the second one by blindly trusting a URL parameter, so the two checks end up talking about two different accounts.',
        'tools' => array('Browser or Burp Suite'),
        'steps' => array(
            'Confirm you can no longer change another user\'s password without a current-password value.',
            'Try entering YOUR OWN current password, but keep the <code>?id=</code> parameter pointed at someone else.',
            'Check whether the account that actually gets modified matches the account whose password you verified.',
        ),
        'hints' => array(
            'nudge' => 'Read the form\'s logic carefully: it checks your current password — but does it also check that the password belongs to the same account the update is about to modify?',
            'answer' => 'Many real apps have this exact bug: the check is "does this password match the logged-in user," but the update statement blindly trusts a separate ID parameter for which row to modify.',
        ),
    ),
    array(
        'title' => 'Date-Based Token Guessing', 'module' => 'Forgot Password', 'target' => '/user/forgot_password.php',
        'objective' => 'The reset token is no longer just <code>md5(username)</code>. Figure out the new formula and reset an account anyway.',
        'difficulty' => 'Standard',
        'concept' => 'A "secret" token is only as secret as its least-secret ingredient. Mixing in today\'s date makes the token look different from the simple-tier version, but the date isn\'t secret — everyone in the world can look it up. Any input to a security token that an attacker can also obtain independently doesn\'t add real unpredictability, it just adds an extra step for them to compute.',
        'tools' => array('Browser or a scratch script'),
        'steps' => array(
            'Request a reset for a known username and compare the resulting token against the simple-tier formula — it won\'t match anymore.',
            'Consider what OTHER piece of information, entirely public, might now be mixed in.',
            'Recompute the token for a target account using today\'s date, and use it without ever triggering a reset request for that account.',
        ),
        'hints' => array(
            'nudge' => 'The token changed from the simple tier — what\'s the simplest new piece of information the server could have mixed in that still isn\'t actually secret?',
            'answer' => 'Token = <code>md5(username . date(\'Y-m-d\'))</code> — you know the date without asking anyone.',
        ),
    ),
    array(
        'title' => 'Slash Your Way Out', 'module' => 'Open Redirect', 'target' => '/index.php?redirect=',
        'objective' => 'The redirect target must now start with a <code>/</code>. Get redirected to an external site anyway.',
        'difficulty' => 'Standard',
        'concept' => 'Requiring a leading slash is meant to force a same-site relative path — but a URL starting with <em>two</em> slashes (<code>//evil.com</code>) is what\'s called a protocol-relative URL, and browsers resolve it as "same scheme, different host," not as a path on the current site. It satisfies a naive "starts with /" check while still pointing somewhere else entirely.',
        'tools' => array('Browser'),
        'steps' => array(
            'Confirm <code>?redirect=http://evil.com</code> no longer works at this tier.',
            'Try a redirect value that starts with a slash but is still a full URL to somewhere else.',
            'Log in and watch where you land.',
        ),
        'hints' => array(
            'nudge' => 'The check only confirms the value starts with one particular character — is there more than one way to start a URL with that character and still point off-site?',
            'answer' => '<code>/index.php?redirect=//evil.com/phish</code> — the double slash passes the "starts with /" check but browsers treat <code>//host</code> as an absolute redirect to that host.',
        ),
    ),
    array(
        'title' => 'Win the Narrow Window', 'module' => 'Welcome Bonus — Race Condition', 'target' => '/user/claim_bonus.php',
        'objective' => 'The same one-time bonus bug exists here, but the check-and-write gap is much narrower. Land it anyway.',
        'difficulty' => 'Stretch',
        'concept' => 'The underlying bug hasn\'t changed at all — it\'s the exact same TOCTOU pattern as the simple tier. What\'s changed is how wide the window is: a handful of manually-clicked browser tabs relies on human reaction time, which is far too slow to reliably land a gap measured in milliseconds. This is the real-world reason race-condition testing tools exist — you need requests dispatched with as little timing jitter between them as possible, which naive sequential scripting (spawning one <code>curl</code> process at a time in a loop) doesn\'t achieve either, since each process spawn itself takes measurable time.',
        'tools' => array('Burp Suite Intruder (concurrent/throttled mode)', 'or a short async script (Python + aiohttp, or similar)'),
        'steps' => array(
            'Confirm that a handful of manually-clicked tabs (which worked at the simple tier) mostly fails to double-claim here.',
            'Think about what made your simple-tier approach work — was it really "multiple requests," or specifically "multiple requests landing within the same narrow window"?',
            'Use a tool built for real concurrency — Burp\'s Intruder with concurrent request mode, or a short script that dispatches many requests from a single process at once — rather than a loop that spawns one process per request.',
        ),
        'hints' => array(
            'nudge' => 'A bash loop that does <code>curl ... &amp;</code> many times still has to fork a new process for each one — that overhead alone can be wider than this tier\'s window. What would send many requests without that per-request overhead?',
            'answer' => 'A burst of 50-100+ requests dispatched from a single script using real async I/O (e.g. Python\'s <code>aiohttp</code> with <code>asyncio.gather</code>) reliably lands multiple successful claims here, even though a naive loop of 40 sequential <code>curl</code> spawns typically lands only one.',
        ),
    ),
    array(
        'title' => 'Any Session Will Do', 'module' => 'Tickets API — Broken Object Level Auth', 'target' => '/api/tickets.php',
        'objective' => 'The API now requires login — but does it check whose tickets you\'re actually allowed to see?',
        'difficulty' => 'Standard',
        'concept' => 'Requiring authentication answers "who are you?" — it says nothing about "what are you allowed to see?" Those are two different checks (authentication vs. authorization), and this tier only added the first one. Any valid, logged-in session — regardless of role or account — still gets full access to every ticket in the system.',
        'tools' => array('Browser or curl', 'a second test account'),
        'steps' => array(
            'Log in as a regular user (not admin/support) and confirm the unauthenticated request now fails.',
            'Using that same logged-in session, request a ticket by ID that you know belongs to someone else.',
            'Confirm you can read its full contents, including the message body.',
        ),
        'hints' => array(
            'nudge' => 'You\'re definitely logged in now — but does the endpoint ever check that the ticket ID you\'re asking for belongs to you specifically?',
            'answer' => 'Log in as alice, then request <code>/api/tickets.php?id=2</code> (Bob\'s ticket) using alice\'s session cookie — it returns Bob\'s full ticket, no ownership check performed at all.',
        ),
    ),
    array(
        'title' => 'Capitalize Your Way Past the Filter', 'module' => 'API Token (JWT) Auth', 'target' => '/api/auth_token.php, /api/ticket_update.php (Bearer header)',
        'objective' => 'The server now rejects <code>alg: none</code> exactly as written. Get the same forged-token trick working anyway.',
        'difficulty' => 'Standard',
        'concept' => 'A blacklist check that compares strings has to decide whether "none" and "None" and "NONE" count as the same value — and PHP\'s default string comparison is case-sensitive unless a function explicitly says otherwise. Blocking one exact spelling of a dangerous value is not the same as blocking the concept that value represents.',
        'tools' => array('Burp Suite (or curl)', 'a scratch script to base64url-encode JSON'),
        'steps' => array(
            'Resend your Simple-tier forged token unchanged and confirm it\'s now rejected.',
            'Change only the case of the <code>alg</code> value in your header — nothing else — and rebuild the token.',
            'Resend it and see whether the capitalization alone was enough to get back through.',
        ),
        'hints' => array(
            'nudge' => 'The filter blocks one exact piece of text — does it care how that text is capitalized?',
            'answer' => 'A header of <code>{"typ":"JWT","alg":"None"}</code> (or <code>"NONE"</code>) still skips the signature check — only the literal lowercase <code>"none"</code> is blocked.',
        ),
    ),
    array(
        'title' => 'Verified Owner, Unverified Transfer', 'module' => 'API Ticket Update — Mass Assignment', 'target' => '/api/ticket_update.php',
        'objective' => 'The endpoint now checks that you own the ticket (or are staff) before allowing any update. Use your own legitimate ownership to steal the ticket anyway.',
        'difficulty' => 'Stretch',
        'concept' => 'This is the same shape of bug as the browser-facing "Verify Yourself, Hijack Someone Else" change-password flaw elsewhere in this app: an authorization check answers "do you currently own this resource?", but if the request is also allowed to change *who owns it* as part of the very same write, the check you just passed stops describing the ticket\'s state the instant the UPDATE statement runs.',
        'tools' => array('Burp Suite or curl', 'two seeded accounts'),
        'steps' => array(
            'Get a token for an account that genuinely owns a ticket (e.g. alice, who owns ticket 1).',
            'POST an update that includes a legitimate field change alongside <code>user_id=&lt;someone else\'s id&gt;</code>.',
            'Confirm the ownership check passed (because you really did own it going in) — and that the ticket now belongs to someone else coming out.',
        ),
        'hints' => array(
            'nudge' => 'The check confirms you own the ticket *before* the update runs — does it also confirm you still own it, specifically, after your own update changes who the owner is?',
            'answer' => 'As the owner, POST <code>ticket_id=1&amp;user_id=&lt;bob\'s id&gt;</code> — the ownership check you legitimately pass is for the ticket\'s state going in, not its state coming out.',
        ),
    ),
    array(
        'title' => 'Dress Up 127.0.0.1', 'module' => 'SSRF — Link Preview', 'target' => '/user/link_preview.php',
        'objective' => 'The preview feature now blocks a <code>localhost</code>/<code>127.0.0.1</code> substring blacklist. Reach the same loopback address under a different spelling.',
        'difficulty' => 'Standard',
        'concept' => 'A blacklist built out of string comparisons only blocks the exact spellings someone thought to type in. IPv4 has several legal-but-unusual ways to write the same address — a short form that drops leading octets, or octal notation with a leading zero — that a browser and a C-based resolver (which is what curl ultimately uses) will both still happily resolve to <code>127.0.0.1</code>, even though the string never contains the substrings <code>"localhost"</code> or <code>"127.0.0.1"</code>.',
        'tools' => array('Browser or curl'),
        'steps' => array(
            'Confirm <code>http://127.0.0.1/</code> and <code>http://localhost/</code> are now rejected by the preview feature.',
            'Try an alternate representation of the same address instead — e.g. <code>http://127.1/</code> or <code>http://0177.0.0.1/</code>.',
            'Confirm the preview still fetches the internal resource, proving the block is string-matching, not address-resolving.',
        ),
        'hints' => array(
            'nudge' => 'The filter is looking for specific text in the URL. Is there more than one way to write "127.0.0.1" that a resolver still understands?',
            'answer' => 'Submit <code>http://127.1/</code> (or octal <code>http://0177.0.0.1/</code>) as the link to preview — neither string contains the blocked substrings, but both resolve to loopback.',
        ),
    ),
    array(
        'title' => 'The Fix That Substitutes Instead of Blocking', 'module' => 'XXE — Bulk Import Tickets', 'target' => '/admin/import_tickets.php',
        'objective' => 'The import feature now uses <code>DOMDocument</code> instead of <code>simplexml_load_string()</code> — confirm the external entity read still works exactly the same way.',
        'difficulty' => 'Stretch',
        'concept' => 'Switching parsers is often assumed to be a security fix on its own, but the actual behavior is controlled by the flags passed in, not the class name. <code>LIBXML_NOENT</code> sounds protective — it reads like "no entities" — but it actually means the opposite: substitute entity references with their defined value when building the tree. That is precisely the operation XXE depends on.',
        'tools' => array('Burp Suite or curl'),
        'steps' => array(
            'Resend your Simple-tier XXE payload (a <code>&lt;!DOCTYPE&gt;</code> defining an external entity pointing at a local file) unchanged.',
            'Confirm the import still succeeds and the file contents still come back in the created ticket.',
            'Report that switching to <code>DOMDocument</code> did not close this — only removing <code>LIBXML_NOENT</code>, or disabling entity loading entirely, would.',
        ),
        'hints' => array(
            'nudge' => 'Read what <code>LIBXML_NOENT</code> actually does, not what its name suggests it does.',
            'answer' => 'Your original <code>&lt;!ENTITY xxe SYSTEM "file:///etc/passwd"&gt;</code> payload still works unchanged — <code>LIBXML_NOENT</code> substitutes entities, it does not block them.',
        ),
    ),
    array(
        'title' => 'The Filter That Checks for One Tag', 'module' => 'DOM XSS — Search Deep Link', 'target' => '/user/tickets.php#q=',
        'objective' => 'The deep-link banner now strips the literal text <code>&lt;script</code> before writing it into the page. Get script execution anyway, entirely client-side.',
        'difficulty' => 'Standard',
        'concept' => 'The exact same lesson as the server-side ticket renderer\'s keyword filter, now sitting in JavaScript instead of PHP: stripping one tag name does nothing to the dozens of other HTML elements whose attributes can execute JavaScript on their own, with no <code>&lt;script&gt;</code> tag involved at all.',
        'tools' => array('Browser address bar'),
        'steps' => array(
            'Confirm <code>#q=&lt;script&gt;alert(1)&lt;/script&gt;</code> is now neutralized (the literal text is stripped before being written to the page).',
            'Try a payload that never uses the word "script" at all — an image tag with a broken source and an <code>onerror</code> handler.',
            'Confirm the alert still fires, purely from the URL fragment, with no request ever reaching the server.',
        ),
        'hints' => array(
            'nudge' => 'The filter is looking for one specific substring. Which other HTML elements can run JavaScript without ever containing that substring?',
            'answer' => 'Visit <code>/user/tickets.php#q=&lt;img src=x onerror=alert(1)&gt;</code> — the banner still writes it via <code>innerHTML</code>, and the browser executes <code>onerror</code> on the broken image, no <code>&lt;script&gt;</code> text anywhere in the payload.',
        ),
    ),
    array(
        'title' => 'The Session Flag That Means Two Things', 'module' => '2FA Bypass', 'target' => '/api/tickets.php',
        'objective' => 'The main login flow now correctly withholds full access until a TOTP code is verified. Find a different endpoint that was never told about the new partial-auth state.',
        'difficulty' => 'Stretch',
        'concept' => 'Adding a new check to the login flow protects every page that funnels through the same gate — but a second-factor fix only actually works if *every* authenticated endpoint checks the same thing the same way. An endpoint written earlier, checking only "is there a logged-in session," has no idea a newer, in-between "logged in but not yet verified" state now exists, because nobody went back and updated it.',
        'tools' => array('Burp Suite or curl', 'carol\'s credentials (the account with 2FA enabled)'),
        'steps' => array(
            'Log in as carol with the correct password; confirm you land on the 2FA code-entry step, not the dashboard.',
            'Without ever entering a TOTP code, request <code>/api/tickets.php</code> using the session cookie you already have.',
            'Confirm it returns data instead of rejecting the still-partial session.',
        ),
        'hints' => array(
            'nudge' => 'The dashboard correctly bounces you back to the 2FA step. Does every endpoint that checks "am I logged in" actually ask the same question the dashboard does?',
            'answer' => 'After carol\'s password step (but before entering any code), hit <code>/api/tickets.php</code> directly — it only checks <code>isset($_SESSION[\'user_id\'])</code>, which is already set at this point, so it returns ticket data from a session that never completed 2FA.',
        ),
    ),
    array(
        'title' => 'Bust the Cache, Poison It For Real', 'module' => 'Cache Poisoning — Login Page', 'target' => '/index.php',
        'objective' => 'A cache-buster is now needed to force a fresh cache entry — use that same technique to actually prove the poisoning, not just the reflection.',
        'difficulty' => 'Standard',
        'concept' => 'This is the real technique security researchers use to demonstrate cache poisoning safely during testing: appending a harmless, cache-key-varying query parameter lets you force the cache to populate a *fresh* entry on demand, so you can poison it and then immediately confirm a second, "clean" request to the exact same URL gets served your injected content back — proving impact instead of just reflection.',
        'tools' => array('curl (two separate requests)'),
        'steps' => array(
            'Request <code>/index.php?cb=1</code> with a crafted <code>X-Forwarded-Host</code> header, to force a fresh cache entry for that exact URL.',
            'Request the exact same URL, <code>/index.php?cb=1</code>, again — this time with no special header at all.',
            'Confirm the second, "clean" request still shows your injected value in the canonical link — the cache served your poisoned entry to a request that never sent the header.',
        ),
        'hints' => array(
            'nudge' => 'The cache is keyed by the full request URL, including query string. How could you force a brand-new cache entry on demand, poison it, then check it from a "clean" second request to that identical URL?',
            'answer' => '<code>curl -H "X-Forwarded-Host: evil.example" "http://TARGET/vulnapp/index.php?cb=1"</code>, then <code>curl "http://TARGET/vulnapp/index.php?cb=1"</code> with no header at all — the second response still contains <code>evil.example</code>, served straight from the poisoned cache entry.',
        ),
    ),
    array(
        'title' => 'The Button That Lied About Being Disabled', 'module' => 'Business Logic — Escalation Workflow', 'target' => '/user/tickets.php',
        'objective' => 'The "Request Escalation" button now greys itself out after one click. Confirm that\'s cosmetic, not an actual server-side gate.',
        'difficulty' => 'Standard',
        'concept' => 'A pending state now exists in the data model — but a pending state only protects anything if the server actually enforces it on every write. Disabling a button in JavaScript changes what the browser is willing to let you click; it does nothing at all to what the server behind that button is willing to accept, since the server has no idea the button exists.',
        'tools' => array('Burp Suite or curl (to resend the POST directly, bypassing the disabled button)'),
        'steps' => array(
            'Click "Request Urgent" once in the browser and confirm the button now shows as disabled/pending.',
            'Using Burp or curl, resend the exact same POST request directly to the server — not through the now-disabled button.',
            'Confirm the ticket escalates immediately anyway, with no staff approval, despite the UI claiming a request is "pending."',
        ),
        'hints' => array(
            'nudge' => 'The button being greyed out is something the browser decided to do. Does the server know, or care, what the button currently looks like?',
            'answer' => 'Resend the identical <code>action=request_escalation</code> POST directly (skip the disabled button entirely) — the server applies the escalation immediately regardless of any client-side "pending" state.',
        ),
    ),
),

'hard' => array(
    array(
        'title' => 'Forge a Remember-Me Cookie', 'module' => 'Login (secondary surface)', 'target' => '/index.php (cookie: remember_token)',
        'objective' => 'The login form itself is now fully parameterized. Find the SQLi that got left behind elsewhere in the auth flow.',
        'difficulty' => 'Stretch',
        'concept' => 'Fixing one input doesn\'t fix the vulnerability class everywhere it appears — SQL injection is a pattern (untrusted data glued into a query), and this app has more than one place that pattern shows up. A cookie is just as attacker-controlled as a form field; the only difference is where the data enters the app. If the "remember me" feature builds its query the same unsafe way the login form used to, the bug simply moved, it didn\'t disappear.',
        'tools' => array('Burp Suite'),
        'steps' => array(
            'Register interest in "Remember me" — log in normally with it checked and inspect the cookie you get back.',
            'Think about what else in this app reads a cookie value straight into a query. (Hint: re-read includes/db.php and index.php together, or just test it.)',
            'Try sending a crafted <code>remember_token</code> cookie on a fresh, logged-out session.',
        ),
        'hints' => array(
            'nudge' => 'The login form itself got fixed — but "remember me" had to store something in your browser to recognize you next time. Where did that value go, and does anything in the app read a cookie value straight into a query?',
            'answer' => 'If a value from a cookie is dropped into <code>WHERE session_token = \'$token\'</code> unescaped, a <code>\' OR 1=1 -- </code>-style payload in the cookie itself logs you in as the first user returned.',
        ),
    ),
    array(
        'title' => 'Reflected XSS via Search', 'module' => 'Tickets', 'target' => '/user/tickets.php?q=',
        'objective' => 'Ticket subject/body are now safely encoded. Find where user input still comes back unescaped.',
        'difficulty' => 'Standard',
        'concept' => 'Encoding has to happen everywhere untrusted data gets printed into HTML, not just in the one place a developer remembered to fix. "Reflected" XSS works the same way as stored XSS — the browser still just executes whatever HTML/JS it\'s given — the only difference is the payload comes back in the same request instead of being saved first. And context matters: text placed inside an HTML attribute (<code>value="..."</code>) needs to escape the *attribute* first, which is a different job than escaping text placed between tags.',
        'tools' => array('Browser', 'Burp Suite'),
        'steps' => array(
            'Try your intermediate-tier XSS payload in a ticket subject/message and confirm it\'s now escaped.',
            'Look at every other place on the page that reflects something you control — including the search box.',
            'View source after searching for something distinctive to see exactly how your input lands in the HTML.',
        ),
        'hints' => array(
            'nudge' => 'The ticket fields are properly escaped now — but is the search box on that same page treated the same way?',
            'answer' => 'The search term is placed inside an HTML attribute (<code>value="..."</code>) — you don\'t need a script tag, you need to close the attribute and the input tag first.',
        ),
    ),
    array(
        'title' => 'The Endpoint They Forgot', 'module' => 'Profile — Broken Access Control', 'target' => '/user/profile_export.php',
        'objective' => 'Direct profile viewing/editing is now locked to your own account. Find the endpoint where that fix wasn\'t applied.',
        'difficulty' => 'Standard',
        'concept' => 'A permission check protects exactly the code it\'s written into — nothing more. When a second endpoint is added later (an "export" feature, an API route, a quick admin tool) that reads the same underlying data through a different file, it needs its *own* copy of that check, and it\'s very easy for that copy to just never get written. This is why real security reviews map every endpoint that touches sensitive data, not just the ones already known to be sensitive.',
        'tools' => array('Burp Suite (or a directory/endpoint wordlist + ffuf)'),
        'steps' => array(
            'Confirm <code>/user/profile.php?id=&lt;someone else&gt;</code> now 403s.',
            'This app has more than one way to read profile data — think about "export", "API", "download" style naming conventions developers commonly add later.',
            'Try the same IDOR technique against that endpoint instead.',
        ),
        'hints' => array(
            'nudge' => 'This app added a feature (exporting your profile) after the original access-control fix was already written — new code doesn\'t automatically inherit old protections.',
            'answer' => 'Check <code>/user/profile_export.php?id=4</code>.',
        ),
    ),
    array(
        'title' => 'Split-Parameter Command Injection', 'module' => 'Admin Diagnostics', 'target' => '/admin/diagnostics.php',
        'objective' => 'The host field is now properly escaped. There\'s a second field on this form now — is it?',
        'difficulty' => 'Standard',
        'concept' => 'Escaping one input doesn\'t protect the whole command line if a second, unescaped input gets concatenated in next to it. <code>escapeshellarg()</code> correctly wraps and neutralizes whatever\'s inside it — but only what\'s inside it. If a different variable is pasted into the same shell string without going through the same function, the safety of the first argument doesn\'t transfer to it.',
        'tools' => array('Browser', 'Burp Suite'),
        'steps' => array(
            'Try injecting into the host field directly and confirm <code>escapeshellarg()</code> now neutralizes it.',
            'Notice the form grew an extra "ping options" field in this mode — check whether that one is escaped too.',
            'Craft an "options" value that appends a second command after the legitimate ping options.',
        ),
        'hints' => array(
            'nudge' => 'One field got properly escaped — but the form grew a second field in this mode. Did the fix cover that one too?',
            'answer' => 'The options field is concatenated into the shell command as-is, right before your (safely escaped) host — so put your injection at the *end* of the options value.',
        ),
    ),
    array(
        'title' => 'Polyglot Upload', 'module' => 'Avatar Upload', 'target' => '/user/upload.php',
        'objective' => 'The app now validates real image structure with <code>getimagesize()</code>. Get PHP execution anyway.',
        'difficulty' => 'Stretch',
        'concept' => '<code>getimagesize()</code> checks that a file *starts with* a valid image header — it doesn\'t check that the file contains *only* image data. A file can legally have a few bytes of real GIF header followed by anything else at all, and still pass that check, because nothing reads past the header to confirm the rest. Meanwhile the web server still decides how to execute the file based purely on its extension, which this tier never restricts — so "passes the image check" and "gets executed as PHP" turn out to be two independent, non-conflicting facts about the same file.',
        'tools' => array('exiftool or a hex editor', 'Browser'),
        'steps' => array(
            'Confirm a plain <code>.php</code> file is now rejected by <code>getimagesize()</code>.',
            'Build a file that starts with a valid image header (so <code>getimagesize()</code> is satisfied) but also contains PHP code.',
            'Save/upload that file with a <code>.php</code> extension — the app keeps whatever extension you give it at this tier.',
        ),
        'hints' => array(
            'nudge' => 'The server checks that the file *looks like* a real image using its header bytes — does it ever check that the file contains *only* image data, or just that it starts that way?',
            'answer' => 'A GIF89a header is only 6 bytes: <code>GIF89a</code>. Prepend it to a one-line PHP payload and upload the result as <code>shell.php</code>.',
        ),
    ),
    array(
        'title' => 'Timing-Window Token Guessing', 'module' => 'Forgot Password', 'target' => '/user/forgot_password.php',
        'objective' => 'The token now depends on a unix timestamp, not the date. Reset an account by racing the clock instead of guessing a fixed value.',
        'difficulty' => 'Stretch',
        'concept' => 'A secret with a small search space isn\'t really a secret, even if it changes every second. A timestamp only has as many possible values as there are seconds you\'re willing to try, and if you know roughly *when* the token was generated (because you\'re the one who triggered it), that window shrinks to a handful of guesses instead of millions. Real unpredictability needs enough random bits that guessing is infeasible even with perfect timing information — this token has time, but not enough randomness.',
        'tools' => array('Burp Intruder or a small script'),
        'steps' => array(
            'Trigger a reset request for a target account and note roughly what time you did it.',
            'Compute <code>md5(username . timestamp)</code> for every timestamp in a small window around that moment (a few seconds either direction covers request latency).',
            'Try each candidate token against <code>/user/reset_password.php?token=...</code> until one works.',
        ),
        'hints' => array(
            'nudge' => 'The token isn\'t fixed anymore, but you know roughly when it was generated, because you\'re the one who triggered it — how big is the real search space once you narrow it to a small window of time?',
            'answer' => 'This is the same idea as the simple/intermediate tokens, just with a much smaller, timing-dependent search space instead of zero search space — the fix (expert tier) is real entropy, not a bigger secret.',
        ),
    ),
    array(
        'title' => 'Contains Isn\'t Equals', 'module' => 'Open Redirect', 'target' => '/index.php?redirect=',
        'objective' => 'Protocol-relative URLs are blocked now. Find the other flaw in this tier\'s validation.',
        'difficulty' => 'Standard',
        'concept' => 'A check like "does this string contain the word vulnapp anywhere" is trying to approximate "is this URL actually on our site" — but <code>strpos()</code> doesn\'t know anything about URL structure. It\'ll happily match the app\'s name sitting in the path, the query string, or even after the real (attacker-controlled) hostname, since none of those positions matter to the function — it just needs the substring to appear <em>somewhere</em>.',
        'tools' => array('Browser'),
        'steps' => array(
            'Confirm a bare <code>//evil.com</code> is now blocked.',
            'Think about what the validation is actually checking for, rather than what it\'s trying to achieve — a substring match is not the same thing as "this is our domain."',
            'Build a URL that satisfies a substring check for the app\'s name while still pointing at a domain you control.',
        ),
        'hints' => array(
            'nudge' => 'If the check just looks for the app\'s name appearing anywhere in the string, does it matter where in the URL that name actually shows up?',
            'answer' => '<code>/index.php?redirect=http://evil.com/vulnapp</code> — the literal text "vulnapp" appears in the URL (just in the wrong place: the attacker\'s own path, not the real app\'s domain), which is enough to satisfy a naive <code>strpos()</code> check.',
        ),
    ),
    array(
        'title' => 'The List Mode They Forgot', 'module' => 'Tickets API — Broken Object Level Auth', 'target' => '/api/tickets.php',
        'objective' => 'Fetching a single ticket by ID is properly locked down now. Find the other way this same API leaks everyone\'s data.',
        'difficulty' => 'Standard',
        'concept' => 'The single-ticket lookup and the "list all my tickets" mode are two different code paths inside the same file — and a fix applied to one doesn\'t automatically apply to the other. This is the same "endpoint added later, never got the same check" pattern as the browser-facing profile-export bug elsewhere in this app, just showing up inside an API instead of a separate page.',
        'tools' => array('Browser or curl'),
        'steps' => array(
            'Confirm requesting another user\'s ticket by <code>?id=</code> now correctly 403s.',
            'Try the same endpoint with no <code>id</code> parameter at all.',
            'Compare what comes back to what a properly-scoped "list my tickets" response should look like.',
        ),
        'hints' => array(
            'nudge' => 'The single-ticket code path clearly checks ownership now — does the "no id given" code path share that same check, or is it a separate block of logic entirely?',
            'answer' => '<code>/api/tickets.php</code> with no <code>id</code> parameter returns every ticket in the system regardless of who\'s logged in — the list-mode branch never received the ownership filter that was added to the single-ticket branch.',
        ),
    ),
    array(
        'title' => 'Replay It Forever', 'module' => 'API Token (JWT) Auth', 'target' => '/api/auth_token.php, /api/ticket_update.php (Bearer header)',
        'objective' => 'Alg forgery no longer works at all — every token must carry a real, correctly-computed signature. Find the other way a token outlives its intended lifetime.',
        'difficulty' => 'Stretch',
        'concept' => 'A JWT can carry an <code>exp</code> (expiration) claim specifically so a stolen or leaked token eventually stops working on its own, without anyone having to revoke it by hand. That claim is only a protection if something on the server side actually reads it and rejects anything past that timestamp — a token with a perfectly valid signature and an <code>exp</code> value in the past is still just as "real" as one that\'s still fresh, unless the verifier specifically checks the clock.',
        'tools' => array('Burp Suite', 'a legitimate token from /api/auth_token.php', 'a script that can read the current time'),
        'steps' => array(
            'Get a real, correctly-issued token from <code>/api/auth_token.php</code> using any seeded account\'s api_key, and decode its payload (base64url-decode the middle segment) to see its <code>exp</code> value.',
            'Note that this token is only meant to last 15 minutes from issuance.',
            'Keep using the exact same token well past that 15-minute window and confirm the API still accepts it.',
        ),
        'hints' => array(
            'nudge' => 'The token has an <code>exp</code> field right there in its payload — does anything on the server side actually look at it before this tier?',
            'answer' => 'At hard tier, alg-confusion is closed and the signature is genuinely required — but nothing checks <code>exp</code> at all, so a token captured once (sniffed off the wire, or simply kept around after your legitimate session ended) remains valid indefinitely.',
        ),
    ),
    array(
        'title' => 'The Field Everyone Forgot to Lock', 'module' => 'API Ticket Update — Mass Assignment', 'target' => '/api/ticket_update.php',
        'objective' => '<code>user_id</code> is finally off-limits no matter who you are. Find the other field that was supposed to be staff-only and isn\'t.',
        'difficulty' => 'Standard',
        'concept' => 'Closing one over-broad field (<code>user_id</code>) doesn\'t automatically mean every other sensitive field got the same scrutiny — a reviewer fixing the obvious "anyone can steal any ticket" bug can very plausibly stop there without re-auditing every remaining column for the same class of problem. <code>priority</code> looks like an internal triage field a regular user shouldn\'t touch, but nothing in this tier\'s code actually enforces that.',
        'tools' => array('Burp Suite or curl', 'your own ticket as a non-staff user'),
        'steps' => array(
            'Confirm <code>user_id</code> no longer transfers ownership, even when you legitimately own the ticket.',
            'On a ticket you genuinely own, try setting <code>priority</code> to something like <code>urgent</code> — a field no regular user\'s UI exposes at all.',
            'Confirm it\'s accepted even though you\'re not support or admin staff.',
        ),
        'hints' => array(
            'nudge' => 'One dangerous field just got closed — are you sure every *other* field on this same endpoint got the same review?',
            'answer' => 'POST <code>ticket_id=&lt;your own ticket&gt;&amp;priority=urgent</code> as a plain user — it\'s written through with no staff check at all, unlike <code>user_id</code>.',
        ),
    ),
    array(
        'title' => 'Two Ways Around the Lockout', 'module' => 'API Token Request — Rate Limiting', 'target' => '/api/auth_token.php',
        'objective' => 'A lockout now exists after repeated failures. Find two independent ways around it.',
        'difficulty' => 'Stretch',
        'concept' => 'A rate limit has to be keyed by something that actually, uniquely identifies the attacker across their requests — and both halves of a naive key can be wrong at once. A username comparison that\'s case-sensitive treats "alice" and "ALICE" as two different counters even though they target the same account; and a client-IP value read from a header the client itself sends (<code>X-Forwarded-For</code>) is exactly as trustworthy as any other request body — which is to say, not trustworthy at all unless a real reverse proxy is the one setting it.',
        'tools' => array('Burp Suite or curl', 'a known username'),
        'steps' => array(
            'Trigger the lockout normally: send enough wrong <code>api_key</code> guesses for one exact username/IP combination to get rate-limited.',
            'Confirm it\'s really locked out at that same exact username and your real IP — then retry with ONLY the username\'s capitalization changed.',
            'Separately, retry with the original exact username again, but this time send a different <code>X-Forwarded-For</code> header value on each request.',
        ),
        'hints' => array(
            'nudge' => 'The lockout is keyed by two pieces of information about you — your username and your "IP." Is either one of those actually fixed, from the server\'s point of view?',
            'answer' => 'Varying the username\'s capitalization (<code>Alice</code> vs <code>alice</code>) lands on a fresh counter because the comparison is case-sensitive; separately, setting a different <code>X-Forwarded-For: 1.2.3.4</code> value on every request resets the IP half of the key, since the server trusts that header outright instead of using the real connecting IP.',
        ),
    ),
    array(
        'title' => 'Fixate It, Then Wait For Remember-Me', 'module' => 'Session Fixation', 'target' => '/index.php',
        'objective' => 'The main password-login path now correctly regenerates the session ID. Find the *other* way a session gets established without that happening.',
        'difficulty' => 'Stretch',
        'concept' => 'A single login flow often has more than one entry point that ends in the same authenticated state — a password check, and a "remember me" cookie that silently logs the same account back in later. Fixing session handling on the first path is easy to verify and easy to call done; it\'s also easy to forget that the second, less-visible path produces an identical session and needs the identical fix, independently.',
        'tools' => array('Browser dev tools (to plant a known session ID cookie)', 'two browser profiles (attacker + victim)'),
        'steps' => array(
            'As the attacker, visit the login page and note your own pre-auth session ID (no login yet).',
            'Get the victim to open a link carrying that same session ID (fixation), then have the victim log in once and log out, leaving their "remember me" cookie in place.',
            'Wait for the remember-me cookie to silently re-authenticate the victim on a later visit, then check whether your originally-noted session ID is now the victim\'s logged-in session.',
        ),
        'hints' => array(
            'nudge' => 'You confirmed the password-check path regenerates the ID correctly. Is the "remember me" auto-login branch literally the same code, or a separate branch that might have been missed?',
            'answer' => 'The remember-me cookie branch in <code>index.php</code> logs the account back in without ever calling <code>session_regenerate_id()</code> — plant a session ID before the victim\'s remember-me auto-login fires, and that same ID becomes their authenticated session.',
        ),
    ),
    array(
        'title' => 'Frame the One Page That Forgot the Header', 'module' => 'Clickjacking', 'target' => '/user/verify_2fa.php',
        'objective' => 'Every normal page now sends <code>X-Frame-Options</code>. Find the one page in the app that doesn\'t, and frame it.',
        'difficulty' => 'Standard',
        'concept' => 'A security header added to one shared template protects every page that actually goes through that template — but not a page that was built as a standalone, lightweight file and never wired up to include the same shared chrome. That\'s often true of single-purpose flow steps (like a second-factor prompt) that get written quickly, outside the normal page structure, specifically because they\'re "just one small form."',
        'tools' => array('A simple local HTML file with an <code>&lt;iframe&gt;</code>'),
        'steps' => array(
            'Confirm a normal page like the dashboard now sends <code>X-Frame-Options</code> and refuses to render inside your test iframe.',
            'Log in with carol\'s account (2FA-enabled) to reach <code>/user/verify_2fa.php</code>, then try framing that specific page instead.',
            'Confirm it loads inside your iframe with no restriction, because this one page never goes through the header-sending shared template.',
        ),
        'hints' => array(
            'nudge' => 'The header is added in one shared file every normal page includes. Does every page in this app actually include it?',
            'answer' => '<code>/user/verify_2fa.php</code> is a standalone page that never includes <code>includes/header.php</code>, so it never gets <code>X-Frame-Options</code> — frame it directly and overlay a fake "Disable 2FA" button on top of its real one to clickjack the toggle.',
        ),
    ),
    array(
        'title' => 'Validate the URL, Then Follow It Somewhere Else', 'module' => 'SSRF — Link Preview', 'target' => '/user/link_preview.php',
        'objective' => 'The preview feature now properly validates the initial host against private IP ranges. Get it to fetch an internal address anyway.',
        'difficulty' => 'Stretch',
        'concept' => 'Validating a URL once, before the request is sent, only closes the SSRF if nothing *after* that validation can change where the request actually ends up going. A fetch that automatically follows redirects introduces exactly that gap: the first hop you validated is completely legitimate, and the server\'s own HTTP client decides, entirely on its own, to then follow a 3xx response to wherever its <code>Location</code> header points — without re-running the same check.',
        'tools' => array('A server you control (or a free redirect service) to host a redirect', 'curl or Burp'),
        'steps' => array(
            'Confirm a direct request to an internal address like <code>http://127.0.0.1/</code> is now correctly rejected before any fetch happens.',
            'Submit a URL to a server you control that responds with a 3xx redirect pointing at an internal address instead.',
            'Confirm the preview follows the redirect and fetches the internal resource, since only the original (externally-hosted, legitimate-looking) URL was ever validated.',
        ),
        'hints' => array(
            'nudge' => 'The validation runs once, before the fetch. What happens if the URL you submit is valid and external, but responds with a redirect?',
            'answer' => 'Host a redirect (HTTP 302 to <code>http://127.0.0.1/some-internal-path</code>) at a URL that passes the initial validation, and submit that URL — the preview\'s HTTP client follows the redirect without re-validating the new destination.',
        ),
    ),
    array(
        'title' => 'Exfiltrate Blind, One DNS Lookup at a Time', 'module' => 'XXE — Bulk Import Tickets', 'target' => '/admin/import_tickets.php',
        'objective' => 'Direct file disclosure is now closed. Describe how data could still be exfiltrated out-of-band, using a parameter entity instead of a general one.',
        'difficulty' => 'Stretch',
        'concept' => 'Disabling the straightforward "read a file and get it echoed straight back" path is the fix most people reach for first — but it only closes the path where the *response itself* carries the stolen data. A parameter entity (declared with <code>%name;</code> rather than <code>&amp;name;</code>) can reference an *external* DTD hosted on an attacker-controlled server, and that external DTD can itself build a request — e.g. to a URL containing the contents of a local file as part of the hostname — that the vulnerable server makes outbound, independent of whatever gets returned to the original caller. The attacker\'s own server, watching its access logs or DNS queries, receives the data; the HTTP response to the import request never needs to contain it at all.',
        'tools' => array('A server you control that can log inbound requests/DNS queries (conceptual exercise — not run live in this lab)'),
        'steps' => array(
            'Confirm direct external-entity file disclosure (your Simple/Intermediate payloads) no longer works at this tier.',
            'Research how a parameter entity referencing an attacker-hosted external DTD can still trigger an outbound request carrying stolen file contents, even when the *main* document\'s external entities are disabled.',
            'Write up the attack chain (XML payload → external DTD fetch → DTD-defined parameter entity reading a local file → that value used to build a URL requested by the target → data arrives in the attacker\'s own access log) as your submission — this one is intentionally not wired up as a live exploit in the lab, matching this app\'s existing restraint around payloads too risky to run destructively in a shared classroom environment.',
        ),
        'hints' => array(
            'nudge' => 'The fix closes entities that get *substituted back into the response*. Is there a different kind of entity, declared differently, that could carry data out through a completely different channel?',
            'answer' => 'A parameter entity (<code>%xxe;</code>) defined inside an attacker-hosted external DTD can reference a local file and splice its contents into a URL that the target server then requests on its own — the attacker never needs the import\'s own HTTP response to contain anything; the data shows up in their web server\'s access log instead. This is "blind" or out-of-band XXE.',
        ),
    ),
    array(
        'title' => 'The Allowlist That Checks for href, Not Just href', 'module' => 'DOM XSS — Search Deep Link', 'target' => '/user/tickets.php#q=',
        'objective' => 'The banner now uses an allowlist that keeps <code>&lt;a href&gt;</code> links but strips every other tag. Smuggle script execution through an allowed tag anyway.',
        'difficulty' => 'Stretch',
        'concept' => 'The same gap as this app\'s server-side "naive allowlist" ticket renderer, now in client-side JavaScript: a sanitizer that checks "is this an <code>&lt;a&gt;</code> tag with an <code>href</code> attribute present" and, satisfied, leaves the whole tag alone, has only verified that ONE attribute exists — it never looked at what OTHER attributes might also be sitting on that same tag.',
        'tools' => array('Browser address bar'),
        'steps' => array(
            'Confirm a bare <code>&lt;img onerror=...&gt;</code> payload is now stripped (not an <code>&lt;a&gt;</code> tag, so it doesn\'t pass the allowlist at all).',
            'Try an <code>&lt;a&gt;</code> tag that legitimately has an <code>href</code> attribute, but also carries an event-handler attribute alongside it.',
            'Confirm the whole tag survives the filter, and the event handler still fires.',
        ),
        'hints' => array(
            'nudge' => 'The filter\'s rule is "keep it if it\'s an &lt;a&gt; tag and has an href." Does satisfying that rule say anything about what ELSE is allowed to be on the tag?',
            'answer' => 'Visit <code>/user/tickets.php#q=&lt;a href=# onmouseover=alert(1)&gt;hover me&lt;/a&gt;</code> — it has a valid <code>href</code>, so the allowlist keeps the entire tag including <code>onmouseover</code>, which fires on interaction.',
        ),
    ),
    array(
        'title' => 'Six Digits, No Lockout', 'module' => '2FA Bypass', 'target' => '/user/verify_2fa.php',
        'objective' => 'The forgotten-endpoint gap is closed — every page now correctly requires a verified second factor. Show that the code-entry step itself has no limit on guesses.',
        'difficulty' => 'Standard',
        'concept' => 'Closing every bypass around a control doesn\'t help if the control itself can simply be brute-forced. A 6-digit TOTP code is one of one million possibilities at any given moment — a small enough space that, with no rate limiting or lockout on the verification endpoint, an attacker who already has a valid username/password (phished, leaked, reused) can simply guess codes until the current 30-second window\'s correct one lands, same as the existing login brute-force and API rate-limiting lessons elsewhere in this app.',
        'tools' => array('Burp Suite Intruder (or a scripted loop)', 'a valid username/password with 2FA enabled'),
        'steps' => array(
            'Log in with carol\'s correct password to reach the code-entry step.',
            'Send a long sequence of incorrect 6-digit codes in a tight loop.',
            'Confirm none of them trigger a lockout, delay, or any limiting response at all — the endpoint accepts guesses indefinitely.',
        ),
        'hints' => array(
            'nudge' => 'This app already has a login brute-force lesson and an API rate-limiting lesson elsewhere. Does the SAME kind of protection exist on the brand-new code-entry endpoint?',
            'answer' => 'Hammer <code>/user/verify_2fa.php</code> with sequential or random 6-digit codes after a valid password step — there\'s no attempt counter, delay, or lockout anywhere on this endpoint, so a 1-in-1,000,000 guess per 30-second window is the only thing standing between an attacker and a full bypass.',
        ),
    ),
    array(
        'title' => 'Escalate Someone Else\'s Ticket Yourself', 'module' => 'Business Logic — Escalation Workflow', 'target' => '/support/escalation_approve.php',
        'objective' => 'Escalation requests now correctly sit in a pending state. Approve your OWN pending request directly, without being staff at all.',
        'difficulty' => 'Stretch',
        'concept' => 'Introducing a pending state and an approval endpoint only creates a real approval gate if the approval endpoint itself checks who\'s allowed to approve. An endpoint that correctly requires *some* logged-in session, but never checks *which role* that session belongs to, has built the workflow\'s shape without building its actual security property — anyone, not just support/admin staff, can walk up and approve their own request.',
        'tools' => array('Burp Suite or curl', 'a plain non-staff account'),
        'steps' => array(
            'As a regular user, submit a "Request Urgent" on your own ticket and confirm it now sits in a <code>pending</code> state rather than applying immediately.',
            'Find the approval endpoint the staff UI posts to, and send that exact same request yourself, still logged in as the plain user.',
            'Confirm your own ticket gets approved to <code>urgent</code>, despite you never having support or admin privileges.',
        ),
        'hints' => array(
            'nudge' => 'The approval endpoint definitely requires you to be logged in. Does it separately require you to be logged in AS STAFF?',
            'answer' => 'POST <code>action=approve&amp;ticket_id=&lt;your own ticket&gt;</code> to <code>/support/escalation_approve.php</code> while logged in as a plain user — it only calls <code>require_login()</code>, never checking <code>$_SESSION[\'role\']</code>, so any authenticated account can approve any pending request, including their own.',
        ),
    ),
),

'expert' => array(
    array(
        'title' => 'No More SQLi — Break In Anyway', 'module' => 'Login', 'target' => '/index.php',
        'objective' => 'Every query is parameterized and there\'s no info leakage. The path in is credential/session attack, not injection.',
        'difficulty' => 'Standard',
        'concept' => 'A "secure" login form can still be attacked by pure repetition if nothing limits how many guesses it will accept. This isn\'t a code injection bug at all — it\'s the absence of a control (rate limiting / account lockout) that should exist alongside correct query handling. Security isn\'t just "did you sanitize input," it\'s also "did you constrain behavior an attacker could abuse even with perfectly clean input."',
        'tools' => array('Hydra or Burp Intruder', 'a small wordlist'),
        'steps' => array(
            'Confirm there is no lockout after repeated failed logins.',
            'Given the seed account naming pattern in this lab, build a small candidate password list.',
            'Run an online brute-force against the login form and see how long an unthrottled login endpoint survives.',
        ),
        'hints' => array(
            'nudge' => 'There\'s no injection bug left to find here — think about what happens if nothing at all stops you from simply trying password after password after password.',
            'answer' => 'This is exactly the class of finding you\'d write up as "Missing Rate Limiting on Authentication Endpoint" in a real bounty report — the vulnerable behavior isn\'t a payload, it\'s an absence of a control.',
        ),
    ),
    array(
        'title' => 'Attribute-Injection XSS', 'module' => 'Ticket Signature Sanitizer', 'target' => 'includes/render.php: naive_allowlist_sanitize()',
        'objective' => 'The app allows a small set of "safe" HTML tags (b, i, a) in one field via an allowlist sanitizer. Break out of it.',
        'difficulty' => 'Stretch',
        'concept' => 'An allowlist sanitizer has to validate every single attribute on a tag, not just confirm that one expected attribute is present somewhere. Checking "does this string contain the word href" is very different from "does this tag contain href and *nothing else*" — the first can be satisfied by a tag that also carries an <code>onmouseover</code> or similar event handler sitting right alongside the legitimate attribute, which the check never even looks at.',
        'tools' => array('Browser', 'source review — this one\'s a white-box challenge'),
        'steps' => array(
            'Read <code>naive_allowlist_sanitize()</code> in <code>includes/render.php</code> directly — this challenge is meant to be solved by reading the sanitizer\'s logic, the same way you\'d review a client\'s code in a source-available bounty program.',
            'Notice what the function checks for on an <code>&lt;a&gt;</code> tag, and what it does NOT check for.',
            'Craft an <code>&lt;a&gt;</code> tag that contains an <code>href</code> attribute (to satisfy the check) alongside an event-handler attribute (which the check never inspects).',
        ),
        'hints' => array(
            'nudge' => 'This sanitizer function is short — read it line by line and ask what it actually checks for on an &lt;a&gt; tag, versus what it removes.',
            'answer' => 'The function only confirms the substring "href" exists somewhere in the tag\'s attributes — it never validates that ONLY href is present.',
        ),
    ),
    array(
        'title' => 'Privilege Escalation via Mass Assignment', 'module' => 'Profile Update', 'target' => '/user/profile.php',
        'objective' => 'The profile form the browser renders has no role field for regular users. Become admin anyway.',
        'difficulty' => 'Standard',
        'concept' => 'What a form *shows* you and what the server will *accept* are two completely different things — the HTML is just a suggestion the browser normally follows, not an enforcement mechanism. If the server-side update code takes every field submitted and writes it to the matching database column without checking a fixed list of "fields this role is allowed to set," then hiding a field from the visible form provides zero actual protection: anyone sending a raw HTTP request (not using the rendered form at all) can include it anyway. This is called mass assignment.',
        'tools' => array('Burp Suite (Repeater)'),
        'steps' => array(
            'Log in as a regular user and submit a normal profile update; capture the POST request in Burp.',
            'Think about what the server-side handler does with fields it wasn\'t expecting — does it only save what the form shows, or everything submitted?',
            'Add a parameter to the captured request that the visible form never includes, with the value you want.',
        ),
        'hints' => array(
            'nudge' => 'The form you see in the browser is just a suggestion to the server about which fields to expect — what happens if you send one it never included at all?',
            'answer' => 'Add <code>&amp;role=admin</code> to the POST body and resend.',
        ),
    ),
    array(
        'title' => 'CSRF the Support Queue', 'module' => 'Support Ticket Status', 'target' => '/support/tickets.php',
        'objective' => 'Below this tier, ticket status changes have no CSRF protection at all. At expert, prove you understand why the token stops it.',
        'difficulty' => 'Standard',
        'concept' => 'A CSRF token works because it\'s something the attacker\'s page genuinely cannot know: a random value stored server-side in your session and expected back in the form submission. The attacker\'s forged page can make your browser send cookies (those attach automatically to any request), but it has no way to read your session data and copy the matching token into its form — so the server can tell "this request came from our own page" apart from "this request was forged elsewhere," purely by whether the right token showed up.',
        'tools' => array('Browser', 'a scratch HTML file'),
        'steps' => array(
            'Set the mode to <strong>hard</strong> temporarily and build a minimal auto-submitting HTML form pointed at <code>/support/tickets.php</code> with <code>ticket_id</code> and <code>status</code> fields, hosted anywhere.',
            'While logged in as <code>sam</code> in one browser tab, open your crafted page in another and confirm the ticket status changes without sam ever visiting the real app for that action.',
            'Switch the mode to <strong>expert</strong> and repeat the exact same PoC — confirm it now fails, and explain in your own write-up why the token defeats it.',
        ),
        'hints' => array(
            'nudge' => 'You\'ve already built this exact proof-of-concept once, for a lower tier — the only new question is whether the same trick still works once a token is required.',
            'answer' => 'A minimal PoC is: <code>&lt;form action="http://TARGET/support/tickets.php" method="POST"&gt;&lt;input name="ticket_id" value="1"&gt;&lt;input name="status" value="closed"&gt;&lt;/form&gt;&lt;script&gt;document.forms[0].submit()&lt;/script&gt;</code> — this is a defensive PoC pattern, the same one you\'d include in a real CSRF bug report.',
        ),
    ),
    array(
        'title' => 'Confirm the Backdoor Is Closed', 'module' => 'Create User (CSRF)', 'target' => '/admin/create_user.php',
        'objective' => 'Re-run the "Silent Backdoor Admin" PoC from the simple tier against this tier and confirm it now fails — then explain why in one paragraph.',
        'difficulty' => 'Standard',
        'concept' => 'This challenge is really about closing the loop: you saw the CSRF token explanation above in the abstract, now you\'re confirming it holds up against the *exact* attack that worked three tiers ago. If your explanation from the previous challenge is right, this should fail in a very specific, predictable way — not just "it doesn\'t work," but "it fails with an invalid-token error," because the token check is the only thing that changed between the two tiers.',
        'tools' => array('Browser', 'the same scratch HTML file from the simple-tier challenge'),
        'steps' => array(
            'Reuse (or rebuild) the auto-submitting form that targeted <code>/admin/create_user.php</code> on the simple tier.',
            'With the app in expert mode and logged in as admin, load the page and confirm no account is created — look for the specific error the server returns.',
            'Write one paragraph explaining, in report-style language, why the token stops a request the browser would otherwise happily send with valid session cookies attached.',
        ),
        'hints' => array(
            'nudge' => 'Reuse your Simple-tier attack unchanged and watch exactly how, and where, it fails now — the specific error message tells you what actually changed.',
            'answer' => 'The response should say "CSRF token invalid — request rejected." The key point for your write-up: the attacker\'s page can forge the request and the cookies ride along automatically, but it can\'t read the token out of your session to include it — that\'s the whole defense.',
        ),
    ),
    array(
        'title' => 'Outlive Your Own Password', 'module' => 'API Token (JWT) Auth', 'target' => '/api/auth_token.php, /api/ticket_update.php (Bearer header)',
        'objective' => 'Expiration is finally enforced too. Find the one way a token can still outlive the account state it was issued for.',
        'difficulty' => 'Stretch',
        'concept' => 'A signed, non-expired token with correct claims looks indistinguishable from a legitimate one, by design — that\'s the whole point of signing it. But "signed correctly" only proves the token hasn\'t been tampered with since issuance; it says nothing about whether the account it describes has changed since then. A stateless token scheme like this one has no built-in way to answer "has something happened to this account that should invalidate tokens issued before now?" unless the app deliberately adds one (a token-version column, a revocation list) — and this app never does, at any tier.',
        'tools' => array('Burp Suite', 'your own test account'),
        'steps' => array(
            'Log in as any user and get a token for yourself from <code>/api/auth_token.php</code>.',
            'Confirm the token works normally against <code>/api/ticket_update.php</code>.',
            'Change your own password via <code>/user/change_password.php</code> (a completely unrelated, legitimate feature) — then replay the exact same, still-unexpired token and see whether it still works.',
        ),
        'hints' => array(
            'nudge' => 'You just proved <code>exp</code> and the signature are both solid — now ask what changing an account\'s password is actually supposed to do to any tokens issued before that change.',
            'answer' => 'The token keeps working after the password change, because nothing in this app ever invalidates a previously-issued token for any reason short of its own <code>exp</code> timestamp — there\'s no revocation list or token-version check anywhere. In a real write-up, this is the "Missing Token Revocation on Credential Change" finding: not a payload, an absent control, the same flavor as the login brute-force finding elsewhere at this tier.',
        ),
    ),
    array(
        'title' => 'The Check Reads One Thing, the Write Reads Another', 'module' => 'API Ticket Update — Mass Assignment', 'target' => '/api/ticket_update.php',
        'objective' => '<code>priority</code> is now properly staff-only, checked against the POST body. Find the one place a request can still slip a restricted field through.',
        'difficulty' => 'Stretch',
        'concept' => 'PHP exposes request data through multiple distinct superglobals that largely overlap — <code>$_POST</code> only has the body\'s form-encoded fields, while <code>$_REQUEST</code> additionally folds in the query string. A security check and the code it\'s meant to gate have to read from the *same* source of truth, or the check can pass against one view of the request while a completely different value from another part of the same request gets written. This is the sort of bug a source-available review would need to actually read the code to find — a black-box attacker would have to notice the inconsistency by trial and error, the same white-box flavor as the signature-sanitizer attribute-injection XSS elsewhere in this app.',
        'tools' => array('Burp Suite', 'source review (this one\'s a white-box challenge)'),
        'steps' => array(
            'Confirm sending <code>priority</code> in the POST body as a non-staff owner is now correctly rejected.',
            'Read <code>api/ticket_update.php</code>\'s expert-tier branch directly — notice which superglobal the privilege check inspects, and which one the final write loop reads from.',
            'Resend the exact same update, but move <code>priority</code> from the POST body onto the URL\'s query string instead.',
        ),
        'hints' => array(
            'nudge' => 'The rejection you just triggered checked one specific PHP superglobal for the restricted field — does the code that actually performs the write look in exactly that same place, or somewhere broader?',
            'answer' => 'POST to <code>/api/ticket_update.php?priority=urgent</code> (field in the query string, not the POST body) with <code>ticket_id</code> still in the body — the privilege check only inspects <code>$_POST</code> and never sees it, but the write loop reads <code>$_REQUEST</code>, which includes the query string.',
        ),
    ),
    array(
        'title' => 'The One Address Every Blocklist Forgets', 'module' => 'SSRF — Link Preview', 'target' => '/user/link_preview.php',
        'objective' => 'Redirects are now re-validated at every hop and basic private ranges are blocked. Find the one reachable address that was never on the list.',
        'difficulty' => 'Stretch',
        'concept' => 'A hand-rolled "block private IP ranges" check is really a checklist of everything the author remembered to type in — RFC1918 ranges, loopback, maybe link-local in the abstract — and checklists are exactly as complete as the person writing them. The cloud-metadata address is link-local (<code>169.254.0.0/16</code>) but almost never shows up in anyone\'s mental model of "private ranges" unless they\'ve specifically been burned by it before, which makes it the single most common real-world gap in exactly this kind of filter — common enough that it\'s the example this app\'s own vulnerability reference names for SSRF.',
        'tools' => array('curl or Burp'),
        'steps' => array(
            'Confirm both a direct loopback request and a redirect to loopback are now correctly blocked at every hop.',
            'Submit <code>http://169.254.169.254/</code> directly as the URL to preview.',
            'Confirm it\'s fetched successfully — this address was never included in the private-range blocklist.',
        ),
        'hints' => array(
            'nudge' => 'The blocklist covers the ranges most people think of as "private." Is there a well-known internal-only address that technically belongs to a DIFFERENT, easy-to-forget range?',
            'answer' => '<code>169.254.169.254</code> — the cloud instance-metadata address — is link-local (<code>169.254.0.0/16</code>), a range the hand-rolled check never accounts for. On a real cloud deployment this is how SSRF leads to full credential theft; here, confirming the fetch succeeds at all is the proof.',
        ),
    ),
    array(
        'title' => 'Confirm the Deep Link Is Finally Safe', 'module' => 'DOM XSS — Search Deep Link', 'target' => '/user/tickets.php#q=',
        'objective' => 'The banner now writes the fragment value using <code>textContent</code> instead of <code>innerHTML</code>. Confirm every prior payload fails, and explain the one-line fix in your own words.',
        'difficulty' => 'Standard',
        'concept' => 'This closes the loop the same way the CSRF module\'s expert tier does: <code>textContent</code> assigns a string as literal text, full stop — the browser never parses it as markup, so there is no tag, attribute, or event handler for any payload to hide inside, regardless of how the filtering logic upstream of it is written. The fix isn\'t a better filter; it\'s using an API that was never capable of interpreting its input as HTML in the first place.',
        'tools' => array('Browser address bar'),
        'steps' => array(
            'Re-run your Hard-tier <code>&lt;a href=# onmouseover=...&gt;</code> payload (and the earlier simple/intermediate ones) unchanged against this tier.',
            'Confirm the banner now displays the literal, inert text of your payload instead of executing anything.',
            'View the page source or dev tools to see that the value was assigned via <code>textContent</code>, and write one sentence on why that makes the specific filtering bypasses you used earlier irrelevant.',
        ),
        'hints' => array(
            'nudge' => 'Every previous bypass depended on the browser parsing your fragment value AS markup. What changes if the assignment never triggers HTML parsing at all?',
            'answer' => 'All prior payloads now render as plain, visible text — <code>element.textContent = value</code> never interprets its argument as HTML, so there is no allowlist or blacklist left to bypass; the sink itself stopped being exploitable.',
        ),
    ),
    array(
        'title' => 'The Cookie That Never Needed the Code', 'module' => '2FA Bypass', 'target' => '/user/verify_2fa.php',
        'objective' => 'Code-guessing is now rate-limited. Skip entering a code at all, using the "remember this device" feature.',
        'difficulty' => 'Stretch',
        'concept' => 'A "remember this device" convenience feature has to generate a token that\'s actually unpredictable, because once set, that cookie is functionally equivalent to a completed second factor — anyone who can produce a valid one skips 2FA entirely, forever (or until it expires), with no code-guessing involved at all. Deriving it from a value that\'s not even secret, like the username, makes it trivial to forge for any account, the same weak-token pattern this app\'s own password-reset module already uses at its simple tier.',
        'tools' => array('Browser dev tools (to set a cookie manually)', 'a target username'),
        'steps' => array(
            'Log in once with carol\'s correct password and complete 2FA normally, checking "remember this device" — note the resulting cookie\'s name and value.',
            'Figure out how that value relates to the username, without ever looking at server source.',
            'Clear your session, then manually set a forged cookie built the same way for carol\'s account and visit the login page — confirm you land on the dashboard with no code ever requested.',
        ),
        'hints' => array(
            'nudge' => 'Compare the remember-device cookie\'s value against the account\'s username using a few common hash functions. Does it match any of them directly?',
            'answer' => 'The cookie is <code>trusted_device_&lt;user_id&gt; = md5(username)</code> — compute <code>md5("carol")</code> yourself, set that as the cookie value, and the login flow skips straight past the code-entry step entirely, independent of any rate limiting on the code itself.',
        ),
    ),
    array(
        'title' => 'The Other Header Nobody Keyed the Cache On', 'module' => 'Cache Poisoning — Login Page', 'target' => '/index.php',
        'objective' => 'The canonical-link header is now excluded from the cached response entirely. Find the other, unrelated header still being reflected into the same cached page.',
        'difficulty' => 'Standard',
        'concept' => 'Fixing the specific header a reviewer was shown (or found first) doesn\'t mean every other unkeyed, reflected header on the same page got the same review — a "preferred language" banner is a completely different feature, built separately, and easy to overlook once attention has already moved on to the header everyone was focused on. The underlying lesson repeats: the cache still doesn\'t vary by this header either, so the same poisoning mechanics apply, just through a different, lower-profile value.',
        'tools' => array('curl (two separate requests, as in the earlier cache-poisoning challenge)'),
        'steps' => array(
            'Confirm <code>X-Forwarded-Host</code> no longer gets reflected into the cached canonical link at all.',
            'Request <code>/index.php?cb=2</code> with a crafted <code>Accept-Language</code> header value instead, then request the same URL again with no special header.',
            'Confirm the "preferred language" banner on the clean second request still shows your crafted value, proving this second header is still being cached unkeyed.',
        ),
        'hints' => array(
            'nudge' => 'One reflected header just got fixed. Is it the only piece of request data this page reflects into HTML that then gets cached?',
            'answer' => '<code>curl -H "Accept-Language: &lt;script&gt;evil&lt;/script&gt;" "http://TARGET/vulnapp/index.php?cb=2"</code>, then a clean request to the same URL — the "preferred language" banner still carries your value from the earlier poisoned entry, since <code>Accept-Language</code> was never added to the cache key either.',
        ),
    ),
    array(
        'title' => 'Deny It, Then Just Ask Again', 'module' => 'Business Logic — Escalation Workflow', 'target' => '/user/tickets.php',
        'objective' => 'Approval is now correctly staff-only. Show that nothing stops a denied request from simply being resubmitted, over and over, with no limit.',
        'difficulty' => 'Standard',
        'concept' => 'A workflow can have every individual step correctly gated — a real pending state, a real staff-only approval check — and still have no answer to "what stops someone from just doing the request step again immediately." That\'s not a flaw in any single check; it\'s the absence of a control that spans the whole workflow (a cooldown, a per-user cap on open requests), the same "missing control, not a broken one" flavor as this app\'s other expert-tier absence-of-rate-limiting findings.',
        'tools' => array('Browser or a scripted loop', 'a staff account to issue denials'),
        'steps' => array(
            'As a regular user, request escalation on a ticket, then have a staff account deny it.',
            'Immediately request escalation again on the same ticket.',
            'Repeat several times in quick succession and confirm there\'s no cooldown, cap, or any limit on how many times the request step can be resubmitted after a denial.',
        ),
        'hints' => array(
            'nudge' => 'Every individual step in this workflow is now correctly checked. Is there anything at all limiting how many TIMES you\'re allowed to go through the whole workflow?',
            'answer' => 'Resubmit <code>action=request_escalation</code> on the same ticket repeatedly right after a staff denial — it goes back to <code>pending</code> every single time, with no cooldown or cap, letting a user flood the staff queue with the same request indefinitely.',
        ),
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
// Capture-the-flag challenges — like $recon above, these are NOT gated
// by the difficulty toggle (both chains below work at every tier; see
// each entry's clue for why). Each rewards a literal FLAG{...} string
// instead of just confirming a bypass, and each chains more than one
// bug together rather than exercising a single vulnerability class.
// ---------------------------------------------------------------
$ctf_flags = array(
    array(
        'title' => 'The Forgotten Export', 'module' => 'Chained: Profile IDOR → API Key Leak → JWT Auth', 'target' => '/user/profile_export.php, /api/auth_token.php, /api/tickets.php',
        'objective' => 'Starting from a brand-new, unprivileged account, chain three separate bugs into reading a ticket only an admin should ever see — and recover the flag inside it.',
        'tools' => array('Browser or Burp Suite', 'curl (optional, for the API steps)'),
        'steps' => array(
            'Log in as any seeded non-admin account and request <code>/user/profile_export.php?id=1</code> (admin\'s user id) — this endpoint has no ownership check at any difficulty tier.',
            'From the JSON it returns, note the <code>api_key</code> field — a credential, not harmless metadata, even though this endpoint treats it that way.',
            'Exchange that leaked <code>api_key</code> (with username <code>admin</code>) for a JWT at <code>/api/auth_token.php</code>.',
            'Use the resulting token as a Bearer token against <code>/api/tickets.php?id=3</code> and read the flag in the ticket\'s message.',
        ),
        'clue' => 'This chain works at every difficulty tier, because the first link — <code>profile_export.php</code>\'s missing ownership check — was never gated by the difficulty toggle in the first place (see the Hard-tier "The Endpoint They Forgot" challenge above). Everything downstream of leaking that one field just follows from there.',
    ),
    array(
        'title' => 'Forge Your Way In', 'module' => 'API Ticket Update — Unverified Admin Branch', 'target' => '/api/ticket_update.php?admin_note=1',
        'objective' => 'Reach a hidden admin-only branch of the ticket-update API using nothing but a hand-forged, completely unsigned token — no valid credentials of any kind, and independent of whatever difficulty tier the app is set to.',
        'tools' => array('Burp Suite or curl', 'a scratch script to base64url-encode JSON'),
        'steps' => array(
            'Build your own unsigned JWT: header <code>{"typ":"JWT","alg":"none"}</code>, payload <code>{"role":"admin"}</code>, empty signature segment.',
            'Send it as a Bearer token to <code>/api/ticket_update.php?admin_note=1</code> — note the <code>admin_note</code> query parameter.',
            'Confirm it works regardless of the app\'s current difficulty setting, and recover the flag in the response.',
        ),
        'clue' => 'Not every endpoint necessarily routes its auth through the same shared, tier-aware check as the rest of the app — this one was wired to a raw token decoder instead, the same "forgot to call the shared check" shape as a couple of this app\'s other bugs. Difficulty-tier fixes elsewhere in the JWT module never touch this specific branch at all.',
    ),
);

// ---------------------------------------------------------------
// Tools reference — organized by phase of a real engagement, in
// progression order (passive before active, broad before targeted).
// Every entry that can be, is tied to a specific VulnCorp challenge
// above so the syntax isn't just abstract - you can run it against
// this lab right now. Some phases (subdomain enum, Google dorking,
// Shodan) don't really apply to a single-host internal lab like this
// one; those are marked honestly rather than forced into a fake tie-in.
// ---------------------------------------------------------------
$tools_reference = array(
    array(
        'phase' => 'Step 1 — Subdomain Enumeration',
        'intro' => 'Mostly a real-bounty-target concern (finding forgotten subdomains on a large scope). This lab is a single host with no subdomains, so treat this step as "know the syntax," not "expect results here."',
        'tools' => array(
            array('name' => 'crt.sh', 'type' => 'passive', 'kali' => 'Browser or curl — no install needed', 'does' => 'Searches certificate transparency logs for every subdomain that has ever had a cert issued', 'example' => 'curl -s "https://crt.sh/?q=%.example.com&output=json" | jq -r \'.[].name_value\' | sort -u', 'tie' => 'Not applicable to this lab (no public cert/DNS for a local VM). Use on real programs before anything else.'),
            array('name' => 'subfinder', 'type' => 'passive', 'kali' => 'Preinstalled on Kali', 'does' => 'Aggregates subdomains from 20+ passive OSINT sources', 'example' => 'subfinder -d example.com -o subs.txt', 'tie' => 'Not applicable to this lab.'),
            array('name' => 'amass (passive)', 'type' => 'passive', 'kali' => 'Preinstalled on Kali', 'does' => 'Same idea as subfinder, broader source list, slower', 'example' => 'amass enum -passive -d example.com -o subs.txt', 'tie' => 'Not applicable to this lab.'),
            array('name' => 'theHarvester', 'type' => 'passive', 'kali' => 'Preinstalled on Kali', 'does' => 'Pulls subdomains, emails, and hosts from search engines/OSINT sources', 'example' => 'theHarvester -d example.com -b all', 'tie' => 'Not applicable to this lab — but this is the same tool from Week 5 OSINT in the training program.'),
            array('name' => 'amass (active)', 'type' => 'active', 'kali' => 'Preinstalled on Kali', 'does' => 'Adds DNS brute force + zone transfer attempts on top of passive mode', 'example' => 'amass enum -active -d example.com -o subs.txt', 'tie' => 'Not applicable to this lab.'),
        ),
    ),
    array(
        'phase' => 'Step 2 — Live Host Probing',
        'intro' => 'This is where this lab actually starts — confirming what\'s up and what it\'s running.',
        'tools' => array(
            array('name' => 'nmap -sn', 'type' => 'active', 'kali' => 'Preinstalled on Kali', 'does' => 'Ping sweep — which hosts on a range are actually up', 'example' => 'sudo nmap -sn 192.168.50.0/24', 'tie' => 'Same command style you already used to relocate Metasploitable2 after the network change.'),
            array('name' => 'nmap -sV', 'type' => 'active', 'kali' => 'Preinstalled on Kali', 'does' => 'Full port + service/version scan', 'example' => 'nmap -sV -p- 192.168.50.20', 'tie' => 'Ties directly to the "Map the Attack Surface" and "Fingerprint the Stack" recon challenges above.'),
            array('name' => 'httpx', 'type' => 'active', 'kali' => 'apt install httpx-toolkit (Kali repo) or go install', 'does' => 'Takes a host/URL list, checks which respond over HTTP(S), grabs status/title/tech in one pass', 'example' => 'echo "192.168.50.20/vulnapp/" | httpx -status-code -title -tech-detect', 'tie' => 'Faster alternative to manually curling each VulnCorp page during "Fingerprint the Stack."'),
            array('name' => 'masscan', 'type' => 'active', 'kali' => 'Preinstalled on Kali', 'does' => 'Extremely fast port scan across large ranges — run before a slower nmap -sV, not instead of it', 'example' => 'sudo masscan -p1-65535 192.168.50.20 --rate=1000', 'tie' => 'Not needed for a single host, but this is the right tool if the lab ever grows to multiple VMs.'),
        ),
    ),
    array(
        'phase' => 'Step 3 — Content Discovery / Crawling',
        'intro' => 'This is exactly how a real tester would find profile_export.php — not by being told, by brute-forcing.',
        'tools' => array(
            array('name' => 'Wayback / waybackurls', 'type' => 'passive', 'kali' => 'go install github.com/tomnomnom/waybackurls@latest', 'does' => 'Pulls historically archived URLs for a domain with zero live traffic to the target', 'example' => 'echo "example.com" | waybackurls', 'tie' => 'Not applicable — this lab has never been publicly crawled/archived.'),
            array('name' => 'ffuf', 'type' => 'active', 'kali' => 'Preinstalled on Kali', 'does' => 'Fast wordlist-based directory/file brute force', 'example' => 'ffuf -u http://192.168.50.20/vulnapp/FUZZ.php -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200,301,302,403', 'tie' => 'This exact command is how you\'d discover "profile_export.php" for the Hard-tier "The Endpoint They Forgot" challenge, before ever reading the clue.'),
            array('name' => 'gobuster dir', 'type' => 'active', 'kali' => 'Preinstalled on Kali', 'does' => 'Same idea as ffuf, different tool — good to know both since programs sometimes block one but not the other', 'example' => 'gobuster dir -u http://192.168.50.20/vulnapp/ -w /usr/share/wordlists/dirb/common.txt -x php', 'tie' => 'Same target as the ffuf example — try both and compare hit lists.'),
            array('name' => 'dirb', 'type' => 'active', 'kali' => 'Preinstalled on Kali', 'does' => 'Older, slower directory brute-forcer — what the earlier README deploy discussion referenced', 'example' => 'dirb http://192.168.50.20/vulnapp/', 'tie' => 'Same target — this is the tool named in the "Recon Challenges" description above.'),
            array('name' => 'Burp Suite Spider', 'type' => 'active', 'kali' => 'Preinstalled on Kali', 'does' => 'Crawls the app as you click through it, builds a site map from real browsing traffic', 'example' => '(GUI tool — set browser proxy to 127.0.0.1:8080, browse the app logged in as each role)', 'tie' => 'Ties to "Crawl the App Like a User Would" — the best way to find the role-gated pages ffuf alone would miss.'),
            array('name' => 'hakrawler', 'type' => 'active', 'kali' => 'go install github.com/hakluke/hakrawler@latest', 'does' => 'Fast crawler that pulls endpoints out of HTML and linked JS files', 'example' => 'echo "http://192.168.50.20/vulnapp/" | hakrawler', 'tie' => 'Alternative to Burp Spider for the same recon challenge, scriptable/faster for repeat runs.'),
        ),
    ),
    array(
        'phase' => 'Step 4 — Parameter Discovery',
        'intro' => 'The strongest tie-in on this whole page — this is the intended, non-source-reading way to find the expert-tier mass-assignment bug.',
        'tools' => array(
            array('name' => 'ParamSpider', 'type' => 'passive', 'kali' => 'git clone from GitHub, not preinstalled', 'does' => 'Mines likely parameter names out of Wayback-archived URLs for a domain', 'example' => 'python3 paramspider.py -d example.com', 'tie' => 'Not applicable — no archive history for this lab.'),
            array('name' => 'Arjun', 'type' => 'active', 'kali' => 'pip install arjun, or apt install arjun on recent Kali', 'does' => 'Actively brute-forces hidden GET/POST parameter names against a live endpoint', 'example' => 'arjun -u http://192.168.50.20/vulnapp/user/profile.php -m POST', 'tie' => 'This is the real way to discover the hidden "role" parameter for the Expert-tier "Privilege Escalation via Mass Assignment" challenge — the visible form never shows it to a non-admin, but Arjun brute-forcing common parameter names will surface it without reading includes/render.php or the clue.'),
            array('name' => 'x8', 'type' => 'active', 'kali' => 'cargo install x8, or download release binary — not preinstalled', 'does' => 'Same purpose as Arjun, Rust-based, generally faster on large wordlists', 'example' => 'x8 -u http://192.168.50.20/vulnapp/user/profile.php -X POST -w params.txt', 'tie' => 'Same target/goal as the Arjun example — good to compare speed/results between the two.'),
        ),
    ),
    array(
        'phase' => 'Step 5 — Vulnerability Scanning',
        'intro' => 'Automated scanners are a starting point on this lab, not the main event — see the "Quick Misconfig Sweep" challenge\'s own note about this.',
        'tools' => array(
            array('name' => 'Nikto', 'type' => 'active', 'kali' => 'Preinstalled on Kali', 'does' => 'General web server misconfig / outdated-software scanner', 'example' => 'nikto -h http://192.168.50.20/vulnapp/', 'tie' => 'Same tool and target as the "Quick Misconfig Sweep" recon challenge above.'),
            array('name' => 'sqlmap', 'type' => 'active', 'kali' => 'Preinstalled on Kali', 'does' => 'Automated SQL injection detection and exploitation', 'example' => 'sqlmap -r login.req -p username --dump   # capture the login POST in Burp first, save as login.req', 'tie' => 'Directly named in the "Dump the Users Table" Simple-tier challenge — this is the intended tool for that one.'),
            array('name' => 'Nuclei', 'type' => 'active', 'kali' => 'Preinstalled on Kali', 'does' => 'Template-based scanner covering thousands of known CVEs/misconfigs', 'example' => 'nuclei -u http://192.168.50.20/vulnapp/ -t exposures/', 'tie' => 'Limited value on VulnCorp itself since it\'s custom code, not a known product — but run it against Metasploitable2\'s other services (port 8180 Tomcat, port 21 vsftpd) for a good demonstration of what it\'s actually for.'),
            array('name' => 'OWASP ZAP (automated scan)', 'type' => 'active', 'kali' => 'Preinstalled on Kali', 'does' => 'Active spider + automated vulnerability scan combined, GUI or CLI', 'example' => 'zap-cli quick-scan --self-contained http://192.168.50.20/vulnapp/', 'tie' => 'Good comparison run against the same target as the sqlmap/Nikto examples — see what it catches vs. misses on the app-logic bugs (IDOR, mass assignment) that need a human.'),
        ),
    ),
    array(
        'phase' => 'Step 6 — Manual Recon',
        'intro' => 'No tool replaces actually reading the app.',
        'tools' => array(
            array('name' => 'Google dorking', 'type' => 'passive', 'kali' => 'Browser — no install', 'does' => '`site:`, `filetype:`, `inurl:` searches for exposed files/panels on public targets', 'example' => 'site:example.com filetype:env', 'tie' => 'Not applicable — this lab isn\'t publicly indexed.'),
            array('name' => 'Shodan / Censys', 'type' => 'passive', 'kali' => 'Browser or API — no install', 'does' => 'Search pre-indexed internet-wide scan data without ever touching the target directly', 'example' => 'shodan search "apache 2.2.8"', 'tie' => 'Not applicable to an internal lab VM — this is purely a real-target tool.'),
            array('name' => 'Manual browsing + view-source', 'type' => 'active (low-volume)', 'kali' => 'Browser + Burp proxy', 'does' => 'Clicking through the app as each role, reading rendered HTML, forming hypotheses before testing them', 'example' => '(no command — log in as admin/sam/alice/bob in turn, compare what each role can see)', 'tie' => 'This is literally the "Crawl the App Like a User Would" recon challenge.'),
        ),
    ),
    array(
        'phase' => 'Step 7 — Proxy / Interactive Testing',
        'intro' => 'The main workhorse for everything past recon — almost every challenge on this page assumes one of these is running.',
        'tools' => array(
            array('name' => 'Burp Suite', 'type' => 'active', 'kali' => 'Preinstalled on Kali', 'does' => 'Intercept, Repeater, and manual tampering with every request', 'example' => 'Proxy tab -> set browser to 127.0.0.1:8080 -> Intercept on -> submit the login form -> send to Repeater -> edit username to admin\' -- -', 'tie' => 'Used across nearly every challenge on this page, from the Simple-tier auth bypass through the Expert-tier CSRF confirmation.'),
            array('name' => 'OWASP ZAP (manual/proxy mode)', 'type' => 'active', 'kali' => 'Preinstalled on Kali', 'does' => 'Free/open-source alternative to Burp, same core intercept-and-tamper workflow', 'example' => 'Tools -> Options -> Local Proxy -> set browser to 127.0.0.1:8081', 'tie' => 'Drop-in alternative to Burp for any challenge above if you want to compare workflows.'),
            array('name' => 'mitmproxy', 'type' => 'active', 'kali' => 'Preinstalled on Kali', 'does' => 'Terminal-based intercepting proxy, scriptable in Python', 'example' => 'mitmproxy --listen-port 8082', 'tie' => 'Good option for scripting the CSRF PoC auto-submit tests (Support Queue / Create User challenges) instead of a static HTML file.'),
        ),
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
    array('Broken Auth', 'Default creds, password reset flaws, 2FA bypass, session fixation, JWT issues (alg confusion, missing expiry, no revocation)'),
    array('Access Control', 'IDOR, horizontal/vertical privilege escalation, forced browsing, BOLA'),
    array('Business Logic', 'Race conditions, workflow bypass, price manipulation, coupon abuse'),
    array('File Upload', 'Web shells, extension bypass, path traversal, content-type spoofing'),
    array('SSRF', 'Internal IP access, cloud metadata (169.254.169.254), protocol smuggling'),
    array('CSRF', 'Missing/weak tokens, method change (POST→GET)'),
    array('Info Disclosure', 'Exposed .git/.env, verbose errors, API keys in source, directory listing'),
    array('Misconfig', 'CORS, security headers, open redirects, verbose errors, debug endpoints'),
    array('API-specific', 'Mass assignment, broken object-level auth, rate limiting, GraphQL introspection'),
    array('CTF-style chains', 'Multi-step flag challenges that combine several of the categories above into one exploit path'),
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

// Sort challenges within a tier by difficulty (Entry -> Standard -> Stretch),
// preserving original relative order within the same difficulty. Named
// function (not a closure) for PHP 5.2 compatibility - see includes/render.php
// for the same pattern and why.
$GLOBALS['_difficulty_rank'] = array('Entry' => 0, 'Standard' => 1, 'Stretch' => 2);
function _challenge_difficulty_sort($a, $b) {
    $rank = $GLOBALS['_difficulty_rank'];
    $ra = isset($a['difficulty'], $rank[$a['difficulty']]) ? $rank[$a['difficulty']] : 1;
    $rb = isset($b['difficulty'], $rank[$b['difficulty']]) ? $rank[$b['difficulty']] : 1;
    if ($ra !== $rb) { return $ra - $rb; }
    return $a['_orig_idx'] - $b['_orig_idx'];
}
function sort_challenges_by_difficulty($list) {
    $idx = 0;
    foreach ($list as $k => $v) { $list[$k]['_orig_idx'] = $idx++; }
    usort($list, '_challenge_difficulty_sort');
    return $list;
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
<div class="challenge-card" id="feedback-<?php echo htmlspecialchars($cid); ?>" style="border:1px solid #e5e7eb;border-radius:6px;padding:14px 18px;margin-bottom:14px;background:#fff;transition:opacity .2s;">
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
    <?php render_feedback_widget($cid, $my_votes); ?>
</div>
<?php endforeach; ?>

<h3 style="margin-top:34px;">Capture the Flag <span class="small">(also not gated by difficulty — chain these whenever you're ready)</span></h3>
<p class="small">Two standalone flag challenges, each chaining more than one bug in this app together rather than
exercising a single vulnerability class. Both work at every difficulty tier — see each one's clue for why.</p>
<?php foreach ($ctf_flags as $c):
    $cid = challenge_slug('ctf', $c['title']);
?>
<div class="challenge-card" id="feedback-<?php echo htmlspecialchars($cid); ?>" style="border:1px solid #f59e0b;border-radius:6px;padding:14px 18px;margin-bottom:14px;background:#fffbeb;transition:opacity .2s;">
    <label style="display:flex;align-items:flex-start;gap:8px;cursor:pointer;">
        <input type="checkbox" class="challenge-progress-box" data-challenge-id="<?php echo htmlspecialchars($cid); ?>" style="width:auto;margin-top:4px;">
        <span>
    <strong>🚩 <?php echo htmlspecialchars($c['title']); ?></strong>
    <span class="small"> — <?php echo htmlspecialchars($c['module']); ?> · target: <code><?php echo htmlspecialchars($c['target']); ?></code></span>
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
    <?php render_feedback_widget($cid, $my_votes); ?>
</div>
<?php endforeach; ?>

<h3 style="margin-top:34px;">Tools Reference — by Phase (Passive → Active)</h3>
<p class="small"><span style="background:#dcfce7;color:#166534;padding:1px 7px;border-radius:3px;font-size:12px;">🟢 Passive</span> = no direct traffic to the target, safe and undetectable, uses third-party sources.
<span style="background:#ffedd5;color:#9a3412;padding:1px 7px;border-radius:3px;font-size:12px;margin-left:6px;">🟠 Active</span> = touches the target directly — can be logged, rate-limited, or blocked.
Within each phase, exhaust passive options first; only escalate to active tools once passive recon is genuinely exhausted — and active recon (phases 1–2) should always come before active exploitation (phases 4–7).</p>

<?php foreach ($tools_reference as $block): ?>
<h4 style="margin-top:24px;"><?php echo htmlspecialchars($block['phase']); ?></h4>
<p class="small"><?php echo htmlspecialchars($block['intro']); ?></p>
<?php foreach ($block['tools'] as $t):
    $is_active = (strpos($t['type'], 'active') === 0);
    $badge = $is_active
        ? '<span style="background:#ffedd5;color:#9a3412;padding:1px 7px;border-radius:3px;font-size:11px;">🟠 ' . htmlspecialchars($t['type']) . '</span>'
        : '<span style="background:#dcfce7;color:#166534;padding:1px 7px;border-radius:3px;font-size:11px;">🟢 passive</span>';
?>
<div style="border:1px solid #e5e7eb;border-radius:6px;padding:12px 16px;margin-bottom:10px;background:#fff;">
    <strong><?php echo htmlspecialchars($t['name']); ?></strong> <?php echo $badge; ?>
    <span class="small"> — <?php echo htmlspecialchars($t['kali']); ?></span>
    <p class="small" style="margin:6px 0;"><?php echo htmlspecialchars($t['does']); ?></p>
    <pre style="background:#111;color:#0f0;padding:8px 12px;border-radius:4px;overflow:auto;font-size:12.5px;margin:6px 0;"><?php echo htmlspecialchars($t['example']); ?></pre>
    <p class="small" style="margin:6px 0 0;"><strong>On this lab:</strong> <?php echo htmlspecialchars($t['tie']); ?></p>
</div>
<?php endforeach; ?>
<?php endforeach; ?>

<?php foreach ($tier_order as $tier):
    $is_current = ($tier === $difficulty);
?>
<h3 style="margin-top:34px;<?php if($is_current) echo 'color:#2563eb;'; ?>">
    <?php echo htmlspecialchars($tier_labels[$tier]); ?> tier
    <?php if ($is_current): ?><span class="small">(active now)</span><?php endif; ?>
</h3>

<?php $sorted_list = sort_challenges_by_difficulty($challenges[$tier]);
foreach ($sorted_list as $c):
    $cid = challenge_slug($tier, $c['title']);
    $diff_colors = array(
        'Entry' => array('bg' => '#dcfce7', 'fg' => '#166534'),
        'Standard' => array('bg' => '#fef9c3', 'fg' => '#854d0e'),
        'Stretch' => array('bg' => '#fee2e2', 'fg' => '#991b1b'),
    );
    $dc = isset($c['difficulty'], $diff_colors[$c['difficulty']]) ? $diff_colors[$c['difficulty']] : array('bg' => '#e5e7eb', 'fg' => '#374151');
?>
<div class="challenge-card" id="feedback-<?php echo htmlspecialchars($cid); ?>" style="border:1px solid #e5e7eb;border-radius:6px;padding:14px 18px;margin-bottom:14px;background:<?php echo $is_current ? '#f8fafc' : '#fff'; ?>;transition:opacity .2s;">
    <label style="display:flex;align-items:flex-start;gap:8px;cursor:pointer;">
        <input type="checkbox" class="challenge-progress-box" data-challenge-id="<?php echo htmlspecialchars($cid); ?>" style="width:auto;margin-top:4px;">
        <span>
    <strong><?php echo htmlspecialchars($c['title']); ?></strong>
    <?php if (isset($c['difficulty'])): ?>
    <span class="small" style="background:<?php echo $dc['bg']; ?>;color:<?php echo $dc['fg']; ?>;padding:1px 7px;border-radius:3px;font-size:11px;margin-left:4px;"><?php echo htmlspecialchars($c['difficulty']); ?></span>
    <?php endif; ?>
    <span class="small"> — <?php echo htmlspecialchars($c['module']); ?> · target: <code><?php echo htmlspecialchars($c['target']); ?></code></span>
        </span>
    </label>
    <p><?php echo $c['objective']; // contains inline <code> markup by design ?></p>
    <?php if (isset($c['concept'])): ?>
    <div style="background:#eff6ff;border-left:3px solid #2563eb;padding:8px 12px;margin:8px 0;border-radius:0 4px 4px 0;">
        <span class="small" style="color:#1e40af;font-weight:bold;">Why this works:</span>
        <p class="small" style="margin:4px 0 0;color:#1e3a8a;"><?php echo $c['concept']; // contains inline <code> markup by design ?></p>
    </div>
    <?php endif; ?>
    <p class="small"><strong>Tools:</strong> <?php echo htmlspecialchars(implode(', ', $c['tools'])); ?></p>
    <ol>
        <?php foreach ($c['steps'] as $s): ?><li><?php echo $s; // inline <code> markup by design ?></li><?php endforeach; ?>
    </ol>
    <?php if (isset($c['hints'])): ?>
    <details>
        <summary>Nudge (light hint)</summary>
        <p><?php echo $c['hints']['nudge']; // inline <code> markup by design ?></p>
    </details>
    <details style="margin-top:6px;">
        <summary>Full answer</summary>
        <p><?php echo $c['hints']['answer']; // inline <code> markup by design ?></p>
    </details>
    <?php elseif (isset($c['clue'])): ?>
    <details>
        <summary>Reveal clue</summary>
        <p><?php echo $c['clue']; // inline <code> markup by design ?></p>
    </details>
    <?php endif; ?>
    <?php render_feedback_widget($cid, $my_votes); ?>
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
<p class="small">This app currently exercises rows 1 (Injection, including XXE via the Bulk Import Tickets module), 2 (Broken Auth, including JWT issues via the API Token (JWT) Auth module, plus session fixation and 2FA bypass via the Enable 2FA/Verify 2FA modules), 3 (Access Control), 4 (Business Logic, via the ticket escalation-approval workflow), 5 (File Upload), 6 (SSRF, via the Link Preview module), 7 (CSRF), 10 (API-specific), 11 (CTF-style chains), 12 (Client-side, via clickjacking on the 2FA toggle and DOM XSS on the ticket search deep link), and 13 (Advanced, via cache poisoning on the login page) — rows 8 (Info Disclosure) and 9 (Misconfig, beyond the clickjacking header covered under row 12) are worth knowing for real targets even though they're not modeled here yet.</p>

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
