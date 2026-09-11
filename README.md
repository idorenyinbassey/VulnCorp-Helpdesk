# VulnCorp Helpdesk — Intentionally Vulnerable Training App

A small LAMP (Linux/Apache/MySQL/PHP) app built for teaching web
application security, in the same spirit as DVWA/Mutillidae. It has
three roles (**admin**, **support**, **user**), a global
**difficulty toggle** (Simple → Intermediate → Hard → Expert) that
changes *how* each vulnerability is exploitable, and an in-app
**Challenges** page (`/challenges/index.php`) with per-tier
objectives, required tools, steps, and revealable clues.

> ⚠️ **Use only on an isolated lab network** (e.g. alongside Metasploitable2
> in a host-only/NAT VirtualBox network, or a segmented VLAN with no
> route to production or the internet). This app has no business
> being reachable from anywhere your students don't control. Never
> deploy it on a real production LAMP stack or expose it publicly.

## 1. Deploy to Metasploitable2

**Prerequisites:** Metasploitable2 running in VirtualBox/VMware on a
**host-only or internal network** (not bridged to the internet), and
you know its IP (`ip addr` or `ifconfig` on the VM console — default
creds `msfadmin`/`msfadmin`).

### The fast way: `setup.sh`

```bash
# On your trainer machine, clone the repo (root IS the app - admin/,
# user/, index.php etc. sit directly in the cloned folder):
git clone https://github.com/idorenyinbassey/VulnCorp-Helpdesk.git

# Modern OpenSSH's scp defaults to a protocol Metasploitable2's ancient
# sshd chokes on ("realpath ... path canonicalization failed") - force
# the legacy protocol with -O:
scp -O -r VulnCorp-Helpdesk msfadmin@<metasploitable2-ip>:/tmp/

# SSH in and run the setup script:
ssh msfadmin@<metasploitable2-ip>
cd /tmp/VulnCorp-Helpdesk
sudo bash setup.sh
```

That's it. `setup.sh` starts Apache/MySQL if they're stopped, copies the
app to `/var/www/vulnapp`, fixes ownership and permissions (including
the world-writable `uploads/` folder the upload module needs), loads
the database schema, detects the box's IP, and prints the URL and
every seeded login. It asks for confirmation before wiping the
database (skip that with `sudo bash setup.sh --yes`), and it's **safe
to re-run** any time you pull an update — it refreshes the deployed
files and resets the database to a clean state, which doubles as a
quick "reset for a new class" command.

### The manual way (useful for understanding what setup.sh automates,
or if something above doesn't fit your setup)

1. **Confirm the stack is up on Metasploitable2**
   ```bash
   ssh msfadmin@<metasploitable2-ip>
   sudo /etc/init.d/apache2 status
   sudo /etc/init.d/mysql status
   php -v          # ships PHP 5.2.x — this app avoids modern syntax on purpose
   php -m | grep mysqli   # confirm the mysqli extension is present
   ```
   If Apache/MySQL aren't running: `sudo /etc/init.d/apache2 start` / `sudo /etc/init.d/mysql start`.
   (Metasploitable2's image predates the `service` wrapper — everything there is
   driven by raw `/etc/init.d/<name> {start|stop|restart|status}` scripts.)

2. **Get the project onto your trainer machine, then copy it over**
   ```bash
   git clone https://github.com/idorenyinbassey/VulnCorp-Helpdesk.git
   scp -O -r VulnCorp-Helpdesk msfadmin@<metasploitable2-ip>:/tmp/
   ```

3. **Install it under the webroot**
   ```bash
   ssh msfadmin@<metasploitable2-ip>
   sudo mv /tmp/VulnCorp-Helpdesk /var/www/vulnapp
   sudo chown -R www-data:www-data /var/www/vulnapp
   sudo chmod -R 755 /var/www/vulnapp
   sudo chmod -R 777 /var/www/vulnapp/uploads   # deliberately world-writable for the upload module
   ```

4. **Load the database schema**
   ```bash
   mysql -u root < /var/www/vulnapp/db_setup.sql
   # Metasploitable2's MySQL root user has no password by default.
   # If yours differs, edit /var/www/vulnapp/includes/db.php first:
   #   $DB_USER = 'root'; $DB_PASS = 'yourpassword';
   ```

5. **Verify the schema loaded**
   ```bash
   mysql -u root -e "USE vulnapp; SELECT username, role FROM users; SELECT * FROM settings;"
   ```
   You should see 4 users (admin/sam/alice/bob) and one settings row (`difficulty = simple`).

6. **(Optional) Give it its own vhost** instead of `/vulnapp/` in the URL —
   add to `/etc/apache2/sites-available/vulnapp.conf`:
   ```apache
   <VirtualHost *:8080>
       DocumentRoot /var/www/vulnapp
       <Directory /var/www/vulnapp>
           AllowOverride All
           Require all granted
       </Directory>
   </VirtualHost>
   ```
   Then: add `Listen 8080` to `/etc/apache2/ports.conf`,
   `sudo a2ensite vulnapp`, `sudo /etc/init.d/apache2 restart`.
   (Port 80 is already used by Metasploitable2's own vulnerable apps —
   pick a free port like 8080 if you go this route. `setup.sh` doesn't
   set up a vhost — it deploys to `/var/www/vulnapp` either way.)

7. **Browse to it and smoke-test**
   ```
   http://<metasploitable2-ip>/vulnapp/            # or :8080/ if you used a vhost
   ```
   Log in as `admin` / `admin123`, confirm the dashboard loads, then
   open **Admin Panel → Difficulty Settings** and confirm you can
   flip tiers. Open **Challenges** from the dashboard to confirm it
   renders for every role.

8. **Firewall/network sanity check** — Metasploitable2 ships with no
   firewall by default, which is fine as long as the VM's network
   adapter is host-only/internal. If you've bridged it, disable that
   before going further.

## 2. Login credentials

| Username | Password    | Role    |
|----------|-------------|---------|
| admin    | admin123    | admin   |
| sam      | support123  | support |
| alice    | alice123    | user    |
| bob      | bob123      | user    |

**Managing accounts:** passwords can be changed at `/user/change_password.php`
(link on the dashboard), and admins can create new accounts at
`/admin/create_user.php`. Both are deliberately weak below the expert
tier — see the vulnerability matrix below. There's still no
self-registration; account creation is admin-only by design.

**Other reachable features** (also on the dashboard, also weak below
expert): a one-time "welcome bonus" claim at `/user/claim_bonus.php`
(race condition), and a small JSON API at `/api/tickets.php` (broken
object-level authorization) — good for practicing with Postman/Burp
against something that isn't an HTML form.

## 3. Setting the difficulty

Log in as `admin` → **Difficulty Settings**. The mode is stored
server-side and applies globally to every session immediately —
good for live-demoing "watch the same payload stop working."

## 4. What changes at each tier

| Module | Simple | Intermediate | Hard | Expert |
|---|---|---|---|---|
| **Login** (`index.php`) | Raw string-concat SQL, errors shown → classic `' OR '1'='1'-- ` bypass, UNION extraction | Lowercase keyword blacklist (`union`,`select`,…) → bypass with `UNION`/mixed case | Login itself parameterized; **"remember me" cookie** is checked via unescaped SQL → forge `remember_token` cookie | Fully parameterized, no info leakage; **no rate limiting anywhere** → intended path is credential brute force (Hydra) + weak session token analysis |
| **Ticket text** (`user/tickets.php`, `support/tickets.php`) | Stored XSS, zero encoding | Blacklist strips `<script>` only → bypass with `<img onerror=...>`, `<svg onload=...>` etc. | Ticket body escaped; **search box (`?q=`)** reflects into an HTML attribute unescaped → reflected XSS | Search escaped too; vuln moves to signature field allowlist sanitizer (`includes/render.php: naive_allowlist_sanitize`) which keeps attributes on `<a>` tags → attribute-injection XSS |
| **Ticket status update** (`support/tickets.php`) | No CSRF token | No CSRF token | No CSRF token | CSRF token required + validated |
| **Profile** (`user/profile.php`) | No ownership check at all → view/edit any `?id=`; password hash shown | Same IDOR, hash hidden | Ownership enforced on `profile.php`... but `user/profile_export.php` (JSON export) forgot the same check | Ownership enforced everywhere in `profile.php`, but the update handler doesn't strip an unexpected `role` POST field for non-admins → mass-assignment privilege escalation |
| **Diagnostics / ping tool** (`admin/diagnostics.php`, admin-only) | Raw `shell_exec` concatenation → trivial command injection | Blacklists `;`, `&&`, `\|\|` → bypass with backticks / `$(...)` / newline | Host param escaped correctly, but a second `opts` field is concatenated unescaped | Unanchored whitelist regex (`/[a-zA-Z0-9\.\-]+/` with no `^...$`) → payload just needs a valid-looking substring anywhere |
| **Avatar upload** (`user/upload.php`) | No validation → upload a `.php` web shell directly | Checks the **client-supplied** `Content-Type` header only → trivially forged | Validates real image structure (`getimagesize`) but keeps original filename/extension → GIF+PHP polyglot named `shell.php` passes | Validates image structure **and** forces a random `.png` name server-side → path closed (shows the fix) |
| **Change password** (`user/change_password.php`) | No current-password check, no ownership check, no CSRF token → any logged-in user takes over any account by `?id=` | Current password IS checked... but only against **your own** account while the UPDATE still targets `?id=` → verify-yourself-but-hijack-anyone logic bug | Ownership + current-password check both correct; still no CSRF token | Ownership + current-password check + **CSRF token required** — fully closed |
| **Forgot password** (`user/forgot_password.php`) | Reset token = `md5(username)` — zero secret material, no expiry effectively | Reset token = `md5(username + today's date)` — guessable by anyone who knows the date | Reset token = `md5(username + time())` — guessable within a narrow time window of the real request | Token = `random_bytes(32)`, 15-minute expiry, generic response either way → closed |
| **Create user** (`admin/create_user.php`, admin-only) | No CSRF token; raw SQL insert (secondary SQLi via `full_name`) → a page an admin merely *visits* can silently create a backdoor admin account | No CSRF token; insert now parameterized | No CSRF token | CSRF token required — closed. This is the highest-impact CSRF in the app: chain it with the stored-XSS-in-a-ticket-an-admin-reads idea from the Simple tier for a full account-takeover writeup. |
| **Login redirect** (`index.php?redirect=`) | No validation at all → raw open redirect to any external URL | Requires a leading `/` → bypassed by protocol-relative `//evil.com` | Blocks protocol-relative, but "contains the app name anywhere" is a substring check → `http://evil.com/vulnapp` passes | Fixed allowlist of real in-app paths only — closed |
| **Welcome bonus** (`user/claim_bonus.php`) | Classic TOCTOU (check-then-write, two statements) with a wide 400ms artificial window → reliably double-claimable with a handful of concurrent requests | Same TOCTOU, narrower 50ms window → still exploitable, but needs real concurrent tooling (async script or Burp Intruder concurrent mode), not naive sequential `curl` loops | Single atomic `UPDATE ... WHERE bonus_claimed = 0` checked via `mysqli_affected_rows()` — closed | Same atomic fix as hard — closed |
| **Tickets API** (`api/tickets.php`, JSON) | No authentication at all — anyone can read any ticket or list all of them | Requires login, but no ownership check — any valid session reads any ticket | Single-ticket lookup (`?id=`) is properly scoped; **list mode** (no `id`) was added later and never got the same check → still leaks every ticket | Both single-ticket and list mode properly scoped to the caller — closed |

`user/profile_export.php` is a good standalone target at every
tier since its missing ownership check doesn't depend on the toggle.
The welcome-bonus race condition needed real verification, not just
code review — see the "Notes" section below for what that took.

## 5. In-app Challenges page

Every logged-in user (any role) can open **Challenges** from the
dashboard, or browse directly to `/challenges/index.php`. It lists,
per difficulty tier: the objective, a **"Why this works" concept
block** explaining the underlying mechanism in plain language before
any hint is given, the legitimate tools suited to it (Burp Suite,
sqlmap, Hydra, ffuf, exiftool, browser devtools), numbered methodology
steps, and a click-to-reveal clue — no full payload is pre-typed, so
students still have to construct the final exploit themselves. It's
driven by a plain PHP array at the top of `challenges/index.php`, so
it's easy to add your own challenges as you extend the app.

The concept blocks exist specifically for beginners: knowing that
`' -- ` bypasses a login form isn't the same as understanding *why* —
that the query is built by string concatenation, what a quote does to
that string, what a comment operator removes. Each of the 26 tiered
challenges has one; the recon and tools-reference sections don't,
since those are about methodology/tool usage rather than a specific
vulnerability mechanism.

**Difficulty badges and staged hints.** Each of the 26 tiered
challenges is also rated **Entry / Standard / Stretch** (a genuine
audit of relative cognitive load within its tier, not just its
position in the array) and displayed sorted by that rating — Entry
challenges first, Stretch last — so a student working through, say,
the Simple tier meets the four easiest challenges before the ones that
need more synthesis (UNION SQLi, the CSRF backdoor). Hints are
two-stage: a **Nudge** (a conceptual pointer, no payload) reveals
first, and a separate **Full answer** underneath it holds what used to
be the single "Reveal clue." This was originally planned as three
stages (nudge → stronger nudge → full answer); it shipped as two to
keep the addition scoped — the existing, already-verified clue text
became the answer tier unchanged, so nothing that was previously
tested got rewritten in the process.

The recon and tools-reference sections keep the older single-clue
format, since they're methodology content rather than a specific
vulnerability to nudge toward.

A short version of what's covered (full detail is on the page itself):

- **Simple** — auth bypass, UNION-based dumping with sqlmap, stored XSS, basic IDOR, raw command injection, unrestricted upload.
- **Intermediate** — the same bug classes behind naive filters (case-sensitive blacklists, client-controlled Content-Type checks) — the skill here is filter evasion, not new bug-finding.
- **Hard** — main paths are fixed; the challenges point at the secondary flaw a real reviewer would have to hunt for (a forgotten endpoint, a second unescaped parameter, a polyglot file).
- **Expert** — mostly closed; challenges lean on source review, brute force against a missing rate limit, and a CSRF PoC exercise (build the PoC against hard mode, then confirm the same PoC fails once the CSRF token lands in expert mode — a good exercise in writing an accurate bug report).

The **CSRF challenge** is the one place the page hands you a code
snippet — a minimal auto-submitting HTML form pointed at the app's
own ticket-status endpoint. That's the standard, non-weaponized PoC
format used in real CSRF bug reports (it only works against a
target you're already authorized to test, and does nothing on its
own without a logged-in victim visiting it).

## 6. Deployment path handling

The app works whether it's deployed at the web server's root, in a
subfolder (e.g. `/vulnapp/`, as in the steps above), or behind a
dedicated vhost — no Apache config changes required either way. Every
internal link, redirect, and asset reference is generated through a
single `app_base()` function (`includes/compat.php`), which computes
the app's mount point at runtime from `$_SERVER['SCRIPT_NAME']`. If
you add new pages, use `app_base()` for any `href`, `src`, or
`header('Location: ...')` that points back into the app — a hardcoded
`href="/dashboard.php"`-style absolute path will break the moment
someone deploys this one folder deeper or shallower than you did.

## 7. Client-side JavaScript

`assets/app.js` (loaded site-wide via `includes/footer.php`) adds pure
UX polish: a live password-match/strength indicator on Change
Password, a local avatar image preview on Upload, a non-blocking
email-format hint on Create User, and a local (localStorage-only)
progress checklist on the Challenges page.

It is **deliberately not wired up** to any exploit-relevant field —
login, ticket subject/message/search, the diagnostics host/opts
fields, and profile full_name/email have zero JS hooks and zero
`<script>` tags. If you extend this app, keep new client-side
validation off those fields: browser-side checks are trivially
bypassed with devtools or Burp Repeater anyway (the tools this app's
own challenges tell students to use), so adding them there would
only teach the wrong lesson — that a bug is fixed when it isn't.

## 8. Toolkit — downloadable checklists & kits

`/toolkit/index.php` (linked from the dashboard) offers seven real-world
templates — Safe Testing Rules, Program Policy Check, Program Signal
Sheet, Recon Note Template, Web App Test Checklist, Report Writing
Template, and Severity Cheat Sheet — each downloadable in five formats
(`.md`, `.docx`, `.doc`, `.xlsx`, `.xls`) from `assets/toolkit/<format>/`.

These are **static, pre-generated files**, not rendered per-request —
PHP 5.2 has no reliable docx/xlsx library, so they're built once with
modern tooling and just served as plain downloads. If you edit the
content, regenerate all five formats together (`build_docx.js` /
`build_xlsx.py` if you kept them, or by hand) so they don't drift out
of sync with each other.

## 9. Suggested student flow

1. **Recon** — Nmap/Nikto the box, identify the app, map roles by
   registering... actually there's no self-registration (by design,
   keeps the role model simple) — hand out the credentials table.
2. **Simple** — get comfortable with each vuln class in its most
   obvious form; this is where sqlmap/Burp basics get introduced.
3. **Intermediate** — same vuln classes, now behind naive filters;
   practice filter evasion and encoding tricks.
4. **Hard** — main path is fixed; hunt for the secondary/chained
   flaw (cookie-based SQLi, IDOR on a forgotten endpoint, polyglot
   upload, split-parameter command injection).
5. **Expert** — mostly closed; the remaining bugs require chaining
   (mass assignment, unanchored regex, attribute-injection XSS,
   session prediction + brute force) — good for a capstone/CTF.

## 10. Resetting state

Easiest: `cd` into your copy of the repo on Metasploitable2 and re-run
the setup script — `sudo bash setup.sh --yes` reinstalls the current
files and resets the database in one command, which is really just
"start of a new class session."

Or by hand:
```bash
mysql -u root < /var/www/vulnapp/db_setup.sql   # re-run anytime to reset users/tickets
rm -f /var/www/vulnapp/uploads/*                 # clear uploaded files (keep .gitkeep if you add one)
```

## 11. Notes

- All output that *is* meant to be safe uses `htmlspecialchars` /
  prepared statements — only the deliberately-vulnerable code paths
  described above are weak, so you can point students at a specific
  file/line as "this is the bug" rather than the whole app being
  uniformly broken.
- `includes/db.php` defaults to MySQL `root` with no password to
  match Metasploitable2's out-of-the-box MySQL config. Change this
  if you're deploying elsewhere.
- This app has no self-registration and no password-reset flow on
  purpose, to keep the four seeded accounts as the whole attack
  surface for the role model.
- **The welcome-bonus race condition needed a real fix, not just a
  design.** As first written, PHP's default session file locking would
  have serialized concurrent requests from the same session — masking
  the race on a real multi-worker Apache deployment, not just in a
  test harness. Fixed with an early `session_write_close()` (itself a
  realistic thing real code does for performance, which is exactly how
  this bug class often shows up for real). Verifying it also required
  actually installing Apache + mod_php and firing genuinely concurrent
  requests — PHP's built-in dev server (`php -S`) is single-threaded
  and can't demonstrate true concurrency at all, so testing against it
  alone would have been a false negative. The timing windows (400ms
  simple / 50ms intermediate) were tuned empirically against that real
  setup, not guessed.

## 12. Building on this later

- `api/` follows the same one-level-deep folder convention as `admin/`,
  `user/`, `support/`, `challenges/`, `toolkit/` — if you add a new
  top-level module folder, register its name in `app_base()`'s
  `$known_subfolders` list in `includes/compat.php`, or its links will
  break under subfolder deployment (see the git history for what that
  bug looked like the first time it happened).
- New vulnerable modules should get a `'difficulty'` rating
  (`Entry`/`Standard`/`Stretch`) and a two-part `'hints'` array
  (`nudge`/`answer`) in `challenges/index.php`, matching the existing
  26+8 entries, so they sort correctly and fit the site's format.
- If a new module depends on real concurrency (a race condition, a
  timing attack), test it against actual Apache/PHP-FPM, not just
  `php -S` — see the note above.
