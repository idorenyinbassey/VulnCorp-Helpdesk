# VulnCorp Helpdesk — Intentionally Vulnerable Training App

A small LAMP (Linux/Apache/MySQL/PHP) app built for teaching web
application security, in the same spirit as DVWA/Mutillidae. It has
three roles (**admin**, **support**, **user**), a global
**difficulty toggle** (Simple → Intermediate → Hard → Expert) that
changes *how* each vulnerability is exploitable, and an in-app
**Challenges** page (`/challenges/index.php`) with per-tier
objectives, required tools, steps, and revealable clues.

## Why this exists

Tools like DVWA, Mutillidae, WebGoat, and PortSwigger's Web Security
Academy are excellent and don't need replacing — this app doesn't try
to. It exists because none of them are built *around a specific
curriculum*: this one's difficulty tiers, hint wording, "Why this
works" explanations, and the Tools Reference / Toolkit / Challenges
pages are all written in the language of one particular 12-week
cybersecurity bootcamp, so a student moves from lecture straight into
a lab that already assumes the same vocabulary and sequencing the
lecture used. The tiered toggle (the same bug, exploitable a different
way at each difficulty) also isn't common elsewhere — most training
apps are fixed-difficulty.

It's meant as a **guided on-ramp that comes *before* DVWA and
PortSwigger**, not a replacement for them — once a student is
comfortable here, those tools cover far more ground (GraphQL, HTTP
smuggling, SSTI, prototype pollution, and other categories this single
custom app structurally can't demonstrate — JWT auth flaws, SSRF, XXE,
2FA bypass, session fixation, cache poisoning, clickjacking, DOM XSS,
and a full business-logic approval workflow are all now modeled here
too, see sections 5 and 6) and have years of community calibration
behind them that this app doesn't have yet. The
beginner-feedback tools (`/feedback/`) exist specifically to start
building that calibration from real student data instead of one
person's best guess at what a beginner needs.

## Who it's for

- **Students new to web app security** (the primary audience) —
  the Simple tier, the concept blocks, and the staged nudge-before-
  answer hints are aimed at someone who's never exploited SQL
  injection before, not someone who already has.
- **Students working toward bug bounty hunting specifically** — the
  Tools Reference, recon phase, and Toolkit (report templates,
  severity cheat sheet, program-vetting checklists) are there because
  finding the bug is only part of that skill set.
- **The trainer/instructor running the program** — the difficulty
  toggle, the admin feedback dashboard, and `setup.sh`/Docker
  deployment options are built for someone who needs to demo, reset,
  and re-calibrate this across multiple cohorts, not just run it once.

> ⚠️ **Use only on an isolated lab network** (e.g. alongside Metasploitable2
> in a host-only/NAT VirtualBox network, or a segmented VLAN with no
> route to production or the internet). This app has no business
> being reachable from anywhere your students don't control. Never
> deploy it on a real production LAMP stack or expose it publicly.

## 1. Deploy to Metasploitable2

> Setting up a separate VM instead of using Metasploitable2? See
> section 2 below — `setup-modern.sh` is a one-command native install
> for a modern Debian/Ubuntu VM, `setup-rhel.sh` does the same for the
> RHEL/Fedora family, or use [`docker/README.md`](docker/README.md) if
> you already have Docker running somewhere. Same app, same 77
> challenges (70 tiered, 5 recon-phase, 2 CTF flag chains) either way —
> only the deployment mechanics differ from what's below, which is
> Metasploitable2-specific.

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
   sudo mkdir -p /var/www/vulnapp/cache && sudo chmod -R 777 /var/www/vulnapp/cache   # disk cache for the Cache Poisoning module
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
   You should see 5 users (admin/sam/alice/bob/carol) and one settings row (`difficulty = simple`).

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

## 2. Deploy on a separate modern VM (no Metasploitable2 needed)

If you're standing up a dedicated VM for this anyway, **`setup-modern.sh`
is the simpler option** — a native install (Apache/PHP/MariaDB directly
on the VM), no Docker required. Docker only pays for itself when you
already have it running somewhere for other reasons (a laptop with
Docker Desktop already installed, a CI pipeline, etc.) — if the VM is
being created *just* for this, wrapping it in containers adds a layer
of complexity without adding anything, since you still have to
provision that VM either way.

### Option A: native install with `setup-modern.sh` (recommended for a dedicated VM)

1. **Create a new VM** in VirtualBox — a lightweight modern Linux
   distro (Ubuntu Server 22.04/24.04 LTS is a safe default). 1-2GB
   RAM, 1 vCPU, ~15GB disk is plenty.
2. **Attach it to the same isolated network** as Kali and
   Metasploitable2 (e.g. the `hacking_lab` NAT Network from the
   deployment-path troubleshooting elsewhere in this repo's history) —
   reachable from Kali for exercises, still isolated from your home
   LAN, same reasoning as the Metasploitable2 setup above.
3. **Give it a static IP** inside that network, for the same reason
   recommended for Metasploitable2 — a shifting address breaks every
   command that hardcodes it.
4. **Clone and run:**
   ```bash
   git clone https://github.com/idorenyinbassey/VulnCorp-Helpdesk.git
   cd VulnCorp-Helpdesk
   sudo bash setup-modern.sh
   ```
   This installs Apache/PHP/MariaDB if they're not already present,
   fixes MariaDB's modern `auth_socket` default (which otherwise
   blocks the app from connecting at all — see the note below), and
   deploys to `/var/www/html/vulnapp` (this distro's actual default
   `DocumentRoot`, unlike `setup.sh`'s Metasploitable2-specific
   `/var/www/vulnapp`).
5. **Verify from Kali:**
   ```bash
   curl -I http://<this-vm-ip>/vulnapp/
   ```

`setup-modern.sh` is a genuinely different script from `setup.sh`, not
the same file reused — the two environments differ in three concrete
ways that were each confirmed by actually running the Metasploitable2
script against a modern Ubuntu install and watching it fail:
`ifconfig`'s modern output format doesn't match the old-format parsing
`setup.sh` relies on (IP shows as a placeholder, not a real address);
modern Apache's default `DocumentRoot` is `/var/www/html`, not
`/var/www` (the app was completely unreachable, HTTP 404); and modern
MariaDB's `auth_socket` default for `root` blocks any connection that
isn't from the literal Linux `root` user, which is exactly what the
web server's PHP process is not (`Access denied for user
'root'@'localhost'`). `setup-modern.sh` fixes all three.

### Option C: native install with `setup-rhel.sh` (RHEL/Fedora family)

Same idea as Option A, for RHEL, CentOS Stream, Rocky Linux, AlmaLinux,
or Fedora instead of Debian/Ubuntu:
```bash
git clone https://github.com/idorenyinbassey/VulnCorp-Helpdesk.git
cd VulnCorp-Helpdesk
sudo bash setup-rhel.sh
```
This installs `httpd`/PHP/MariaDB via `dnf` (falling back to `yum` if
`dnf` isn't present) if they're not already there, fixes the same
MariaDB `auth_socket` issue `setup-modern.sh` fixes, deploys to the same
`/var/www/html/vulnapp` docroot — but owned by the `apache` user, not
Debian's `www-data` — and, unlike `setup-modern.sh`, also handles two
things that are specific to this distro family and otherwise block the
app outright:
- **SELinux** — if `getenforce` reports `Enforcing` or `Permissive`
  (skipped entirely if SELinux isn't present at all), the script sets the
  `httpd_sys_rw_content_t` context on `uploads/` and runs `restorecon` —
  without this, Apache can have the right Unix file permissions and
  still get denied when the upload module tries to write a file.
- **firewalld** — on by default on RHEL/Fedora (unlike most Debian cloud
  images), so the script opens the `http` service if firewalld is
  running; otherwise the app is unreachable from outside the box even
  though Apache itself is serving it correctly.

Verify the same way as Option A: `curl -I http://<this-vm-ip>/vulnapp/`.

### Option D: Docker, if you already use it elsewhere

See [`docker/README.md`](docker/README.md) for the full walkthrough.
Same idea as above (own VM, same isolated network, static IP) except
step 4 becomes:
```bash
sudo apt install -y docker.io docker-compose-v2
git clone https://github.com/idorenyinbassey/VulnCorp-Helpdesk.git
cd VulnCorp-Helpdesk/docker
sudo docker compose up -d
```
and the app lands on port 8080 instead of 80. This option is the most
distro-agnostic of the four — since every OS-specific detail (package
names, init system, docroot, SELinux) lives inside the official
container images rather than the host, it works identically on literally
any Linux box with a working Docker install, not just Debian/Ubuntu or
RHEL/Fedora.

Any of these options gives the same clean three-VM lab — Kali (attacker),
Metasploitable2 (the old-school multi-service target), and this VM
(VulnCorp Helpdesk) — independent of each other, nothing shared, each
reachable from Kali for whichever exercise needs it.

## 3. Login credentials

| Username | Password    | Role    |
|----------|-------------|---------|
| admin    | admin123    | admin   |
| sam      | support123  | support |
| alice    | alice123    | user    |
| bob      | bob123      | user    |
| carol    | carol123    | user    |

Each seeded account also has an `api_key` in the `users` table, used by
the API Token (JWT) Auth module (see section 6) — it's not shown in any
UI by design; the "The Forgotten Export" CTF chain is about leaking one
via an existing IDOR, not reading it off this table.

**carol is the only account with `totp_enabled = 1`** — she's the
designated target for the 2FA Bypass module (section 5) and the
Clickjacking module's PoC (framing her "Disable 2FA" toggle). She's a
brand-new account rather than reusing admin/sam/alice/bob specifically
so every pre-existing challenge that assumes those four accounts
complete login in a single step keeps working unmodified — 2FA is
opt-in, per-account, not a global login change.

**Managing accounts:** passwords can be changed at `/user/change_password.php`
(link on the dashboard), and admins can create new accounts at
`/admin/create_user.php`. Both are deliberately weak below the expert
tier — see the vulnerability matrix below. There's still no
self-registration; account creation is admin-only by design.

**Other reachable features** (also on the dashboard, also weak below
expert): a one-time "welcome bonus" claim at `/user/claim_bonus.php`
(race condition), a small JSON API at `/api/tickets.php` (broken
object-level authorization), an API token exchange at
`/api/auth_token.php` and a JSON write endpoint at
`/api/ticket_update.php` (JWT auth flaws and API-specific mass
assignment — see section 6) — all good for practicing with Postman/Burp
against something that isn't an HTML form.

## 4. Setting the difficulty

Log in as `admin` → **Difficulty Settings**. The mode is stored
server-side and applies globally to every session immediately —
good for live-demoing "watch the same payload stop working."

## 5. What changes at each tier

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
| **API Token (JWT) Auth** (`api/auth_token.php`, `includes/jwt.php`, Bearer header) | `alg: none` in the JWT header skips signature verification entirely → forge any claims | Blocks the literal lowercase `none` only → bypass with `None`/`NONE` | Alg confusion fully closed, signature required — but `exp` is never checked → a captured token is valid forever | `exp` checked too — but no revocation on password change → a token issued before a password change keeps working after it |
| **API Token Request rate limiting** (`api/auth_token.php`) | No rate limiting at all → brute-force the `api_key` freely | *(inherits hard-tier behavior below)* | Lockout exists, but keyed by a case-sensitive username and a spoofable `X-Forwarded-For` → both independently bypass it | *(inherits hard-tier behavior — this module's own challenges are simple/hard only)* |
| **API Ticket Update — Mass Assignment** (`api/ticket_update.php`, Bearer header) | No field allowlist and no ownership check at all → any caller rewrites any ticket's owner and priority | Ownership checked against the ticket's *current* owner — but a new `user_id` in the same request still reassigns it right after | `user_id` finally stripped — but the admin/support-only `priority` field was forgotten and stays open to any caller | Both fields correctly allowlisted — but the check reads `$_POST` while the write loop reads `$_REQUEST` → the same field via the query string slips through |
| **Session fixation** (`index.php` login + "remember me") | Main login never regenerates the session ID → fixate a victim's session before they log in, then use that same ID yourself afterward | Same bug, plus `session.cookie_httponly` is now set → fixation still works, cookie *theft* doesn't | Main login regenerates correctly — but the separate "remember me" auto-login branch still doesn't → fixate, then wait for a silent remember-me login | Both paths regenerate correctly — closed |
| **Clickjacking** (`includes/header.php`, every page) | No security headers sent at all → any page can be framed | Same — no headers | `X-Frame-Options: SAMEORIGIN` added to the shared header include — but `user/verify_2fa.php` is a standalone page that never includes it → that one page can still be framed (PoC target: overlay a fake button on the real "Disable 2FA" toggle) | `verify_2fa.php` brought into the shared header include too — closed |
| **SSRF — Link Preview** (`user/link_preview.php`) | Fetches any URL server-side with redirects followed, no validation at all → internal IPs, `file://`, cloud metadata all reachable | Blocks a `localhost`/`127.0.0.1` substring blacklist → bypass with `127.1`, octal `0177.0.0.1`, or `[::1]` | Validates the initial host against real private IP ranges — but only once, before the first request; a redirect to an internal address is still followed unchecked | Every redirect hop is re-validated — but the hand-rolled private-range check never special-cased `169.254.169.254` (cloud metadata) |
| **XXE — Bulk Import Tickets** (`admin/import_tickets.php`, admin-only) | `simplexml_load_string()` with no entity-loading protection → classic XXE, read a local file reflected back into the imported ticket | Switches to `DOMDocument->loadXML($xml, LIBXML_NOENT)` — sounds protective, actually *substitutes* entities rather than blocking them → identical exploit still works | Any `<!DOCTYPE` is rejected outright, entity loading disabled → direct disclosure closed; conceptual only beyond this (see the challenge write-up) — blind/OOB exfiltration via a parameter entity referencing an attacker-hosted external DTD | Same fix as hard; conceptual only — entity-expansion ("billion laughs") denial of service |
| **DOM XSS — search deep link** (`assets/search-prefill.js`, reads `location.hash`) | Raw `innerHTML = location.hash` substring, no filtering at all, entirely client-side | A client-side blacklist strips `<script` only → bypass with `<img onerror=...>` | A naive client-side allowlist keeps `<a href>` but doesn't check for extra attributes alongside it → `<a href=# onmouseover=...>` survives | Closed — uses `textContent`, never `innerHTML` |
| **2FA bypass** (`includes/totp.php`, `user/verify_2fa.php`, carol's account only) | The full session is set immediately after the password check, before any code is verified → visiting the dashboard directly skips 2FA entirely | Full session only set after a correct code — but `api/tickets.php` checks only `isset($_SESSION['user_id'])`, which the partial-auth state sets too → that one endpoint stays reachable before 2FA completes | That gap closed — but `verify_2fa.php` has no rate limiting on code guesses at all (6-digit space, no lockout) | Rate-limited correctly — but a "remember this device" cookie, once set, skips 2FA entirely and its value is just `md5(username)` → forgeable without ever completing 2FA |
| **Cache poisoning** (`includes/simple_cache.php`, login page) | `X-Forwarded-Host` reflected raw into a cached `<link rel="canonical">`, cache never varies by it → poison once, every later plain visitor gets the injected content | Same bug, but a cache-buster query param is now needed to force a fresh entry per test | The header value is now `htmlspecialchars()`-escaped — but the canonical *URL* is still built from it unsafely → poisoning now produces an open-redirect-flavored cached page instead | The Host-ish header is excluded from reflection — but `Accept-Language` (an unrelated "preferred language" banner) is still reflected into the same cached page, unkeyed |
| **Business logic — escalation workflow** (`user/tickets.php`, `support/escalation_approve.php`) | "Request Escalation" directly sets `priority = urgent` server-side, no approval step or role check anywhere | A `pending` state exists, but the "waiting for approval" gating is enforced only in JS → a direct POST to the same handler still applies the escalation immediately | Server-side pending-state enforced for the request step — but the approval endpoint never checks the caller's role → any logged-in user can approve their own pending request | The approval endpoint is correctly role-checked — but nothing limits how many times a user can re-request escalation after a denial, no cooldown at all |

`user/profile_export.php` is a good standalone target at every
tier since its missing ownership check doesn't depend on the toggle —
and, since it now also exports each user's `api_key`, it's the entry
point for the "The Forgotten Export" CTF chain (see section 6).
The welcome-bonus race condition needed real verification, not just
code review — see the "Notes" section below for what that took.

## 6. In-app Challenges page

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
that string, what a comment operator removes. Each of the 70 tiered
challenges has one; the recon, CTF-flag, and tools-reference sections
don't, since those are about methodology/tool usage or multi-step chains
rather than a single specific vulnerability mechanism.

**Difficulty badges and staged hints.** Each of the 70 tiered
challenges is also rated **Entry / Standard / Stretch** (a genuine
audit of relative cognitive load within its tier, not just its
position in the array) and displayed sorted by that rating — Entry
challenges first, Stretch last — so a student working through, say,
the Simple tier meets its easiest challenges (auth bypass, basic IDOR,
the DOM XSS deep link, the business-logic escalation gap) before the
ones that need more synthesis (UNION SQLi, the CSRF backdoor, the XXE
file read). Hints are
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

- **Simple** — auth bypass, UNION-based dumping with sqlmap, stored XSS, basic IDOR, raw command injection, unrestricted upload, a hand-forged `alg: none` JWT, unrestricted API mass assignment, a brute-forceable API token exchange, session fixation, a framed 2FA toggle, an unrestricted SSRF link preview, a classic XXE file read, a client-side DOM XSS deep link, a decorative 2FA step, unkeyed cache poisoning, and a self-approved ticket escalation.
- **Intermediate** — the same bug classes behind naive filters (case-sensitive blacklists, client-controlled Content-Type checks, case-sensitive `alg` filtering, a `localhost` substring SSRF blacklist, a `LIBXML_NOENT` XXE misconception, a `<script`-only DOM XSS filter, a forgotten-endpoint 2FA gap, a cache-buster-gated poisoning check, and a JS-only escalation gate) — the skill here is filter evasion, not new bug-finding.
- **Hard** — main paths are fixed; the challenges point at the secondary flaw a real reviewer would have to hunt for (a forgotten endpoint, a second unescaped parameter, a polyglot file, a JWT with no expiry check, an API field nobody staff-gated, a rate limit with two independent bypasses, a remember-me path that skips session regeneration, a 2FA page that never got the clickjacking header, a redirect that bypasses SSRF host validation, blind/OOB XXE via a parameter entity, a DOM XSS allowlist that only checks for `href`, unrate-limited 2FA codes, an unsafely-built cached canonical URL, and an escalation-approval endpoint with no role check).
- **Expert** — mostly closed; challenges lean on source review, brute force against a missing rate limit, a CSRF PoC exercise, a JWT with no revocation on password change, a `$_POST`-vs-`$_REQUEST` mismatch on the API mass-assignment endpoint, an SSRF blocklist that forgot the cloud-metadata address, a closed DOM XSS sink to confirm and explain, a forgeable "remember this device" 2FA cookie, an unkeyed `Accept-Language` reflection into the same cached page, and an escalation workflow with no cooldown on repeated requests (build the PoC against hard mode, then confirm the same PoC fails once the matching fix lands in expert mode — a good exercise in writing an accurate bug report).
- **CTF flags (not tier-gated)** — two standalone chains that combine several bugs above into one exploit path: an IDOR-leaked API key exchanged for a forged admin session, and a hidden always-vulnerable `alg: none` branch independent of the configured tier.

The **CSRF challenge** is the one place the page hands you a code
snippet — a minimal auto-submitting HTML form pointed at the app's
own ticket-status endpoint. That's the standard, non-weaponized PoC
format used in real CSRF bug reports (it only works against a
target you're already authorized to test, and does nothing on its
own without a logged-in victim visiting it).

**API Token (JWT) Auth module.** `/api/auth_token.php` exchanges a
user's `api_key` (seeded per account — see the credentials table above)
for a hand-rolled HS256 JSON Web Token, used as a `Bearer` token against
`/api/tickets.php` and the new `/api/ticket_update.php`. The signing
secret is generated randomly per install (`settings.jwt_secret` in
`db_setup.sql`, via `MD5(RAND())`) — it is never a fixed value anywhere
in the source, so every bug in this module is a verification-logic flaw
(algorithm confusion, a missing expiry check, no revocation on password
change), never a guessable secret. See `includes/jwt.php`.

**API Ticket Update — Mass Assignment module.** `/api/ticket_update.php`
is a JSON write endpoint, authenticated the same way, that deliberately
writes whatever fields a request supplies instead of enforcing a fixed,
role-aware allowlist — the API-specific counterpart to the browser-form
mass assignment in `user/profile.php`.

**Session fixation module.** No new feature — this one lives entirely
in the existing login flow (`index.php`). Below the hard tier, neither
the password-check success path nor the "remember me" auto-login path
ever calls `session_regenerate_id()`, so a session ID set *before*
login (e.g. handed to a victim via a crafted link) stays valid *after*
login too — the classic fixation attack. The hard tier fixes the main
path but not the remember-me branch; expert fixes both.

**Clickjacking module.** `includes/header.php` (included by every
normal page) sends a tiered `X-Frame-Options` header. The designated
target is `/user/enable_2fa.php`'s "Disable 2FA" toggle — but the hard
tier's bug isn't in that page at all: `/user/verify_2fa.php` (the
second login step, see the 2FA module below) is a deliberately
lightweight, standalone page that never includes the shared
header/footer chrome, so it never gets the new header either — the
same "one endpoint forgot the shared protection" pattern this app
already uses for `profile_export.php` and the API list-mode endpoint.

**SSRF — Link Preview module.** `/user/link_preview.php` is a
real, common helpdesk feature: paste a URL while composing a ticket
and get a fetched title/snippet back (Slack and Jira both do this).
It fetches server-side via curl with no library beyond what PHP ships.
The bug progression is the textbook SSRF validation story: no checks
at all, then a substring blacklist (bypassable with alternate IP
representations), then a real IP-range check that only runs once
before the first request (bypassable via a redirect `curl` follows
without re-validating), then per-hop redirect revalidation that still
forgets the cloud-metadata range `169.254.169.254` — the exact gap
this app's own vulnerability reference table already calls out for
SSRF.

**XXE — Bulk Import Tickets module.** `/admin/import_tickets.php`
(admin-only) adds bulk ticket import from a pasted XML document —
again a real pattern many helpdesks support for migrations. At the
simple tier it's `simplexml_load_string()` with PHP's own real
pre-8.0 default behavior (external entity loading enabled), so no
code at all is needed to make it vulnerable, only code is needed to
fix it. The intermediate tier switches to `DOMDocument` with
`LIBXML_NOENT` — a common real-world misconception, since that flag
*substitutes* entity values into the tree rather than blocking them,
so the exact same file-read payload still works. Hard/expert reject
any `<!DOCTYPE` outright (the reliable fix — tuning
`resolveExternals`/`substituteEntities` alone turned out *not* to be
enough, since `->textContent` still walks into an EntityReference
subtree and reconstructs the substituted value regardless); beyond
that, blind/OOB exfiltration via a parameter entity and
entity-expansion ("billion laughs") denial of service are covered as
challenge write-up exercises rather than live-exploitable code paths,
matching this app's existing restraint around payloads too risky to
run destructively in a shared classroom lab (see the command-injection
module's "confirm with a harmless command" guidance).

**DOM XSS — search deep link module.** `assets/search-prefill.js`
reads `location.hash` for a `q=` deep-link parameter and writes a
"Showing results for: …" banner on the ticket search page — a feature
that exists purely client-side, with the payload never touching the
server at all. This is a deliberate, explicitly-flagged one-off
exception to `assets/app.js`'s documented "touches no exploit-relevant
field" policy (see section 8): a DOM XSS module structurally requires
a client-side sink, so it's isolated into its own file rather than
mixed into the JS that's supposed to stay exploit-free. The tiers
mirror `naive_allowlist_sanitize()`'s server-side bug shape exactly,
just in JavaScript: raw `innerHTML`, a `<script`-only blacklist, an
allowlist that checks for `href` but not *only* `href`, and finally
`textContent`, which closes it for good.

**2FA bypass module.** `includes/totp.php` is a hand-rolled RFC 6238
TOTP implementation (`hash_hmac('sha1', ...)`, no library — same
precedent as `includes/jwt.php`). Only `carol` has `totp_enabled = 1`
seeded (see the credentials table in section 3); logging in with 2FA
enabled routes through the new second step, `/user/verify_2fa.php`.
Below the hard tier, the full session is granted before the code is
even checked (simple), or a differently-named session flag means a
second endpoint never learned about the new partial-auth state
(intermediate — `api/tickets.php` only checks `isset($_SESSION['user_id'])`,
which the partial-auth state sets too). Hard closes both, but adds no
rate limiting to the 6-digit code itself; expert rate-limits correctly
but still has a "remember this device" cookie worth exactly
`md5(username)` — forgeable without ever touching a code, the same
weak-token flavor as this app's simple-tier password-reset bug.

**Cache poisoning module.** `includes/simple_cache.php` is a minimal
disk cache (atomic write-temp-then-`rename()`) applied only to the
login page's GET-render branch — the POST auth logic every other
login challenge depends on is untouched. The login page reflects
`X-Forwarded-Host` into a `<link rel="canonical">` URL; since the
cache never varies by that header, poisoning it once serves the
injected value to every later plain visitor of the same URL. Tiers
move through: raw reflection, a cache-buster needed to force a fresh
entry to test against, an escaped-but-still-unsafely-built canonical
URL (open-redirect flavor), and finally a second, unrelated reflected
header (`Accept-Language`, feeding an unkeyed "preferred language"
banner) that nobody thought to check once attention moved on to the
first one.

**Business logic — escalation workflow module.** A regular user can
ask for their own ticket to be bumped to Urgent priority
(`user/tickets.php`); only support/admin staff should be able to
*approve* that request (`support/escalation_approve.php`). This is
deliberately distinct from the existing API mass-assignment module
(a JSON endpoint accepting an unexpected field) — it's a multi-step
*workflow* with its own approval gate, and every tier's bug is in
whether that gate is actually enforced: no gate at all, a
client-side-only gate, a gate with no role check on the approval
side, and finally a correctly-gated workflow with no limit on how
many times it can be re-requested after a denial.

## 7. Deployment path handling

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

## 8. Client-side JavaScript

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

**One deliberate, explicitly-flagged exception:** `assets/search-prefill.js`
is a *separate* file, not part of `app.js`, that reads `location.hash`
and writes it into the ticket-search page — the DOM XSS module (see
section 5). A client-side vulnerability class structurally needs a
client-side sink, so this one file carries the exception on purpose
rather than quietly bending the "no exploit-relevant JS" rule inside
`app.js` itself. It also reads the server-rendered
`<body data-difficulty="...">` attribute to branch its own tiered
behavior — the only place in this app client-side code needs to know
the server's difficulty tier.

## 9. Toolkit — downloadable checklists & kits

`/toolkit/index.php` (linked from the dashboard) offers eight real-world
templates, each downloadable from `assets/toolkit/<format>/`:

- **Safe Testing Rules**, **Program Policy Check**, **Program Signal
  Sheet**, **Recon Note Template**, **Web App Test Checklist**,
  **Report Writing Template**, **Severity Cheat Sheet** — seven
  checklist/reference templates, each in five formats (`.md`, `.docx`,
  `.doc`, `.xlsx`, `.xls`).
- **20 Bug Bounty Lab Practices** — a full-workflow lab manual (recon
  → mapping → simple-tier exploits → filter evasion → hard-tier
  chained flaws → expert-tier logic bugs → API testing → a complete
  engagement report) using VulnCorp Helpdesk itself as the live
  target. Every lab names its required tools, the difficulty tier to
  set, numbered steps, a success check, and a "Report it" note showing
  what that finding looks like in a real submission. Narrative
  document, not a checklist, so it ships in four formats
  (`.md`, `.docx`, `.doc`, `.pdf` — no spreadsheet formats).

  **A separate Trainer Manual edition exists** (adds a "For the
  Trainer" pacing/usage note plus a compact answer-key summary table)
  but is **deliberately not shipped anywhere under this repo or the
  app's `/toolkit/`** — that page is reachable by every logged-in role,
  including the seeded student accounts, so an answer key there would
  just hand the exercise to students through their own login. Keep
  the trainer edition somewhere outside the deployed app entirely.

These are **static, pre-generated files**, not rendered per-request —
PHP 5.2 has no reliable docx/xlsx library, so they're built once with
modern tooling and just served as plain downloads. If you edit the
content, regenerate every format that template ships in together
(`build_docx.js`/`build_xlsx.py` if you kept them, `pandoc` for the
lab manual, or by hand) so they don't drift out of sync with each
other. The Toolkit page's `$templates` array supports a per-template
`'formats'` list (defaulting to all five) specifically so a narrative
document like this one doesn't need spreadsheet formats it has no use
for — see `toolkit/index.php` if you add another document-shaped
template later.

> **Known drift, flagged rather than hidden:** the Labs 23–30 addition
> to `20-lab-practices.md` was regenerated into `.docx` (via `pandoc`)
> and `.pdf` (via `pandoc` → HTML → `weasyprint`), but
> `assets/toolkit/doc/20-lab-practices.doc` is currently **stale**
> (pre-Lab-21 content) — `pandoc` doesn't emit legacy `.doc` at all, and
> the LibreOffice (`soffice --headless --convert-to doc`) fallback used
> to produce it from the `.docx` consistently fails with "source file
> could not be loaded" in this sandbox, reproduced even against an
> untouched, pre-existing template, so regenerating just this one format
> needs a working LibreOffice environment this one doesn't have. `.md`,
> `.docx`, and `.pdf` are all current through Lab 30; re-run the `.doc`
> conversion from `.docx` once you have a working LibreOffice install.

## 10. Beginner-feedback tools

Real feedback capture, not part of the training lab itself — built
correctly, with no intentional vulnerabilities.

- **Quick per-challenge votes.** Every challenge card on the Challenges
  page (including recon) has a one-click "How was this one?" widget —
  Too easy / Just right / Too hard / I got stuck. One vote per student
  per challenge; clicking again changes your existing vote rather than
  adding a duplicate. Votes are tied to the logged-in username.
- **End-of-tier survey** at `/feedback/survey.php` (linked from the
  dashboard) — four 1-5 ratings (difficulty, concept-block clarity,
  hint usefulness, confidence) plus two optional free-text questions,
  one submission per student per tier (re-submitting updates it).
- **Admin results dashboard** at `/admin/feedback.php` — the payoff.
  Per-challenge votes are sorted **worst-first** (most "too hard" +
  "stuck" votes at the top, highlighted red if they outnumber "just
  right") so problem spots surface automatically instead of requiring
  you to read every row. Survey responses are averaged per tier, and
  every free-text comment is listed with its rater's difficulty/
  confidence scores for context.

This is genuinely how the difficulty ratings, hints, and concept
blocks in this app should keep improving — they were calibrated by
one person reasoning about what a beginner needs, not by actual
beginner data. Point a real cohort at this before trusting the
calibration further.

## 11. Suggested student flow

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
6. **After each tier** — have students fill out the tier survey
   (`/feedback/survey.php`) before moving on, so you have a record of
   how that specific cohort experienced it.

Or skip the free-form version of the above and hand out the **20 Bug
Bounty Lab Practices** guide from the Toolkit instead — it's this same
progression already broken into 20 numbered, step-by-step labs (with
required tools and a report-writing note on each one), ending in a
capstone lab where students compile their findings from every prior
lab into one submission-ready engagement report.

## 12. Resetting state

Easiest: `cd` into your copy of the repo and re-run the setup script
for however you deployed — `sudo bash setup.sh --yes` on Metasploitable2,
`sudo bash setup-modern.sh --yes` on a native modern-VM install, or
`docker compose down -v && docker compose up -d --build` for Docker.
Each reinstalls the current files and resets the database in one
command, which is really just "start of a new class session."

Or by hand (paths shown for Metasploitable2 — swap in
`/var/www/html/vulnapp` for a modern-VM install):
```bash
mysql -u root < /var/www/vulnapp/db_setup.sql   # re-run anytime to reset users/tickets
rm -f /var/www/vulnapp/uploads/*                 # clear uploaded files (keep .gitkeep if you add one)
rm -f /var/www/vulnapp/cache/*                   # clear the login-page disk cache (keep .gitkeep if you add one)
```

## 13. Notes

- All output that *is* meant to be safe uses `htmlspecialchars` /
  prepared statements — only the deliberately-vulnerable code paths
  described above are weak, so you can point students at a specific
  file/line as "this is the bug" rather than the whole app being
  uniformly broken.
- `includes/db.php` defaults to MySQL `root` with no password to
  match Metasploitable2's out-of-the-box MySQL config. Change this
  if you're deploying elsewhere.
- This app has no self-registration on purpose, to keep the five
  seeded accounts as the whole attack surface for the role model
  (it does have a password-reset flow — see section 5's "Forgot
  password" row — just no way to create a new account outside
  `admin/create_user.php`).
- **2FA is opt-in and seeded on exactly one account (`carol`), not
  `admin`/`sam`/`alice`/`bob`.** Roughly 40+ of this app's other
  challenges assume those four accounts complete login in a single
  step (the SQLi bypass, brute force, the CSRF-backdoor chain, and
  more) — adding a second factor to any of them would have silently
  broken every one of those. A fifth, brand-new account keeps 2FA
  fully additive instead of a breaking change.
- **The XXE module's simple-tier bug is PHP-version-sensitive by
  design, not by accident.** `simplexml_load_string()` loads external
  entities by default on PHP before 8.0 — the exact target this app
  is built for (see the PHP 5.2 notes throughout) — but PHP 8+
  disables that by default regardless of what the code says. If
  you're testing this module on a modern PHP install instead of the
  intended Metasploitable2/legacy target, the simple-tier *external
  file read* won't demonstrate itself the same way; the intermediate
  tier's `LIBXML_NOENT` entity-substitution bug doesn't depend on that
  default and reproduces identically on any PHP version.
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
- **The JWT signing secret (`settings.jwt_secret`) is generated randomly
  per install** (`MD5(RAND())` in `db_setup.sql`), never a fixed value in
  any source file. This app is open source, so a hardcoded secret
  would make every JWT challenge trivial by just reading the repo
  instead of exploiting a real verification-logic bug — every JWT bug
  here (algorithm confusion, missing expiry, no revocation) is meant to
  be exploitable without ever knowing the secret at all.
- The `activity_log` table doubles as the rate-limit counter for
  `api/auth_token.php` (`action = 'api_token_fail'` rows within a
  rolling 5-minute window) rather than a dedicated table — reuse an
  existing table before adding a new one if the data genuinely fits.

## 14. Building on this later

- `api/` and `feedback/` follow the same one-level-deep folder
  convention as `admin/`, `user/`, `support/`, `challenges/`,
  `toolkit/` — if you add a new top-level module folder, register its
  name in `app_base()`'s `$known_subfolders` list in
  `includes/compat.php`, or its links will break under subfolder
  deployment (see the git history for what that bug looked like the
  first time it happened).
- New vulnerable modules should get a `'difficulty'` rating
  (`Entry`/`Standard`/`Stretch`) and a two-part `'hints'` array
  (`nudge`/`answer`) in `challenges/index.php`, matching the existing
  70 tiered entries, so they sort correctly and fit the site's format.
  If you want vote data on it too, give it the same `challenge_slug()`-
  based `id` and the `render_feedback_widget()` call already used by
  every other card — nothing else to wire up. A standalone, non-tiered
  challenge (a CTF flag chain, like the two in `$ctf_flags`, or a recon
  step, like the five in `$recon`) uses the narrower `title`/`module`/
  `target`/`objective`/`tools`/`steps`/`clue` shape instead — no
  `difficulty`, `concept`, or `hints`.
- If a new module depends on real concurrency (a race condition, a
  timing attack), test it against actual Apache/PHP-FPM, not just
  `php -S` — see the note above.
- If a new module needs a server-side secret (the JWT module's
  `jwt_secret` is the current example), generate it randomly per
  install in `db_setup.sql` rather than hardcoding it anywhere in the
  PHP source — see the note above on why.
- `setup.sh` (Metasploitable2), `setup-modern.sh` (modern Debian/
  Ubuntu), and `setup-rhel.sh` (RHEL/Fedora family) are separate
  scripts on purpose, not one script branching on OS detection — they
  target genuinely different environments
  (`/etc/init.d` vs. `systemctl`, `/var/www` vs. `/var/www/html` as
  `DocumentRoot`, MySQL 5.0's open-by-default root vs. modern
  MariaDB's `auth_socket`, `apt`/`www-data`/no-SELinux vs.
  `dnf`-or-`yum`/`apache`/SELinux-and-firewalld). If you change
  deployment behavior in one, check whether the others need the
  equivalent change too — don't assume fixing one automatically fixes
  the others, since that
  assumption is exactly what broke `setup.sh` when it was first run
  against a modern machine (three separate real bugs, found by
  actually running it, not by inspection).
