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

## 1. Deploy to Metasploitable2 — step by step

**Prerequisites:** Metasploitable2 running in VirtualBox/VMware on a
**host-only or internal network** (not bridged to the internet), and
you know its IP (`ip addr` or `ifconfig` on the VM console — default
creds `msfadmin`/`msfadmin`).

1. **Confirm the stack is up on Metasploitable2**
   ```bash
   ssh msfadmin@<metasploitable2-ip>
   sudo service apache2 status
   sudo service mysql status
   php -v          # ships PHP 5.2.x — this app avoids modern syntax on purpose
   php -m | grep mysqli   # confirm the mysqli extension is present
   ```
   If Apache/MySQL aren't running: `sudo service apache2 start` / `sudo service mysql start`.

2. **Copy the project over** (from your trainer machine, same network as the VM)
   ```bash
   scp -r vulnapp msfadmin@<metasploitable2-ip>:/tmp/
   ```

3. **Install it under the webroot**
   ```bash
   ssh msfadmin@<metasploitable2-ip>
   sudo mv /tmp/vulnapp /var/www/vulnapp
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
   `sudo a2ensite vulnapp`, `sudo service apache2 restart`.
   (Port 80 is already used by Metasploitable2's own vulnerable apps —
   pick a free port like 8080 if you go this route.)

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

`user/profile_export.php` is a good standalone target at every
tier since its missing ownership check doesn't depend on the toggle.

## 5. In-app Challenges page

Every logged-in user (any role) can open **Challenges** from the
dashboard, or browse directly to `/challenges/index.php`. It lists,
per difficulty tier: the objective, the legitimate tools suited to
it (Burp Suite, sqlmap, Hydra, ffuf, exiftool, browser devtools),
numbered methodology steps, and a click-to-reveal clue — no full
payload is pre-typed, so students still have to construct the final
exploit themselves. It's driven by a plain PHP array at the top of
`challenges/index.php`, so it's easy to add your own challenges as
you extend the app.

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

## 6. Suggested student flow

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

## 7. Resetting state

```bash
mysql -u root < /var/www/vulnapp/db_setup.sql   # re-run anytime to reset users/tickets
rm -f /var/www/vulnapp/uploads/*                 # clear uploaded files (keep .gitkeep if you add one)
```

## 8. Notes

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
