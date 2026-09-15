# VulnCorp Helpdesk — Docker deployment

A modern alternative to the Metasploitable2 deployment path in the
main README — same app, same 39 challenges, same Toolkit and feedback
tools, no SSH/scp/init.d/network-conflict dance.

**Worth being clear about when this actually helps:** Docker pays off
when you already have it running somewhere — a laptop with Docker
Desktop, a CI pipeline, a host you don't want to install Apache/PHP/
MariaDB directly onto. If you're creating a **dedicated VM just for
this app**, Docker doesn't save you anything — you still have to
provision that VM either way, so a native install
(`setup-modern.sh`, from the repo root, documented in the main
README's section 2) is simpler for that specific case. This file
covers the Docker path for when it *is* the better fit.

**Nothing about the vulnerable app changed for this.** The only
non-cosmetic code change anywhere in this repo for Docker support is
`includes/db.php` reading `DB_HOST`/`DB_USER`/`DB_PASS`/`DB_NAME` from
environment variables when present, falling back to the exact same
defaults Metasploitable2 needs when they're not set. Everything else —
every challenge, every difficulty tier, every deliberate bug — is
identical to the Metasploitable2 deployment.

## Quick start

```bash
git clone https://github.com/idorenyinbassey/VulnCorp-Helpdesk.git
cd VulnCorp-Helpdesk/docker
docker compose up -d
```

Then browse to **http://localhost:8080/** and log in with any of the
seeded accounts (see the main README's credentials table).

To reset (fresh database, re-pull the latest code into the image):
```bash
docker compose down -v
docker compose up -d --build
```

## What's in `docker/`

- `Dockerfile` — PHP 8.2 + Apache (`php:8.2-apache`), `mysqli` extension
  installed, app copied in and permissions fixed (including the
  world-writable `uploads/` the upload module needs).
- `docker-compose.yml` — two services: `db` (official `mariadb:10.11`,
  schema auto-loaded from `../db_setup.sql` via the standard
  `docker-entrypoint-initdb.d` mechanism) and `web` (built from the
  Dockerfile above, waits for `db`'s healthcheck before starting,
  exposed on `localhost:8080`).

That's the whole shipped setup — two files, one command.

## Why PHP 8.2 here but PHP 5.2 on Metasploitable2?

The app was built to run correctly on *both*. `includes/compat.php`
polyfills the handful of functions PHP 5.2 lacks (`hash_equals`,
`random_bytes`, a `mysqli_stmt_get_result` fallback for mysqli builds
without mysqlnd) behind `function_exists()` guards — so on PHP 8.2
those polyfills simply never activate, since the real functions
already exist, and the app behaves identically either way. This was
verified directly: every core exploit (SQLi bypass, the IDOR account
takeover, command injection, stored XSS, the race condition) was
re-tested against a real Apache + mod_php + MariaDB stack running
modern PHP, not just against the PHP 5.2 target, and behaved the same.

## A note on how this was verified

The sandbox this was built in can't reach Docker Hub (its network
egress is allowlisted to a handful of package registries, and
`registry-1.docker.io` isn't one of them) — so `docker/Dockerfile` and
`docker/docker-compose.yml` above, which use the official
`php:8.2-apache` and `mariadb:10.11` images, couldn't be built and run
directly in that environment.

To actually verify the orchestration logic (not just review it),
equivalent images were built from a locally-debootstrapped Ubuntu base
(pulling only from Ubuntu's own package archive, not Docker Hub) with
the same packages installed via `apt` instead of pulled as pre-built
images. Those stand-ins live alongside the real files for reference:
`Dockerfile.devtest`, `Dockerfile.db.devtest`, `docker-compose.devtest.yml`,
and `devtest-db-entrypoint.sh` (a small script replicating enough of
the official MariaDB image's first-boot behavior — reading
`MYSQL_ROOT_PASSWORD`/`MYSQL_DATABASE`, running `*.sql` files from
`/docker-entrypoint-initdb.d/` — to prove the compose file's env-var
wiring and healthcheck-gated startup actually work).

Running the full stack that way and testing through the exposed port
confirmed: the schema auto-loads correctly, the web container connects
to the db container over the Docker network via `DB_HOST=db`, the
SQLi auth bypass and other core exploits work identically to the
native deployment, and the race-condition module (which specifically
needs multi-process concurrency — see the main README's note on this)
behaves the same as it did against a native Apache install: ~5/15
successful claims at simple tier with naive concurrent `curl`.

If you hit an issue with the real `docker compose up` that this
verification didn't catch, it's most likely something specific to the
official images that the local stand-ins don't perfectly replicate —
worth checking the difference against `Dockerfile.devtest` /
`Dockerfile.db.devtest` first.

## Limitations vs. the Metasploitable2 deployment

- No other Metasploitable2 services (vsftpd 2.3.4, the other
  intentionally-vulnerable web apps, etc.) — this is VulnCorp Helpdesk
  alone, not a Metasploitable2 replacement. If a lesson needs those,
  keep the Metasploitable2 path.
- `uploads/` is not a named volume, so it resets whenever the
  container is recreated (`down` + `up`, or `--build`) — matching the
  training-lab expectation that a reset means a clean slate. Plain
  `stop`/`start` (no `down`) preserves it if you want persistence
  across a restart without a fresh install.
