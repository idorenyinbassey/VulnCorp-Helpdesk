#!/bin/bash
# VulnCorp Helpdesk - one-command setup for a MODERN Ubuntu/Debian VM
# (systemd-based, e.g. Ubuntu 22.04/24.04 Server).
#
# This is NOT for Metasploitable2 - see setup.sh for that. Use this one
# on a separate, modern VM if you want to run the app natively (no
# Docker, no containers) instead of the docker/ path. See the main
# README's "Deploy the Docker version on its own VM" section for how
# to provision that VM - the same VM works here, just skip Docker
# entirely and run this script instead.
#
# Run this ON THE MODERN VM, from inside the folder you cloned there
# (the one containing this script, index.php, db_setup.sql, etc.):
#
#   sudo bash setup-modern.sh
#
# Installs Apache/PHP/MariaDB if not already present, fixes MariaDB's
# modern auth_socket default (which would otherwise block the app from
# connecting), deploys to /var/www/html/vulnapp (this distro's actual
# default DocumentRoot - NOT /var/www/vulnapp, which is what setup.sh
# uses for Metasploitable2's different default), loads the schema,
# detects this machine's real IP, and prints the URL and every login.

set -e

APP_DIR="/var/www/html/vulnapp"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_PASS_FOR_ROOT=""   # matches includes/db.php's default (empty password)

echo "=================================================="
echo " VulnCorp Helpdesk setup (modern Ubuntu/Debian)"
echo "=================================================="

if [ "$(id -u)" != "0" ]; then
    echo "This needs root. Re-run as:"
    echo "  sudo bash setup-modern.sh"
    exit 1
fi

if [ ! -f "$SRC_DIR/db_setup.sql" ] || [ ! -f "$SRC_DIR/index.php" ]; then
    echo "Error: couldn't find db_setup.sql / index.php next to this script."
    echo "Run this from inside the VulnCorp Helpdesk folder you cloned,"
    echo "e.g.: cd VulnCorp-Helpdesk && sudo bash setup-modern.sh"
    exit 1
fi

if [ "$1" != "--yes" ] && [ "$1" != "-y" ]; then
    echo ""
    echo "This will install/update the app at $APP_DIR and RESET its"
    echo "database - any accounts, tickets, or uploaded files added since"
    echo "the last reset will be wiped."
    printf "Continue? [y/N] "
    read confirm
    case "$confirm" in
        y|Y|yes|YES) ;;
        *) echo "Aborted - nothing changed."; exit 0 ;;
    esac
fi

echo ""
echo "-- Installing Apache, PHP, and MariaDB if not already present --"
export DEBIAN_FRONTEND=noninteractive
# Tolerate a failure on any single configured repo (common on real machines
# with third-party sources) - as long as apt's own archive is reachable,
# the packages below will still install fine even if `apt-get update`
# itself returns non-zero because some unrelated repo was unreachable.
apt-get update -qq || true
apt-get install -y -qq apache2 mariadb-server php php-mysqli libapache2-mod-php > /dev/null

echo "-- Starting Apache and MariaDB --"
if command -v systemctl >/dev/null 2>&1 && systemctl list-units >/dev/null 2>&1; then
    systemctl enable --now apache2 > /dev/null 2>&1 || true
    systemctl enable --now mariadb > /dev/null 2>&1 || true
else
    # systemd isn't actually reachable here (e.g. inside a container, or
    # WSL without systemd enabled) - fall back to direct service invocation.
    service apache2 start > /dev/null 2>&1 || true
    service mariadb start > /dev/null 2>&1 || true
fi
sleep 2

echo "-- Fixing MariaDB root authentication --"
# Modern MariaDB defaults 'root'@'localhost' to auth_socket, which only
# accepts connections from the literal Linux root user - the app's PHP
# process (running as www-data via Apache) gets "Access denied" against
# that. Switch to a real (still empty, matching includes/db.php's
# default) password so www-data can connect too - the same access
# Metasploitable2's own MySQL already allows by default, since it
# predates auth_socket entirely.
mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED VIA mysql_native_password USING PASSWORD('${DB_PASS_FOR_ROOT}'); FLUSH PRIVILEGES;"

echo "-- Installing app files to $APP_DIR --"
mkdir -p "$APP_DIR"
if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
        --exclude '.git' \
        --exclude 'setup.sh' \
        --exclude 'setup-modern.sh' \
        --exclude 'docker' \
        "$SRC_DIR"/ "$APP_DIR"/
else
    find "$SRC_DIR" -mindepth 1 -maxdepth 1 \
        ! -name '.git' ! -name 'setup.sh' ! -name 'setup-modern.sh' ! -name 'docker' \
        -exec cp -r {} "$APP_DIR"/ \;
fi

echo "-- Fixing ownership and permissions --"
chown -R www-data:www-data "$APP_DIR"
chmod -R 755 "$APP_DIR"
mkdir -p "$APP_DIR/uploads"
chmod -R 777 "$APP_DIR/uploads"

echo "-- Loading database schema (resets all data) --"
mysql -u root < "$APP_DIR/db_setup.sql"

echo "-- Detecting this machine's IP address --"
IP="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)"
if [ -z "$IP" ]; then
    IP="<this-machine-ip>"
fi

echo ""
echo "=================================================="
echo " Done. VulnCorp Helpdesk is ready."
echo ""
echo "   URL:   http://$IP/vulnapp/"
echo ""
echo "   Login  admin / admin123"
echo "          sam   / support123"
echo "          alice / alice123"
echo "          bob   / bob123"
echo ""
echo " Re-run this script (sudo bash setup-modern.sh) any time you pull an"
echo " update, to refresh the deployed files and reset the database."
echo "=================================================="
