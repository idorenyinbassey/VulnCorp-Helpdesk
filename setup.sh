#!/bin/bash
# VulnCorp Helpdesk - one-command setup for Metasploitable2
#
# Run this ON THE METASPLOITABLE2 BOX, from inside the folder you copied
# there (the one containing this script, index.php, db_setup.sql, etc.):
#
#   sudo bash setup.sh
#
# It installs/updates the app at /var/www/vulnapp, fixes ownership and
# permissions, starts Apache/MySQL if they aren't running, loads the
# database schema, and prints the URL and login credentials.
#
# Safe to re-run any time you pull an update from the repo - it will
# refresh the deployed files and reset the database to a clean state.

set -e

APP_DIR="/var/www/vulnapp"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=================================================="
echo " VulnCorp Helpdesk setup"
echo "=================================================="

if [ "$(id -u)" != "0" ]; then
    echo "This needs root. Re-run as:"
    echo "  sudo bash setup.sh"
    exit 1
fi

if [ ! -f "$SRC_DIR/db_setup.sql" ] || [ ! -f "$SRC_DIR/index.php" ]; then
    echo "Error: couldn't find db_setup.sql / index.php next to this script."
    echo "Run this from inside the VulnCorp Helpdesk folder you copied over,"
    echo "e.g.: cd /tmp/VulnCorp-Helpdesk-update && sudo bash setup.sh"
    exit 1
fi

if [ "$1" != "--yes" ] && [ "$1" != "-y" ]; then
    echo ""
    echo "This will install/update the app at $APP_DIR and RESET its"
    echo "database - any accounts, tickets, or uploaded files added since"
    echo "the last reset will be wiped. This matches a normal 'start of"
    echo "class' reset."
    printf "Continue? [y/N] "
    read confirm
    case "$confirm" in
        y|Y|yes|YES) ;;
        *) echo "Aborted - nothing changed."; exit 0 ;;
    esac
fi

echo ""
echo "-- Starting Apache and MySQL (harmless if already running) --"
/etc/init.d/apache2 start 2>/dev/null || true
/etc/init.d/mysql start 2>/dev/null || true

echo "-- Installing app files to $APP_DIR --"
mkdir -p "$APP_DIR"
if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
        --exclude '.git' \
        --exclude 'setup.sh' \
        "$SRC_DIR"/ "$APP_DIR"/
else
    # rsync not present - fall back to a plain copy. This won't remove
    # files that existed in a previous deploy but no longer exist in the
    # source, but it's good enough for a first install.
    find "$SRC_DIR" -mindepth 1 -maxdepth 1 ! -name '.git' ! -name 'setup.sh' \
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
IP="$(ifconfig eth0 2>/dev/null | grep 'inet addr' | awk -F: '{print $2}' | awk '{print $1}')"
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
echo " Re-run this script (sudo bash setup.sh) any time you pull an"
echo " update, to refresh the deployed files and reset the database."
echo "=================================================="
