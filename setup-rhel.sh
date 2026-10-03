#!/bin/bash
# VulnCorp Helpdesk - one-command setup for a RHEL/Fedora-family VM
# (RHEL, CentOS Stream, Rocky Linux, AlmaLinux, Fedora - anything using
# dnf/yum + httpd + systemd).
#
# This is NOT for Metasploitable2 (see setup.sh) and NOT for Debian/Ubuntu
# (see setup-modern.sh) - this script targets the RHEL/Fedora package
# ecosystem specifically: dnf/yum instead of apt, httpd instead of
# apache2, the 'apache' user instead of 'www-data', and (when present)
# SELinux contexts and firewalld, none of which setup-modern.sh handles.
#
# Run this ON THE RHEL/FEDORA VM, from inside the folder you cloned
# there (the one containing this script, index.php, db_setup.sql, etc.):
#
#   sudo bash setup-rhel.sh
#
# Installs httpd/PHP/MariaDB if not already present, fixes MariaDB's
# modern auth_socket default, opens the SELinux context the uploads/
# folder needs (only if SELinux is actually enforcing/permissive on this
# box), opens the firewall for HTTP (only if firewalld is active), deploys
# to /var/www/html/vulnapp, loads the schema, detects this machine's real
# IP, and prints the URL and every login.

set -e

APP_DIR="/var/www/html/vulnapp"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
DB_PASS_FOR_ROOT=""   # matches includes/db.php's default (empty password)

echo "=================================================="
echo " VulnCorp Helpdesk setup (RHEL/Fedora family)"
echo "=================================================="

if [ "$(id -u)" != "0" ]; then
    echo "This needs root. Re-run as:"
    echo "  sudo bash setup-rhel.sh"
    exit 1
fi

if [ ! -f "$SRC_DIR/db_setup.sql" ] || [ ! -f "$SRC_DIR/index.php" ]; then
    echo "Error: couldn't find db_setup.sql / index.php next to this script."
    echo "Run this from inside the VulnCorp Helpdesk folder you cloned,"
    echo "e.g.: cd VulnCorp-Helpdesk && sudo bash setup-rhel.sh"
    exit 1
fi

PKG_MGR=""
if command -v dnf >/dev/null 2>&1; then
    PKG_MGR="dnf"
elif command -v yum >/dev/null 2>&1; then
    PKG_MGR="yum"
else
    echo "Error: neither dnf nor yum found - this script targets the RHEL/Fedora"
    echo "package family. Use setup-modern.sh (Debian/Ubuntu) or docker/ instead."
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
echo "-- Installing httpd, PHP, and MariaDB if not already present ($PKG_MGR) --"
# php-mysqlnd provides the mysqli extension on Fedora/RHEL - a different
# package name than Debian's php-mysqli (see setup-modern.sh).
"$PKG_MGR" install -y httpd mariadb-server php php-mysqlnd > /dev/null

echo "-- Starting httpd and MariaDB --"
systemctl enable --now httpd > /dev/null 2>&1 || true
systemctl enable --now mariadb > /dev/null 2>&1 || true
sleep 2

echo "-- Fixing MariaDB root authentication --"
# Same auth_socket issue as setup-modern.sh (see that script's comment) -
# modern MariaDB's 'root'@'localhost' default only accepts connections
# from the literal Linux root user, which httpd's PHP process is not.
mysql -u root -e "ALTER USER 'root'@'localhost' IDENTIFIED VIA mysql_native_password USING PASSWORD('${DB_PASS_FOR_ROOT}'); FLUSH PRIVILEGES;"

echo "-- Installing app files to $APP_DIR --"
mkdir -p "$APP_DIR"
if command -v rsync >/dev/null 2>&1; then
    rsync -a --delete \
        --exclude '.git' \
        --exclude 'setup.sh' \
        --exclude 'setup-modern.sh' \
        --exclude 'setup-rhel.sh' \
        --exclude 'docker' \
        "$SRC_DIR"/ "$APP_DIR"/
else
    find "$SRC_DIR" -mindepth 1 -maxdepth 1 \
        ! -name '.git' ! -name 'setup.sh' ! -name 'setup-modern.sh' ! -name 'setup-rhel.sh' ! -name 'docker' \
        -exec cp -r {} "$APP_DIR"/ \;
fi

echo "-- Fixing ownership and permissions --"
# 'apache' (not 'www-data') is the httpd worker user on RHEL/Fedora.
chown -R apache:apache "$APP_DIR"
chmod -R 755 "$APP_DIR"
mkdir -p "$APP_DIR/uploads"
chmod -R 777 "$APP_DIR/uploads"
mkdir -p "$APP_DIR/cache"
chmod -R 777 "$APP_DIR/cache"   # Cache Poisoning module, see includes/simple_cache.php

echo "-- Checking SELinux --"
if command -v getenforce >/dev/null 2>&1 && [ "$(getenforce)" != "Disabled" ]; then
    echo "   SELinux is $(getenforce) - setting the context httpd needs to"
    echo "   both serve this app and write to uploads/ and cache/."
    if ! command -v semanage >/dev/null 2>&1; then
        echo "   semanage isn't installed - installing policycoreutils-python-utils"
        "$PKG_MGR" install -y policycoreutils-python-utils > /dev/null 2>&1 || true
    fi
    if command -v semanage >/dev/null 2>&1; then
        semanage fcontext -a -t httpd_sys_rw_content_t "$APP_DIR/uploads(/.*)?" 2>/dev/null || true
        semanage fcontext -a -t httpd_sys_rw_content_t "$APP_DIR/cache(/.*)?" 2>/dev/null || true
        restorecon -Rv "$APP_DIR" > /dev/null 2>&1 || true
    else
        # Installing the package above failed (e.g. no network, repo
        # disabled) - don't silently claim success: Apache would be
        # blocked from writing to uploads/ by SELinux despite the Unix
        # permissions already being correct, and the upload module would
        # fail in a way that looks like this script worked.
        echo "   Error: semanage is required to configure the SELinux upload"
        echo "   context and could not be installed. Install"
        echo "   policycoreutils-python-utils manually and re-run this script."
        exit 1
    fi
else
    echo "   SELinux is disabled or not present - nothing to do here."
fi

echo "-- Checking firewalld --"
if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall-cmd --permanent --add-service=http > /dev/null 2>&1 || true
    firewall-cmd --reload > /dev/null 2>&1 || true
    echo "   Opened the http service in firewalld (on by default on RHEL/Fedora,"
    echo "   unlike most Debian cloud images - setup-modern.sh doesn't need this)."
else
    echo "   firewalld isn't running - nothing to do here."
fi

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
echo "          carol / carol123   (2FA enabled - see README section 3)"
echo ""
echo " Re-run this script (sudo bash setup-rhel.sh) any time you pull an"
echo " update, to refresh the deployed files and reset the database."
echo "=================================================="
