#!/bin/bash
set -e
DATADIR=/var/lib/mysql

if [ ! -d "$DATADIR/mysql" ]; then
    echo "[devtest-entrypoint] Initializing data directory..."
    mysql_install_db --datadir="$DATADIR" --user=mysql > /dev/null

    mysqld --datadir="$DATADIR" --user=mysql --skip-networking --socket=/run/mysqld/mysqld.sock &
    pid=$!
    for i in $(seq 1 30); do
        mysqladmin --socket=/run/mysqld/mysqld.sock ping >/dev/null 2>&1 && break
        sleep 1
    done

    echo "[devtest-entrypoint] Setting root password and creating database..."
    mysql --socket=/run/mysqld/mysqld.sock -u root <<-EOSQL
        ALTER USER 'root'@'localhost' IDENTIFIED VIA mysql_native_password USING PASSWORD('${MYSQL_ROOT_PASSWORD}');
        CREATE USER IF NOT EXISTS 'root'@'%' IDENTIFIED VIA mysql_native_password USING PASSWORD('${MYSQL_ROOT_PASSWORD}');
        GRANT ALL PRIVILEGES ON *.* TO 'root'@'%' WITH GRANT OPTION;
        CREATE DATABASE IF NOT EXISTS \`${MYSQL_DATABASE}\`;
        FLUSH PRIVILEGES;
EOSQL

    for f in /docker-entrypoint-initdb.d/*.sql; do
        if [ -f "$f" ]; then
            echo "[devtest-entrypoint] Running init script: $f"
            mysql --socket=/run/mysqld/mysqld.sock -u root -p"${MYSQL_ROOT_PASSWORD}" < "$f"
        fi
    done

    mysqladmin --socket=/run/mysqld/mysqld.sock -u root -p"${MYSQL_ROOT_PASSWORD}" shutdown
    wait "$pid" || true
    echo "[devtest-entrypoint] Init complete."
fi

exec mysqld --datadir="$DATADIR" --user=mysql --bind-address=0.0.0.0
