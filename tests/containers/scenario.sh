#!/usr/bin/env bash
# The migration end to end, as root, with real useradd, chown, ACLs, Apache, PHP-FPM, sshd and a
# database server. Exit 0 only if every check passes.
set -euo pipefail
fail() { echo "SCENARIO FAILED: $*" >&2; exit 1; }
ok()   { echo "ok: $*"; }

D=/root/larry; SRC=/var/www/shop; DOM=shop.example.org; IN=/srv/migration-incoming
mkdir -p "$D" "$SRC/httpdocs" "$IN" /var/backups /srv/vhosts /run/mysqld /run/sshd
chmod 700 "$D"

# ---- database server (socket only) and the source database
if command -v mariadbd >/dev/null; then (mariadbd --user=mysql --skip-networking >/var/log/db.log 2>&1 &); else (mysqld --user=mysql --skip-networking >/var/log/db.log 2>&1 &); fi
for _ in $(seq 60); do mysqladmin ping >/dev/null 2>&1 && break; sleep 1; done
mysqladmin ping >/dev/null 2>&1 || fail "database server did not start"
mysql -e "CREATE DATABASE shop; CREATE USER 'shopuser'@'localhost' IDENTIFIED BY 'pw-123'; GRANT ALL ON shop.* TO 'shopuser'@'localhost';
          CREATE USER 'larry_ro'@'localhost' IDENTIFIED BY 'ro-123';
          GRANT SELECT, LOCK TABLES, SHOW VIEW, PROCESS, EVENT, TRIGGER ON *.* TO 'larry_ro'@'localhost';
          USE shop; CREATE TABLE t (id INT PRIMARY KEY, v VARCHAR(20)) ENGINE=MyISAM; INSERT INTO t VALUES (1,'from-source');"
printf '[client]\nuser=larry_ro\npassword=ro-123\n' > "$D/source-db.cnf"; chmod 600 "$D/source-db.cnf"
printf '[client]\nuser=root\n' > "$D/target-db.cnf"; chmod 600 "$D/target-db.cnf"

# ---- the source site (its own vhost, which is disabled again before the target side is provisioned)
cat > "$SRC/httpdocs/index.php" <<PHP
<?php
\$r = new mysqli('localhost','shopuser','pw-123','shop'); \$row = \$r->query('SELECT v FROM t')->fetch_row();
echo posix_getpwuid(posix_geteuid())['name'], '|', \$row[0], '|', '$SRC/httpdocs';
PHP
cat > "$SRC/httpdocs/wp-config.php" <<'PHP'
<?php
define('DB_NAME', 'shop'); define('DB_USER', 'shopuser'); define('DB_PASSWORD', 'pw-123'); define('DB_HOST', 'localhost');
PHP
cat > "/etc/apache2/sites-available/$DOM.conf" <<CONF
<VirtualHost *:80>
  ServerName $DOM
  DocumentRoot $SRC/httpdocs
</VirtualHost>
CONF
a2ensite "$DOM" >/dev/null; apache2ctl start 2>/dev/null || apache2ctl graceful

# ---- transfer account with the forced rrsync, sshd on 2222
id migrate >/dev/null 2>&1 || useradd --system --home-dir "$IN" --shell /bin/sh migrate
chown migrate: "$IN"; chmod 700 "$IN"
ssh-keygen -q -t ed25519 -N '' -f "$D/id_ed25519"; ssh-keygen -q -t ed25519 -N '' -f "$D/hostkey"
mkdir -p "$IN/.ssh"
KEYLINE="restrict,from=\"127.0.0.1\",command=\"/usr/bin/rrsync -wo $IN\" $(cat "$D/id_ed25519.pub")"
echo "$KEYLINE" > /etc/ssh-authorized-migrate; chown migrate: /etc/ssh-authorized-migrate; chmod 600 /etc/ssh-authorized-migrate
cat > "$D/sshd_config" <<CONF
Port 2222
ListenAddress 127.0.0.1
HostKey $D/hostkey
PidFile /run/sshd-larry.pid
AuthorizedKeysFile /etc/ssh-authorized-migrate
UsePAM no
PasswordAuthentication no
StrictModes no
CONF
mkdir -p /run/sshd; /usr/sbin/sshd -f "$D/sshd_config"
FP=$(ssh-keygen -lf "$D/hostkey.pub" | awk '{print $2}')
echo "[127.0.0.1]:2222 $(cut -d' ' -f1,2 "$D/hostkey.pub")" > "$D/known_hosts"
cat > "$D/ssh_config" <<CONF
Host larry-web1
    HostName 127.0.0.1
    Port 2222
    User migrate
    IdentityFile $D/id_ed25519
    IdentitiesOnly yes
    StrictHostKeyChecking yes
    UserKnownHostsFile $D/known_hosts
    BatchMode yes
CONF
cat > "$D/migration.toml" <<CONF
version = 1
[source]
db_defaults_file = "$D/source-db.cnf"
staging_dir = "/var/tmp/larry"
[ssh]
config_file = "$D/ssh_config"
known_hosts = "$D/known_hosts"
[targets.web1]
host = "127.0.0.1"
host_key = "$FP"
transfer_user = "migrate"
incoming_dir = "$IN"
default = true
CONF
L="larry -c $D/migration.toml"

# ---- discover and plan (the source vhost is live now)
$L discover || [ $? -eq 2 ] || fail "discover"
$L plan || [ $? -eq 2 ] || fail "plan"
grep -q "db = \"shop\"" "$D/sites.toml" || fail "plan did not find the database"
ok "discover and plan found the site and its database"
a2dissite "$DOM" >/dev/null; apache2ctl graceful

# ---- sync, provision, apply
$L sync || [ $? -eq 2 ] || fail "sync"
[ -f "$IN/$DOM/manifest.json" ] || fail "manifest not in the drop directory"
# transfer account is write-only
! ssh -F "$D/ssh_config" larry-web1 id 2>/dev/null || fail "remote command was allowed"
ok "files and dump arrived; the transfer account cannot run commands"
# the drop directory belongs to migrate; root reads it
larry provision --incoming "$IN" || [ $? -eq 2 ] || fail "provision"
id php-shop-example-org >/dev/null || fail "pool user missing"
test "$(stat -c %U:%G /srv/vhosts/$DOM/public)" = "php-shop-example-org:www-data" || fail "owner after provision"
larry target apply --incoming "$IN" --db-defaults-file "$D/target-db.cnf" || [ $? -eq 2 ] || fail "apply"
ok "provision and apply ran"

# ---- what the site does now
OUT=$(curl -fsS --resolve "$DOM:80:127.0.0.1" "http://$DOM/")
[ "${OUT%%|*}" = "php-shop-example-org" ] || fail "PHP does not run as the pool user: $OUT"
case "$OUT" in *"|from-source|"*) ok "PHP runs as the pool user and reads the migrated MyISAM data";; *) fail "page: $OUT";; esac
test "$(stat -c %a /srv/vhosts/$DOM/public/index.php)" = 640 || fail "file mode"
sudo_can() { setpriv --reuid=www-data --regid=www-data --init-groups test -x "$1"; }
sudo_can "/srv/vhosts/$DOM/public" || fail "www-data cannot traverse"
getfacl -p "/srv/vhosts/$DOM/public/index.php" | grep -q '^group::r--' || fail "group ACL"
ok "ownership, modes and ACLs as specified"

# ---- spec regression: the app's DB user survives a re-sync (DROP + CREATE)
mysql -e "UPDATE shop.t SET v='changed-on-source'"
$L sync --db || [ $? -eq 2 ] || fail "db re-sync"
larry target apply --incoming "$IN" --db-defaults-file "$D/target-db.cnf" || [ $? -eq 2 ] || fail "re-apply"
OUT=$(curl -fsS --resolve "$DOM:80:127.0.0.1" "http://$DOM/")
case "$OUT" in *"|changed-on-source|"*) ok "grants survived DROP/CREATE; re-sync carried the change";; *) fail "after re-sync: $OUT";; esac
ls /var/backups/larry/db/shop-* >/dev/null || fail "no backup of the replaced database"

# ---- cutover check and cleanup
$L cutover --check-only || [ $? -eq 2 ] || fail "cutover check"
larry cleanup --target web1 --user migrate --incoming "$IN" --no-certbot --sshd-config /etc/ssh/sshd_config || [ $? -eq 2 ] || fail "cleanup"
test -d "$IN" && fail "drop directory still there"
ok "cutover check and cleanup"
echo "SCENARIO PASSED"
