# larry: step-by-step guide

This walks one migration from an old server (the **source**) to a new one (the **target**). Commands marked
*source* run where the sites live now, commands marked *target* run on the new server as root. Read the
[safety model](../README.md#safety-model) once, and use `--dry-run` before every command that changes anything.

Every command returns `0` (clean), `2` (done, but something needs your review) or `1` (error).

## 0. Before you start

- Install `larry` on both servers ([README](../README.md#install)). The two servers need not be the same version of Debian or Ubuntu.
- On the target install Apache, the PHP-FPM version(s) your sites need, MariaDB or MySQL, `rsync`, `acl` and `certbot`.
- Create a **read-only database account** on the source:

  ```sql
  CREATE USER 'larry_ro'@'localhost' IDENTIFIED BY '…';
  GRANT SELECT, LOCK TABLES, SHOW VIEW, PROCESS, EVENT, TRIGGER ON *.* TO 'larry_ro'@'localhost';
  ```

  and put it in a defaults file, mode 0600, for example `/root/migration-db.cnf`:

  ```ini
  [client]
  user=larry_ro
  password=…
  ```

- On the target create a defaults file for an **admin account** that may create databases and users
  (default path `/root/larry-db.cnf`, mode 0600). On a stock Debian MariaDB, root over the socket works:

  ```ini
  [client]
  user=root
  ```

- Work in a directory only root can read, for example `/root/larry/`. It will hold `migration.toml`,
  the SSH key and config, `inventory.jsonl`, `sites.toml` and the journal.

## 1. Set up the connection (source)

```sh
cd /root/larry
larry init
```

The wizard asks for this server's public IP (as the target sees it) and, per target: a name, host,
address, **SSH port** (default 22), the transfer account (default `migrate`) and the drop directory
(default `/srv/migration-incoming`). It then shows the host key the target offers and asks you to type
the fingerprint **from the target's console**, not from this connection:

```sh
# on the target, at its console or over a separate trusted channel
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
```

A wrong fingerprint pins nothing and writes nothing. When all targets are confirmed, `init` writes
`migration.toml`, `ssh_config`, `known_hosts` and a transfer key, and prints, for each target, the commands to
run there.

## 2. Prepare the target (target, root)

Run what `init` printed. In short:

```sh
# 1. the transfer account (no shell, no sudo) and the drop directory
adduser --system --group --shell /usr/sbin/nologin --home /srv/migration-incoming migrate
install -d -o migrate -m 0700 /srv/migration-incoming
# 2. put the printed key line into ~migrate/.ssh/authorized_keys. It looks like:
#    restrict,from="<source IP>",command="/usr/bin/rrsync -wo /srv/migration-incoming" ssh-ed25519 AAAA…
```

With that line the account can only write into the drop directory. It cannot run commands, read files back
or leave the directory. Password login is only a fallback: if you use it, run
`larry target sshd --target web1 --user migrate --source-ip <source IP> --apply`, which refuses the account from
every other address, backs up `sshd_config`, runs `sshd -t` and checks the effective settings (an `Include` at
the top of `sshd_config` can otherwise silently win). Reloading sshd stays your step. With password login,
set the account's home to the drop directory, because `larry` pushes to `./<domain>/…`.

Root SSH login is never needed.

## 3. Check the source (source)

```sh
larry config check     # parses migration.toml, refuses group- or world-readable secret files
larry preflight        # tools, secrets, pinned host keys, database access, reachability
```

Fix every `FAIL` line. Then discover and plan:

```sh
larry discover
larry plan             # or: larry plan --interactive
```

`discover` is read-only. It writes `inventory.jsonl` and prints a report; findings marked for review are
decisions for you (the report says what to decide). Typical ones:

| Finding | What to do |
| --- | --- |
| Database unresolved (several candidates, or a name that does not exist) | The site is held back. Run `larry plan --interactive`, or `larry plan --db shop.example.org=shop_db` (empty name for no database) |
| `php_value` / `php_flag` found in the vhost or `.htaccess` | These return HTTP 500 under PHP-FPM. They are proposed as pool settings in `sites.toml`; keep or drop each one |
| Old absolute paths in PHP files | Set `rewrite_paths = true` for the site if the paths should be rewritten |
| DEFINER accounts of views, triggers or routines | Create those accounts on the target, or they fail at query time |
| Mail: PHP `mail()` | The target needs a working MTA (and SPF/DKIM for the new IP) |
| Cron entries pointing into a site | v1 does not move cron jobs; recreate them on the target |
| Nested vhost, shared docroot, redirect-only vhost | Reported; nested sites become their own flat sites, redirect-only vhosts get no files |

`plan` writes `sites.toml`. Open it and review it: it is the file you edit. Example:

```toml
[[site]]
domain        = "shop.example.org"
target        = "web1"
docroot       = "public"          # directory name inside /srv/vhosts/<domain>/
db            = "shop_db"
rewrite_paths = false
manage_pool   = false             # true lets larry rewrite an existing pool it adopted

[site.fpm]
max_children = 8
[site.fpm.php_value]
memory_limit = "256M"             # from .htaccess, proposed by discover
```

A later `larry plan` never overwrites a `sites.toml` you edited. It writes `sites.new.toml` and shows the
differences (exit 2).

Pool defaults (PHP version, `pm`, `max_children`, user pattern, …) live in `migration.toml` under
`[fpm.defaults]`; a site's `[site.fpm]` overrides them. Pool users are named `php-<domain-with-dashes>`
(cut to 32 characters with a hash suffix).

Run `larry preflight` again once `sites.toml` exists: it now also hands the plan's facts to each target.

## 4. Check the target (target, root)

```sh
larry target preflight --db-defaults-file /root/larry-db.cnf
```

It checks tools, the PHP-FPM versions your sites need, free space, **name and ownership conflicts** (another
vhost already serving the domain, a pool user used by another pool, files owned by another site's pool user)
and, with the defaults file, that every **collation** the source databases use exists on this server. Fix
every `FAIL` before continuing.

## 5. First sync (source), then provision and apply (target)

```sh
larry sync --dry-run
larry sync              # files, certificates, manifest and database dumps into the drop directory
```

`sync` can be limited: `--files`, `--db`, or named domains (`larry sync shop.example.org`). It is safe to
repeat: the first run is full, later runs carry only changes. `--resume` skips steps already done under the
same `sites.toml`. Dumps use `--single-transaction` when every table is InnoDB and `--lock-tables` otherwise,
are checksummed, and are verified again before they are imported.

On the target:

```sh
larry provision --dry-run
larry provision
larry target apply --dry-run
larry target apply
```

`provision` creates the pool user, the PHP-FPM pool, the Apache vhost, the directories and installs the site's
Let's Encrypt certificate and renewal config. Pool and vhost files are tested (`php-fpm -t`,
`apache2ctl configtest`) before any reload; a failed test puts the old file back. If a vhost for the domain
already exists, it is adopted: its pool is found through its PHP socket and left alone unless the site sets
`manage_pool = true`.

`target apply` snapshots what is there, copies the files, rewrites old PHP paths if the site asked for it,
sets ownership (`<pool user>:www-data`, directories 0750, files 0640) and ACLs, checks with `setpriv` that the
pool user can read and Apache can traverse the docroot, imports the database (existing database dumped to
`/var/backups/larry/db/` first), and creates the application's database user from its own config
(WordPress, `.env`, Joomla; otherwise it warns). It refuses a vhost tree holding another site's files unless
you pass `--adopt`.

Useful options: `DOMAIN…` to limit the run, `--mirror` to also remove files that are gone on the source
(they move to a timestamped backup directory, nothing is deleted), `--deploy-user NAME` for ACLs for a deploy
user, `--vhost-base`, `--incoming`, `--backup-dir`, `--db-defaults-file` if you deviate from the defaults.

Test the new site before DNS changes, without touching DNS:

```sh
curl --resolve shop.example.org:443:<target IP> https://shop.example.org/
```

## 6. Repeat until cutover

Run `larry sync` on the source and `larry target apply` on the target as often as you like while the old
site stays live. Each cycle brings the target up to date.

## 7. Cutover

```sh
# source
larry cutover --freeze-source     # 503 page for the moved hosts, then a final sync of files and databases
# target
larry target apply                # puts the last changes in
# source
larry cutover --check-only        # curl --resolve against each host on the target: ok / REVIEW / FAIL
```

`--freeze-source` is opt-in: it adds one Apache snippet that answers 503 for the moved host names only,
tests the configuration and reloads. Cron jobs and mail keep running on the source, so stop what writes.
Without the freeze, changes made after the final sync are lost. `larry cutover --unfreeze` removes the page
again.

When everything is `ok`, **change DNS yourself**.

## 8. Clean up (target, root)

After DNS points at the target:

```sh
larry cleanup --dry-run --target web1
larry cleanup --target web1
systemctl reload ssh              # activate the sshd change
```

It removes the marked sshd block (after a backup and `sshd -t`), locks and expires the transfer account,
renames the drop directory with a timestamp (nothing is deleted), and runs `certbot renew --dry-run` to
confirm renewal works on the target.

## Files and where things go

| Path | Holds |
| --- | --- |
| `migration.toml`, `ssh_config`, `known_hosts`, `id_ed25519` | Connection setup, written by `init` (source) |
| `inventory.jsonl` | What `discover` found (source) |
| `sites.toml` | The plan; edit it (source) |
| `journal.jsonl` | One line per changing step: site, step, plan hash, result (source; target: `/var/backups/larry/journal.jsonl`) |
| `/srv/migration-incoming/<domain>/` | Drop directory on the target: `manifest.json`, `docroot/`, `extra/`, `<domain>.db.sql.gz` + `.sha256`, `tls/` |
| `/var/backups/larry/` | Target: file snapshots, replaced-file backups, database backups |
| `/srv/vhosts/<domain>/` | Target site: `public/` (or the planned docroot), `logs/`, `tmp/` |

## Troubleshooting

- **`Host key verification failed`**: the target's key changed or `known_hosts` has the wrong entry. Do not
  bypass it; compare the fingerprint on the console and re-run `init` for that target.
- **`ControlPath too long`**: ssh refuses sockets of 108 bytes or more. `init` falls back to `/tmp` when
  your directory is long; otherwise use a shorter directory.
- **`another larry run holds the lock`**: a second run for the same site. Wait for it, or check for a stale
  process; locks are released when the process ends.
- **Collation missing on the target**: the databases come from MySQL 8 and the target is MariaDB (or the
  reverse). Convert the collation on the source or use a matching server version.
- **PHP site returns 500 after the move**: look for `php_value` lines you did not carry into
  `[site.fpm.php_value]`, and read `/srv/vhosts/<domain>/logs/php-fpm-error.log`.
- **Static files return 403**: `www-data` cannot traverse a parent directory; `target apply` warns about
  this in its access checks.
- **Exit code 2** is not a failure: something needs a human look. The output says what.

Found a bug or a gap? Open an issue at <https://github.com/SilverDay/larry/issues>.
