# LAMP site migration tool (Rust) — v1 spec

Nov 2, 2026 · @Klaus

## Purpose and scope

v1 moves individual Apache/PHP/MariaDB sites from one Debian or Ubuntu server to one or more new servers, into a fixed flat layout with one PHP-FPM pool per site. It replaces our script chain (scan, manifest, package, deploy, DB re-sync) with one tool. `larry` is the working name.

It is for admins of self-managed LAMP servers without a control panel. Moves onto Plesk, ISPConfig or cPanel already have vendor migrators. Of the open-source tools, [HostShift](https://github.com/oguzhankrcb/HostShift) moves servers by workload type, and [rehost](https://github.com/pietervanleuven/rehost) moves single sites between shared hosting accounts but provisions nothing on the target.

**In scope for v1**

- Source: Apache 2.4 with mod\_php or PHP-FPM, MariaDB or MySQL, Debian/Ubuntu.
- Target: Apache 2.4 with mpm\_event and PHP-FPM, MariaDB, Ubuntu 24.04 LTS first. Other releases only once they pass the test matrix.
- Choosing sites one by one and spreading them across several targets.
- Repeatable file and database sync until cutover, then a verified final sync.
- Copying each site's existing Let's Encrypt certificate, so HTTPS works on the target before DNS moves.

**Out of scope for v1**

- Mail, DNS changes, nginx/Caddy, control panels, PostgreSQL, Docker.
- Cloning a whole server (packages, system config, users).
- Cron jobs, systemd timers and outgoing mail setup: discovery reports them, v1 does not move them.
- Rewriting absolute paths in databases: discovery reports them, v1 does not change them. Planned for a later version.

## Decisions for v1

The target layout is fixed; the PHP-FPM pool is the one part users configure.

| Area | v1 decision |
| --- | --- |
| Target layout | Every site gets its own `/srv/vhosts/<domain>/` (base path configurable). The docroot is a subdirectory of it, named per site. |
| Nesting | None. A source vhost inside another vhost's tree becomes its own flat vhost, and the parent's copy excludes it. |
| PHP-FPM | One pool per site, with its own Unix user and socket. Pool settings come from a template with per-site overrides. |
| open\_basedir | On by default: the vhost root plus the site's own `tmp`. |
| Ownership | Fixed: `<pool user>:www-data`, dirs 0750, files 0640, optional ACL for one deploy user. |
| Old paths | Always reported. Rewriting them in PHP files is opt-in per site. Database hits stay report-only in v1; a later version rewrites them too, handling PHP serialized data. |
| TLS | The site's existing Let's Encrypt certificate and renewal config are copied; renewal runs on the target after cutover. |
| App DB users | Created from the app's own config: `'<user>'@'localhost'` with that password and rights on its database only. |
| Changes | Plan, then apply. No command changes a target without a reviewed plan, and every changing command has `--dry-run`. |
| Deletion | Nothing is deleted. Replaced files, databases and config files are backed up or renamed with a timestamp first. |
| Source | Read-only, except a 0700 staging directory and an opt-in write freeze at cutover. |
| Tools | System `ssh`, `rsync`, `mysqldump` and `mysql` are orchestrated, never reimplemented. |
| Privileges | The transfer account can only drop files. Root steps on a target are run there by an admin; no sudo rule for the transfer account. |
| License | EUPL-1.2, REUSE-compliant. Signed release binaries; not published on crates.io. |

## Workflow and commands

Eight commands take a migration from config to cleanup. The first four change no target; `sync` repeats as often as needed before cutover.

&#91;embedded content: v1 workflow · 8 commands, 1 review gate\]

Only the plan you reviewed reaches the target, and only after preflight passes.

| Command | Runs on | Changes | What it does |
| --- | --- | --- | --- |
| `init` | source | local files | Wizard: targets, host-key pinning, `migration.toml`, SSH config, the sshd snippet per target |
| `discover` | source | nothing | Writes `inventory.jsonl` and a report |
| `plan` | source | local files | Writes `sites.toml`, or `sites.new.toml` plus a diff |
| `preflight` | source, plus `larry target preflight` as root | nothing | Host keys, reachability, disk space, DB access, PHP versions, collations, name and ownership conflicts |
| `provision` | target, root | target | Pool user, pool file, Apache vhost and directories, or adopts an existing vhost |
| `sync` | source pushes, target applies as root | target | `--files`, `--db` or both. The first run is full, later runs carry only changes. |
| `cutover` | both | target, source opt-in | Maintenance page on the source vhost, final sync, check each site on the target with `curl --resolve`. Changing DNS stays the admin's step. |
| `cleanup` | target, root | target | Remove the sshd Match block (after a backup), lock the transfer user, archive the drop directory |

Target commands run as `larry target <command>`, by an admin on that server. The source never logs in to a target as an admin.

## Configuration

All state lives in plain files the admin can read, diff and edit; the interactive mode only helps write them.

| File | Written by | Edited by hand | Holds |
| --- | --- | --- | --- |
| `migration.toml` | `init` (wizard) | yes | Source settings, targets, SSH settings, layout knobs, FPM pool defaults |
| `inventory.jsonl` | `discover` | no | One JSON line per source vhost: names, docroot, DB, sizes, findings |
| `sites.toml` | `plan` | yes | One `[[site]]` per site to move: target, docroot, DB, pool overrides |
| `state/journal.jsonl` | every changing command | no | Per site and step: plan hash, checksums, result |

`plan` never overwrites a `sites.toml` that was edited after it was written. It writes `sites.new.toml` and shows the diff instead.

**Interactive mode.** `larry init` asks for the targets and pins their host keys, then writes `migration.toml` and the SSH config. Nothing it learns lives anywhere else, so every later run is reproducible from the files alone. `larry plan --interactive` walks through the sites that need a decision (unresolved DB, nested root, redirect-only vhost) and records each answer in `sites.toml`.

**Example `migration.toml`** (illustrative values):

```toml
version = 1

[source]
db_defaults_file = "/root/migration-db.cnf"   # read-only DB account, mode 0600
staging_dir      = "/var/tmp/larry"

[ssh]
config_file = "/root/larry/ssh_config"        # generated by init
known_hosts = "/root/larry/known_hosts"       # pinned keys only

[targets.web1]
host          = "web1.example.net"
address       = "192.0.2.10"
host_key      = "SHA256:..."                  # confirmed out of band
transfer_user = "migrate"
incoming_dir  = "/srv/migration-incoming"
default       = true

[layout]
vhost_base      = "/srv/vhosts"
web_group       = "www-data"
deploy_acl_user = "deploy"                    # optional

[fpm.defaults]
php_version  = "8.3"
user_pattern = "php-{domain_dashed}"
pm           = "ondemand"
max_children = 4
```

**Example `sites.toml` entry:**

```toml
[[site]]
domain        = "shop.example.org"
target        = "web1"
docroot       = "public"
db            = "shop_db"
rewrite_paths = false                       # opt-in: rewrite old absolute paths in PHP files

[site.fpm]
max_children = 8
php_value    = { memory_limit = "256M" }      # proposed by discover from .htaccess, reviewed
```

Secrets never go into these files. Credentials stay in MySQL defaults files with mode 0600; `larry config check` refuses group- or world-readable secret files.

## Source discovery

`discover` is read-only and reports everything that needs a human decision; it never guesses. Exit 0 means clean, 2 means review needed, 1 means error.

1. **Vhosts.** Parse `apache2ctl -S` in both its name-based and IP-based forms, then read each vhost file for `DocumentRoot`, aliases, the SSL twin and a `proxy:unix:` socket.
2. **Nested roots.** Flag any docroot that lies inside another vhost's tree. The child becomes its own site; the parent's copy excludes that path.
3. **Redirect-only vhosts.** A vhost without a `DocumentRoot` is reported and gets no files.
4. **Databases.** Read the DB name from known app config files, using the detectors in `build-migration-manifest.py`, ported. Each name is checked against `SHOW DATABASES`. An unresolved site is held back, never written with an empty DB.
5. **PHP settings.** Collect `php_value`, `php_flag` and `php_admin_*` from vhosts and `.htaccess`. These return HTTP 500 under PHP-FPM, so each becomes a proposed pool setting for review, not an automatic change.
6. **Findings.** Report size and file count, file owners and orphaned GIDs, non-InnoDB tables, DEFINER accounts, cron entries that point into a docroot, and how the site sends mail.
7. **Old paths.** When a site's docroot path changes, search its files at discover time, and its database dump at every sync, for the old absolute path. Each hit is reported per site. Rewriting them in PHP files is a per-site option, described below.

**Path rewriting in PHP files (opt-in per site).** With `rewrite_paths = true`, `target apply` replaces the old absolute vhost and docroot paths with the new ones. It does this after every sync, because each sync brings back the source's copies.

- Only PHP files (`.php`, `.inc`, `.phtml`), and only the exact old path strings. The search runs again at every apply.
- A hit inside a PHP serialized string (`s:<length>:"…"`) is skipped and reported, because changing its length breaks it.
- Each changed file is backed up with a timestamp first. `--dry-run` shows the diff, and the report lists every change.
- Database hits stay report-only in v1. A later version rewrites them too, with the same per-site switch, handling PHP serialized data.

Output is `inventory.jsonl`, one line per vhost, plus a human-readable report.

## Target layout and PHP-FPM pools

The layout and ownership model are fixed, as in `deploy-migration-package.sh` v2. Each site's pool is built from a template with per-site overrides.

**Vhost root.** `/srv/vhosts/<domain>/` holds the docroot (default name `public`, set per site, e.g. `httpdocs`), a log directory and the site's own `tmp`.

**Fixed ownership model**

| Path | Owner | Mode | ACL |
| --- | --- | --- | --- |
| `/srv/vhosts/<domain>/` and below, dirs | `<pool user>:www-data` | 0750 | `g::r-x` set with setfacl (chmod would only write the mask) |
| Files | `<pool user>:www-data` | 0640 | `g::r--` |
| Docroot, if a deploy user is set | unchanged | unchanged | Deploy user `rwx` on dirs (plus default ACL), `rw-` on files, traverse on the parent |

ACLs are applied per type (`-type d` / `-type f`), because setfacl run through `find` follows symlinks. Files that lose an execute bit under the 0640 rule are listed in the report.

**Configurable pool settings.** Defaults follow `create-apache-vhost.sh`, except that open\_basedir is on. Precedence runs from built-in defaults, to `[fpm.defaults]`, to the site's `[site.fpm]`.

| Setting | Default | Note |
| --- | --- | --- |
| `php_version` | target's default php-fpm | preflight checks it is installed |
| `user` / `group` | `php-<domain, dots as dashes>`, cut to 32 characters with an 8-character hash suffix / same as user | must be unique per site |
| `listen` | `/run/php/php<ver>-fpm-<pool>.sock`, owner `www-data:www-data`, mode 0660 | Apache vhost points at it |
| `pm` | `ondemand` |  |
| `pm.max_children` | 4 |  |
| `pm.process_idle_timeout`, `pm.max_requests` | 10s, 500 |  |
| `open_basedir` | vhost root + `<vhost>/tmp` | a second layer; the pool user is the isolation |
| `upload_tmp_dir`, `session.save_path`, `sys_temp_dir` | `<vhost>/tmp` | keeps uploads and sessions inside open\_basedir |
| `session.gc_probability` | 1 | Debian's session cleanup job only covers its default path |
| `error_log`, `log_errors` | `<log dir>/php-fpm-error.log`, on |  |
| `request_terminate_timeout`, `slowlog` | unset |  |
| `php_value` / `php_flag` | none | proposals from discovery, accepted in review |
| `env`, `clear_env` | php-fpm defaults |  |

**Applying a pool**

1. Render the pool file, then run `php-fpm<ver> -t` before any reload.
2. Rename an existing pool file with a timestamp; never overwrite it.
3. Reload only the affected php-fpm version.

**Existing vhosts on the target.** If the vhost already exists, its pool is found the way deploy v2 does it: the vhost's `proxy:unix:` socket is matched to a pool's `listen =`. The tool does not rewrite that pool unless the site sets `manage_pool = true`.

**Guards and checks**

- Refuse if the target tree holds files owned by another site's pool user. `--adopt` turns this into a warning, as in deploy v2.
- After deploy, check with `setpriv` that the pool user can read the docroot and `www-data` can traverse it.

**TLS.** `provision` installs the site's certificate, key and certbot renewal config from the package (root-owned, keys 0600) and writes the HTTPS vhost. A certificate covering several sites is copied once per target. After DNS points at the target, `cleanup` runs `certbot renew --dry-run` to confirm renewal works there.

## Connections and transfer security

All traffic uses the system's OpenSSH with pinned host keys. The account that receives files has no database rights and no sudo.

&#91;embedded content: privilege split · source, one SSH channel, target\]

Data leaves the source through one SSH channel and reaches the target's sites only through root's apply step.

- **Host keys.** `init` shows each target's fingerprint and asks the admin to compare it with the one read on the target's console. Only then is it written to the tool's own known\_hosts file. There is no trust on first use.
- **SSH config.** `init` generates it with `StrictHostKeyChecking yes`, its own `UserKnownHostsFile`, `ControlMaster auto` and an absolute `ControlPath` such as `~/.ssh/cm-%r@%h:%p` (a relative path failed).
- **Transfer account, key login (preferred).** `authorized_keys` carries `restrict`, `from="<source IP>"` and a forced `rrsync` limited to the drop directory. rrsync then blocks remote commands, so the checksum check moves to `target apply`, which verifies anyway.
- **Transfer account, password login (fallback).** An sshd Match block refuses the account from every address except the source.
- **sshd changes are printed, not applied, by default.** With `--apply`, the tool:
  1. backs up `sshd_config` and writes a marked block;
  2. runs `sshd -t`;
  3. checks the effective settings with `sshd -T -C user=…,host=…,addr=…` for the source address and for one other address.

  The check matters because an `Include` at the top of sshd\_config means the first value obtained wins.
- **Root SSH login** is never needed; the tool works with it disabled.
- **Cleanup** removes the marked block after a backup, locks and expires the transfer account, and renames the drop directory with a timestamp.

## Database handling

The first copy and every re-sync use one path: dump on the source, verify, then back up and replace on the target. It is the path `push-migration-dbs.sh` and `import-migration-dbs.sh` implement.

**Dump (source)**

- Use a read-only account: `SELECT, LOCK TABLES, SHOW VIEW, PROCESS, EVENT, TRIGGER`.
- Pick the mode per database. All InnoDB means `--single-transaction`. Any non-InnoDB table means `--lock-tables`, because MariaDB ignores `--lock-tables` when combined with `--single-transaction` (seen in the general log).
- Always pass `--routines --triggers --events --databases`, so the dump re-creates the database with its own character set.
- The first line of the dump is a header naming domain, database, source and time, and a sha256 file goes with it.

**Import (target, root)**

1. Verify the checksum, and check that the header matches the dump's own `USE` line. System databases are refused.
2. If the database exists and has tables, dump it to the backup directory. If that fails, change nothing.
3. `DROP DATABASE`, then import.
4. Compare the table count with the dump, and warn about DEFINER accounts that do not exist on the target.

**App database user.** The first `target apply` for a site creates the user named in the app config it just received: `'<user>'@'localhost'`, with that password and rights on the site's database only. The password is read at run time and never written to the plan, journal or log.

**Checks that are new in the tool**

- Preflight compares the collations the source uses with `SHOW COLLATION` on the target, so a MySQL 8 to MariaDB move fails before any copy.
- The test matrix confirms, per server version, that database-level grants survive DROP and CREATE. This was verified on MariaDB 10.11 only.

During the import the site has no database, so `cutover` freezes writes on the source first. A database-only sync does not carry uploaded files.

## Safety, state and errors

A failure stops one site, never the run, and every run can be resumed from its journal.

- **Journal.** Each changing step appends one JSON line: site, target, step, plan hash, checksums, result. `--resume` skips steps already done under the same plan hash, and refuses if the plan changed.
- **Per-site isolation.** Each site runs in its own error scope. Exit status is 0 when clean, 2 when review is needed, and 1 when any site failed.
- **Locking.** One lock per target and site, so two runs cannot touch the same site.
- **Atomic files.** Packages and dumps are written as `.part`, then renamed, and checksummed before use.
- **No deletion.** Files replaced on the target are snapshotted first. `sync --mirror` uses rsync `--delete` with `--backup --backup-dir`, so removed files move to a timestamped directory. Databases are dumped before replacement, and config files are renamed with a timestamp.
- **Staging.** umask 077, staging directory 0700, owner check, symlinks refused.
- **Secrets.** Credentials only come from defaults files. They never appear on a command line, in a log or in the journal.
- **Dry run.** Every changing command has `--dry-run`, which prints the exact actions it would take.
- **Logs.** One log per run, mode 0600.

## Implementation

One static Rust binary does the orchestration, parsing, validation and state; system tools do the copying and dumping.

**Build and distribution**

- Static musl builds for `x86_64` and `aarch64`. The same binary serves both the source and the target role, so old source servers need no runtime.
- A Cargo workspace with one crate per concern: `config`, `discover`, `plan`, `journal`, `transport` (ssh, rsync), `db` (dump, import), `target` (provision, apply), `cli`.
- Widely used dependencies only, for example `clap`, `serde`, `toml` and `sha2`. Each new one needs a reason.

**Calling external tools**

- Every external call goes through `std::process::Command` with an argument list, never a shell string.
- stdin is set explicitly, `null` unless data is piped. This removes the ssh-swallows-stdin class of bug.
- Preflight checks every external tool and its version: `ssh`, `rsync`, `mysqldump`/`mariadb-dump`, `mysql`, `apache2ctl`, `php-fpm<ver>`, `setfacl`, `getfacl`, `setpriv`.

**Supply chain**

- `Cargo.lock` committed; `cargo-deny` and `cargo-audit` in CI.
- Reproducible builds, signed release artifacts, and a CycloneDX SBOM per release.
- EUPL-1.2, REUSE-compliant. Distributed as signed release binaries; not published on crates.io, where the name larry is already taken.

## Testing

The current scripts and their test harness define the expected behaviour. Every problem we hit and verified becomes a regression test.

| Verified problem | Regression test |
| --- | --- |
| MariaDB ignores `--lock-tables` alongside `--single-transaction` | A MyISAM database is dumped with `--lock-tables`; the general log confirms the lock |
| setfacl through `find` follows symlinks | A symlink out of the tree leaves its target's ACL unchanged |
| chmod on a file with an ACL writes the mask | `group::` is normalized after deploy |
| ssh in a loop swallows stdin | A run over several sites processes every site |
| CRLF in hand-edited files | Config and site files with CRLF parse the same as LF |
| sshd uses the first value it obtains; Match blocks override | Effective config is checked with `sshd -T -C` for an allowed and a denied address |
| `apache2ctl -S` has IP-based vhosts too | IP-based vhosts are discovered |
| Grants survive DROP and CREATE DATABASE | The app user still reads after an import |
| DEFINER accounts missing on the target | The import warns and names them |
| Tampered or mismatched dumps | Bad checksum, missing header or header/USE mismatch changes nothing |

**Matrix**

- Sources: the Debian and Ubuntu releases still in use, each with its distro MariaDB or MySQL.
- Targets: Ubuntu 24.04 LTS first.
- Containers cover the database and Apache cases. VMs with systemd and sshd cover end-to-end runs.

**End-to-end fixture.** Move a PHP app with a database, a static site, a MyISAM site and a nested-root site. Then check each one on the target with `curl --resolve`, before any DNS change.

## Open questions

Settled on 2 Nov 2026: prior art, TLS, app DB users, open\_basedir, old paths, target-side root steps, cron and mail, license, name. The decisions are in the sections above.

- [x] Log directory: `LOG_DIR` is `<vhost>/logs` in `create-apache-vhost.sh` (confirmed 2026-11-19).
- [x] Pool defaults: match `create-apache-vhost.sh` (pm ondemand, max_children 4, idle 10s, max_requests 500, error_log in logs/); confirmed 2026-11-19.

## Sources

- [HostShift](https://github.com/oguzhankrcb/HostShift), GitHub
- [I built HostShift to migrate Linux servers](https://dev.to/oguzhankrcb/i-built-hostshift-to-migrate-linux-servers-1nje), DEV Community
- [rehost](https://github.com/pietervanleuven/rehost), GitHub
- [larry crate](https://docs.rs/crate/larry/0.3.1/source/), docs.rs
