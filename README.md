# larry

**Move Apache/PHP/MariaDB sites from one Debian or Ubuntu server to another, one site at a time, without a control panel.**

`larry` replaces a chain of shell scripts (scan, manifest, package, deploy, database re-sync) with one tool.
It reads what runs on the old server, writes a plan you can review and edit, copies files and databases
over SSH, and sets each site up on the new server in a fixed, hardened layout: one directory, one PHP-FPM
pool and one system user per site.

It is written in Rust and ships as a single static binary. The system's own `ssh`, `rsync`, `mysqldump` and
`mysql` do the transport; `larry` orchestrates them and never goes through a shell.

> **Status: v0.1.0, first release.** Every command is implemented and tested against real MariaDB, sshd,
> rrsync and Apache. The steps that need real root on a target (creating users, chown to the pool user,
> service reloads) were so far exercised only through dry-run plans and `fakeroot`. Try one throwaway site
> first, with `--dry-run` before every changing command. See [Limits](#limits).

## What it does

- **Discovers** vhosts (name-based and IP-based), docroots, nested sites, the database each site uses,
  `php_value` settings that break under PHP-FPM, old absolute paths, cron entries, non-InnoDB tables,
  DEFINER accounts and how each site sends mail. It reports; it never guesses.
- **Plans** in `sites.toml`, a plain file you can edit. A hand-edited plan is never overwritten.
- **Checks** before anything is copied: tools, secrets, pinned host keys, reachability, database
  collations (so a MySQL 8 to MariaDB move fails early), and name or ownership conflicts on the target.
- **Provisions** each site: pool user, PHP-FPM pool, Apache vhost, directories, Let's Encrypt certificate
  and renewal config. An existing vhost is adopted instead of rewritten.
- **Syncs** files and databases repeatedly until cutover. The first run is full, later runs carry changes.
- **Applies** on the target: snapshot, copy, optional rewrite of old paths in PHP files, ownership and ACLs,
  access checks, a verified database import, and the application's own database user.
- **Cuts over** with an opt-in 503 maintenance page on the source, a final sync, and `curl --resolve`
  checks against the target. Changing DNS stays your step.
- **Cleans up**: removes the temporary sshd block, locks the transfer account, archives the drop directory.

## Safety model

- **Plan, then apply.** Every changing command has `--dry-run`, which prints exactly what it would do.
- **Nothing is deleted.** Replaced files are snapshotted first; `sync --mirror` moves removed files into a
  timestamped backup directory; databases are dumped before they are replaced; config files are renamed
  with a timestamp, never overwritten.
- **Pinned host keys.** You type the fingerprint shown on the target's console. There is no trust on first use.
- **A write-only transfer account.** Data goes into a drop directory through an SSH key restricted to the
  source IP and a forced `rrsync -wo`: no shell, no remote commands, no reading back, no path escapes.
  Only a root-run `target apply` moves data into the sites, and it treats everything in the drop
  directory as untrusted input.
- **No secrets on command lines, in logs or in the journal.** Credentials live in MySQL defaults files with
  mode 0600.
- **A failure stops one site, not the run.** Exit codes: `0` clean, `2` review needed, `1` error. Runs are
  journaled and can be resumed.

## Install

Download the tarball for your CPU from the [releases page](https://github.com/SilverDay/larry/releases),
check it, and copy `larry` to `/usr/local/bin` on the source and on each target.

```sh
sha256sum -c SHA256SUMS --ignore-missing
# optional: verify the signature (keyless, made by this repository's release workflow)
cosign verify-blob --bundle SHA256SUMS.sigstore.json \
  --certificate-identity-regexp '^https://github.com/SilverDay/larry/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com SHA256SUMS
tar xzf larry-v0.1.0-x86_64-unknown-linux-musl.tar.gz
install -m 0755 larry-v0.1.0-x86_64-unknown-linux-musl/larry /usr/local/bin/larry
```

The binary is static; it needs no Rust or libraries. Releases carry a CycloneDX SBOM.
To build from source: `cargo build --release --locked` (Rust 1.85 or newer).

### Requirements

| Where | Needs |
| --- | --- |
| Source | `ssh`, `rsync`, `mysql` and `mysqldump` or `mariadb-dump`, `apache2ctl`; a read-only database account |
| Target | `rsync` and `rrsync` (package `rsync`), `sshd`, `setfacl` and `getfacl` (package `acl`), `setpriv` (util-linux), Apache, `php-fpm<version>`, MariaDB or MySQL, `certbot` for renewal checks |
| Both | Debian or Ubuntu; `larry preflight` and `larry target preflight` report anything missing |

## Quick start

The full walkthrough, with every file and flag, is in **[docs/guide.md](docs/guide.md)**. In short:

```sh
# on the source
larry init                 # wizard: targets, host-key pinning, migration.toml, SSH config
larry discover             # read-only; writes inventory.jsonl and prints a report
larry plan                 # writes sites.toml (or: larry plan --interactive)
larry preflight            # checks, and hands the plan's facts to each target

# on each target, as root (the commands init printed)
larry target sshd --target web1 --source-ip <source IP> --apply   # only for password login
larry target preflight --db-defaults-file /root/larry-db.cnf

# back on the source
larry sync --dry-run && larry sync     # files, certificates, databases into the drop directory

# on the target, as root
larry provision --dry-run && larry provision
larry target apply --dry-run && larry target apply

# repeat sync and target apply as often as needed, then
larry cutover --freeze-source          # source: 503 page, final sync
larry target apply                     # target: bring the last changes in
larry cutover --check-only             # source: curl --resolve against the target
# change DNS yourself, then on the target:
larry cleanup --target web1
```

## Commands

| Command | Runs on | Changes |
| --- | --- | --- |
| `init` | source | Writes `migration.toml`, the SSH config and `known_hosts` |
| `discover` | source | Writes `inventory.jsonl`; reads only |
| `plan [--interactive] [--db DOMAIN=NAME]` | source | Writes `sites.toml` |
| `preflight` | source | Pushes `preflight.json` into each target's drop directory |
| `target preflight` | target | Nothing; reports |
| `target sshd [--apply]` | target, root | Prints, or with `--apply` installs after a backup and a check, the sshd block |
| `sync [--files] [--db] [--mirror] [--resume] [--dry-run]` | source | Drop directory on the target |
| `provision [DOMAIN…] [--dry-run]` | target, root | Users, pools, vhosts, directories, certificates |
| `target apply [DOMAIN…] [--adopt] [--mirror] [--dry-run]` | target, root | The sites and their databases |
| `cutover [--freeze-source] [--unfreeze] [--check-only]` | source | Optional 503 page on the source; final sync |
| `cleanup --target NAME` | target, root | sshd block, transfer account, drop directory |
| `config check` | any | Nothing; validates `migration.toml` and secret-file modes |

Run `larry <command> --help` for every flag.

## Limits

- **v1 scope:** Apache, PHP-FPM and MariaDB or MySQL on Debian or Ubuntu, one flat layout
  (`/srv/vhosts/<domain>/`). Cron jobs, mail servers and other services are reported, not moved.
- **Database path rewriting is report-only.** Old absolute paths found in a dump are listed; only PHP files
  can be rewritten, and PHP serialized strings are skipped and reported.
- **App database users** are created from WordPress `wp-config.php`, `.env` files (Laravel and similar) and
  Joomla `configuration.php`. For other applications `larry` warns and you create the user by hand.
- **Not yet run for real:** the root-only steps on a real target (see the status note above). The container
  test matrix in `tests/containers/` is written for that and has not been run yet.
- **Writes on the source** are frozen only for HTTP, and only with `--freeze-source`. Cron jobs and mail
  keep running.

## Development

```sh
cargo test --workspace           # unit tests and integration tests (they skip what is not installed)
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
tests/containers/run.sh          # the whole migration as real root in containers (podman or docker)
```

The integration tests start private servers of their own as the current user: a MariaDB with a socket only,
an sshd with `rrsync`, an Apache, and run `target apply` under `fakeroot`. They never touch other services
on the machine.

The workspace has one crate per concern: `config`, `discover`, `plan`, `journal`, `transport` (ssh, rsync),
`db` (dump, import), `target` (provision, apply) and `cli`. The design and every decision are in
[docs/spec.md](docs/spec.md). The scripts `larry` replaces are kept in [reference/](reference/) as the
behavioural reference.

CI runs fmt, clippy, the tests, `cargo deny` (advisories, licences, sources) and REUSE on every push. Tags
`v*` build static musl binaries for x86_64 and aarch64, a CycloneDX SBOM and signed checksums.

## License

[EUPL-1.2](LICENSE). Licence texts are in `LICENSES/`, and the repository is [REUSE](https://reuse.software)-compliant.
