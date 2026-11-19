# larry

LAMP site migration tool (Rust). Spec: [docs/spec.md](docs/spec.md). License: EUPL-1.2.
The scripts it replaces are kept in [reference/](reference/) as the behavioural reference.

## Status

| Command | State |
| --- | --- |
| `config check` | done |
| `init` | done (wizard, host-key pinning, ssh config, sshd/authorized_keys snippets) |
| `discover` | done (mail setup, non-InnoDB tables and DEFINER findings still to add) |
| `plan` | done (`--interactive` not yet; use `--db DOMAIN=NAME`) |
| `preflight` / `target preflight` | partly: tools, secret files, pinned keys, DB access, reachability, PHP-FPM versions, free space. Collation and name/ownership conflict checks to come |
| `target sshd` | done (print, or `--apply` with backup, `sshd -t` and effective-config check) |
| `sync` | done (files, certificates, manifest, database dump; `--mirror`, `--resume`, `--dry-run`) |
| `provision` | done (pool user and file, vhost, directories, certificates, adoption of existing vhosts; needs root, `--dry-run` without) |
| `target apply` | done (snapshot, copy, PHP path rewriting, ownership and ACLs, access checks, verified database import, app DB user for WordPress, `.env` and Joomla configs) |
| `cutover` | done (opt-in 503 freeze, final sync, `curl --resolve` checks) |
| `cleanup` | done (sshd block, transfer user, drop directory, `certbot renew --dry-run`) |

Order on a real move: `sync` on the source, then `provision` and `target apply` on the target, repeat `sync` and `target apply` until cutover, then `cutover --freeze-source`, `target apply`, `cutover --check-only`, change DNS, `cleanup`.

Library pieces already in place for the rest: dump/verify/import and the app DB user (`db`),
ssh/rsync builders and streaming (`transport`), journal and plan hash (`journal`).

## Tests

`cargo test --workspace`. Two integration tests start throwaway servers of their own
(a private MariaDB with a socket only, a private sshd on localhost) and skip themselves when the
software is not installed. They never touch other servers on the machine.
