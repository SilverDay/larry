#!/usr/bin/env python3
"""
build-migration-manifest.py -- build the manifest for create-migration-packages.sh
from the vhost inventory written by scan-vhosts.sh.

Runs on the legacy box, after:   ./scan-vhosts.sh -o legacy-vhosts.jsonl
Read-only. Python 3.8+, standard library only.

For every vhost in the inventory:
  domain  ServerName from the scan
  root    the vhost's DocumentRoot, re-checked live on disk
  db      auto-detected: the site's config files are searched for a database
          name (wp-config.php, .env, Matomo config.ini.php, Joomla
          configuration.php, PDO DSNs, mysqli_connect(), ...), and a name is
          only used if that database exists on this server. Nothing but DB
          names is ever extracted or printed -- never credentials.
  target  larger2 for the domains in LARGER2 below, --default-target
          (silverday) for everything else; --target overrides per domain.

Target layout is flat: every vhost -- including the ones nested under
<domain>/subdomains/ on legacy -- gets its own row and becomes its own
/srv/vhosts/<domain>/ vhost on the new server. When a parent is searched for
its database, nested vhosts and a top-level subdomains/ are skipped, so a
parent never picks up a child's database.

Skipped, and listed in the report: --exclude'd domains, vhosts whose docroot
does not exist, the server's own default vhost, and rows that cannot be
written safely (e.g. a comma in the path). A site whose database cannot be
determined -- several existing DBs referenced, or a name that doesn't exist
here -- is held back rather than written with an empty db; decide with --db
and re-run.

Usage:
  ./build-migration-manifest.py legacy-vhosts.jsonl -o migration-manifest.csv
  ./build-migration-manifest.py legacy-vhosts.jsonl -o m.csv \\
      --exclude-file migration-exclude.txt --db blog.silverday.de=sdblog_db

Options:
  -o FILE                 Manifest to write (default: stdout)
  --report FILE           Review report (default: stderr)
  --exclude DOMAIN        Leave a domain out (repeatable)
  --exclude-file FILE     One domain per line, '#' comments allowed
  --target DOMAIN=ALIAS   Override the target for one domain (repeatable)
  --default-target ALIAS  Target for domains not in LARGER2 (default: silverday)
  --db DOMAIN=NAME        Set the database by hand (repeatable);
                          DOMAIN= (empty) means "this site has no database"
  --db-defaults-file F    Credentials for SHOW DATABASES
                          (default: ./migration-db.cnf, the read-only
                          migration user create-migration-packages.sh uses)
  --no-db-check           Don't query MariaDB; detected names are used
                          unverified and every one is flagged for review
  --max-depth N           How deep to look for config files below the vhost
                          dir (default: 5)

Exit status: 0 = manifest written, nothing to review
             2 = manifest written, but the report has items that need review
             1 = error, nothing written
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
from collections import defaultdict

# Topology as of 2026-11: webapp ("larger2") takes these, websd ("silverday")
# everything else. Aliases must match the Host names in the migration SSH config.
LARGER2 = {"kioju.de", "dagatal.de", "tourl.at", "wizardscastle.de"}
LARGER2_ALIAS = "larger2"
DEFAULT_TARGET = "silverday"

SYSTEM_DBS = {"mysql", "information_schema", "performance_schema", "sys"}

# What create-migration-packages.sh accepts (it splits on commas, no quoting).
DOMAIN_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$")
DB_RE = re.compile(r"^[A-Za-z0-9_-]+$")
ALIAS_RE = re.compile(r"^[A-Za-z0-9._-]+$")

# --- config file discovery ---------------------------------------------------
CONFIG_NAMES = {
    "wp-config.php", ".env", ".env.local", ".env.production", ".env.prod",
    "configuration.php",            # Joomla
    "config.ini.php",               # Matomo (config/config.ini.php)
    "settings.php",                 # Drupal, TYPO3 v12+
    "localconfiguration.php",       # TYPO3 <= 11 (case-insensitive match)
    "env.php",                      # Magento
    "parameters.yml", "parameters.yaml", "database.yml", "database.yaml",
}
CONFIG_PATTERNS = [re.compile(p, re.I) for p in (
    r"^config.*\.(php|inc|ini)$", r".*config\.(php|inc)$", r"^db.*\.(php|inc)$",
    r"^database.*\.(php|inc)$", r"^connect.*\.(php|inc)$", r"^settings.*\.(php|inc)$",
    r".*\.ini\.php$",
)]
SKIP_FILE_RE = re.compile(r"(sample|example|\.dist$|\.bak$|\.orig$|~$)", re.I)
PRUNE_DIRS = {"vendor", "node_modules", ".git", ".svn", ".hg", "cache", "tmp",
              "temp", "logs", "log", "uploads", "backup", "backups"}
MAX_FILE_BYTES = 1_000_000

# --- DB name patterns (each captures the database name only) ----------------
N = r"([A-Za-z0-9_\-]+)"
DB_PATTERNS = [
    # define('DB_NAME', 'x')  -- WordPress and many custom apps
    re.compile(r"""define\s*\(\s*['"](?:DB_NAME|DB_DATABASE|DATABASE_NAME)['"]\s*,\s*['"]""" + N + r"""['"]"""),
    # .env style
    re.compile(r"""^\s*(?:export\s+)?(?:DB_DATABASE|DB_NAME|MYSQL_DATABASE|DATABASE_NAME)\s*=\s*['"]?""" + N, re.M),
    # PDO DSN: mysql:host=...;dbname=x
    re.compile(r"""(?:mysql|mariadb):[^'"\s]*?dbname=""" + N),
    # URL: DATABASE_URL=mysql://user:pass@host:3306/x
    re.compile(r"""(?:mysql|mariadb)://[^/\s'"]+/""" + N),
    # arrays: 'dbname' => 'x', 'database' => 'x', 'db_name' => 'x'
    re.compile(r"""['"](?:dbname|database|db_name|dbName|db_database)['"]\s*=>\s*['"]""" + N + r"""['"]"""),
    # Matomo / ini: dbname = "x"
    re.compile(r"""^\s*(?:dbname|database)\s*=\s*['"]?""" + N, re.M),
    # Joomla: public $db = 'x';
    re.compile(r"""(?:public|var)\s+\$db\s*=\s*['"]""" + N + r"""['"]"""),
    # plain PHP variables: $dbname = 'x'; $db_name = "x";
    re.compile(r"""\$(?:db_?name|database|db_database|dbName)\s*=\s*['"]""" + N + r"""['"]"""),
    # mysqli_connect('host','user','pass','x') / new mysqli(...)
    re.compile(r"""(?:mysqli_connect|new\s+mysqli)\s*\(\s*['"][^'"]*['"]\s*,\s*['"][^'"]*['"]\s*,\s*['"][^'"]*['"]\s*,\s*['"]""" + N + r"""['"]"""),
    # mysqli_select_db($link, 'x') / mysql_select_db('x')
    re.compile(r"""mysqli?_select_db\s*\(\s*(?:\$\w+\s*,\s*)?['"]""" + N + r"""['"]"""),
    # YAML: database_name: x
    re.compile(r"""^\s*database(?:_name)?\s*:\s*['"]?""" + N, re.M),
]
COMMENT_RE = re.compile(r"^\s*(//|#|;|\*|/\*)")


def die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def kv_list(values, flag):
    out = {}
    for v in values or []:
        if "=" not in v:
            die(f"{flag} expects DOMAIN=VALUE, got '{v}'")
        k, val = v.split("=", 1)
        out[k.strip()] = val.strip()
    return out


def load_scan(path):
    recs = []
    fh = sys.stdin if path == "-" else open(path, encoding="utf-8")
    with fh:
        for n, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                recs.append(json.loads(line))
            except json.JSONDecodeError as e:
                die(f"{path}:{n}: not valid JSON ({e}). Expected scan-vhosts.sh JSONL.")
    if not recs:
        die(f"{path}: no records")
    for r in recs:
        if not r.get("domain"):
            die(f"{path}: record without 'domain' -- is this scan-vhosts.sh output?")
    return recs


def server_databases(defaults_file):
    if not os.path.isfile(defaults_file):
        die(f"no DB credentials at {defaults_file} (use --db-defaults-file, or --no-db-check)")
    try:
        out = subprocess.run(
            ["mysql", f"--defaults-extra-file={defaults_file}", "-N", "-B", "-e", "SHOW DATABASES"],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True,
        ).stdout
    except FileNotFoundError:
        die("mysql client not found (or use --no-db-check)")
    except subprocess.CalledProcessError as e:
        die(f"SHOW DATABASES failed: {e.stderr.strip()}")
    return {d for d in out.split() if d not in SYSTEM_DBS}


def is_config_file(name):
    if SKIP_FILE_RE.search(name):
        return False
    low = name.lower()
    return low in CONFIG_NAMES or any(p.match(name) for p in CONFIG_PATTERNS)


def find_db_candidates(search_root, prune_paths, max_depth):
    """{dbname: [ 'relpath:line', ... ]} found below search_root."""
    found = defaultdict(list)
    base_depth = search_root.rstrip("/").count("/")
    for dirpath, dirnames, filenames in os.walk(search_root, followlinks=False):
        depth = dirpath.rstrip("/").count("/") - base_depth
        keep = []
        for d in dirnames:
            full = os.path.join(dirpath, d)
            if d.lower() in PRUNE_DIRS or full in prune_paths or os.path.islink(full):
                continue
            if depth == 0 and d == "subdomains":       # Plesk: other vhosts live here
                continue
            keep.append(d)
        dirnames[:] = keep if depth < max_depth else []
        for f in filenames:
            if not is_config_file(f):
                continue
            full = os.path.join(dirpath, f)
            try:
                # Never follow symlinks: a link in a web tree must not make us
                # read (and report fragments of) files outside it.
                st = os.lstat(full)
                if not os.path.isfile(full) or os.path.islink(full) or st.st_size > MAX_FILE_BYTES:
                    continue
                with open(full, encoding="utf-8", errors="replace") as fh:
                    lines = fh.read().splitlines()
            except OSError:
                continue
            rel = os.path.relpath(full, search_root)
            for i, line in enumerate(lines, 1):
                if COMMENT_RE.match(line):
                    continue
                for pat in DB_PATTERNS:
                    for m in pat.finditer(line):
                        found[m.group(1)].append(f"{rel}:{i}")
    return found


def main():
    ap = argparse.ArgumentParser(add_help=False)
    ap.add_argument("scan")
    ap.add_argument("-o", dest="output")
    ap.add_argument("--report")
    ap.add_argument("--exclude", action="append", default=[])
    ap.add_argument("--exclude-file")
    ap.add_argument("--target", action="append", default=[])
    ap.add_argument("--default-target", default=DEFAULT_TARGET)
    ap.add_argument("--db", action="append", default=[])
    ap.add_argument("--db-defaults-file", default="./migration-db.cnf")
    ap.add_argument("--no-db-check", action="store_true")
    ap.add_argument("--max-depth", type=int, default=5)
    ap.add_argument("-h", "--help", action="store_true")
    if "-h" in sys.argv[1:] or "--help" in sys.argv[1:]:
        print(__doc__.strip())
        return 0
    a = ap.parse_args()

    excludes = {e.strip() for e in a.exclude if e.strip()}
    if a.exclude_file:
        with open(a.exclude_file, encoding="utf-8") as fh:
            for line in fh:
                line = line.split("#", 1)[0].strip()
                if line:
                    excludes.add(line)
    target_over = kv_list(a.target, "--target")
    db_over = kv_list(a.db, "--db")
    for alias in [a.default_target, LARGER2_ALIAS, *target_over.values()]:
        if not ALIAS_RE.match(alias):
            die(f"invalid target alias '{alias}'")
    for dom, name in db_over.items():
        if name and not DB_RE.match(name):
            die(f"--db {dom}={name}: not a plain database name")

    recs = load_scan(a.scan)
    known = {r["domain"] for r in recs}
    for name, flag in [(d, "--target") for d in target_over] + [(d, "--db") for d in db_over]:
        if name not in known:
            die(f"{flag} {name}: not in the scan (typo?)")
    stale_excludes = sorted(excludes - known)

    dbs = None if a.no_db_check else server_databases(a.db_defaults_file)
    own_names = {socket.gethostname(), socket.getfqdn()} | {r.get("scanned_host", "") for r in recs}
    own_names.discard("")

    # Every docroot and vhost dir in the scan, to keep a parent's DB search out
    # of the trees of vhosts nested inside it.
    all_roots = []
    for r in recs:
        for d in (r.get("docroots") or [r.get("docroot")]):
            if d:
                d = os.path.normpath(d)
                all_roots.append((r["domain"], d, os.path.dirname(d)))

    rows, skipped, attention, notes = [], [], [], defaultdict(list)

    for r in sorted(recs, key=lambda x: x["domain"]):
        dom = r["domain"]
        confs = [os.path.basename(c) for c in r.get("conf_files") or []]
        if dom in excludes:
            skipped.append((dom, "excluded")); continue
        if dom in own_names or (confs and all(c in ("000-default.conf", "default-ssl.conf") for c in confs)):
            skipped.append((dom, "the server's own default vhost")); continue
        if not DOMAIN_RE.match(dom):
            skipped.append((dom, "domain name not usable in the manifest")); attention.append((dom, "unusable domain name")); continue

        # docroot: re-checked live. If :80 and :443 disagree, take the one
        # that exists only when exactly one does.
        cands = [os.path.normpath(d) for d in (r.get("docroots") or [r.get("docroot")]) if d]
        cands = list(dict.fromkeys(cands))
        existing = [d for d in cands if os.path.isdir(d)]
        if not cands:
            skipped.append((dom, "no DocumentRoot in the scan")); continue
        if not existing:
            skipped.append((dom, f"docroot does not exist: {' | '.join(cands)}")); continue
        if len(existing) > 1:
            skipped.append((dom, f"vhost files disagree on DocumentRoot: {' | '.join(existing)}"))
            attention.append((dom, "conflicting DocumentRoots - fix the vhost config, then re-scan")); continue
        root = existing[0]
        if len(cands) > 1:
            notes[dom].append(f"DocumentRoot differs between its vhost files; using the one that exists ({root}), ignoring {', '.join(c for c in cands if c != root)}")
        if any(ch in root for ch in ",\n\r\"'"):
            skipped.append((dom, f"docroot contains a character the manifest cannot carry: {root!r}"))
            attention.append((dom, "docroot path unusable in the CSV")); continue

        # nested on legacy -> flat on the new server
        search_root = os.path.dirname(root)
        if "/subdomains/" in root:
            notes[dom].append("nested under a parent's subdomains/ on legacy - becomes its own flat vhost on the new server")

        # database. A row whose database cannot be determined is held back,
        # not written with an empty db: that would silently mean "no database".
        db, db_note, unresolved = "", "", False
        if dom in db_over:
            db = db_over[dom]
            db_note = "set by --db" if db else "no database (--db)"
            if db and dbs is not None and db not in dbs:
                attention.append((dom, f"--db {db}: no such database on this server")); unresolved = True
        else:
            prune = set()
            for other, d, vdir in all_roots:
                if other == dom:
                    continue
                if vdir.startswith(search_root + "/"):
                    prune.add(vdir)
                elif d.startswith(search_root + "/") and d != root:
                    prune.add(d)
            found = find_db_candidates(search_root, prune, a.max_depth)
            if dbs is None:
                if len(found) == 1:
                    db = next(iter(found))
                    db_note = f"UNVERIFIED (--no-db-check) from {found[db][0]}"
                    attention.append((dom, f"db '{db}' not checked against the server"))
                elif found:
                    attention.append((dom, "several DB names found: " + "; ".join(f"{k} ({v[0]})" for k, v in sorted(found.items()))
                                      + f"  -> pass --db {dom}=NAME")); unresolved = True
                else:
                    db_note = "no DB reference found (static site?)"
            else:
                verified = {k: v for k, v in found.items() if k in dbs}
                if len(verified) == 1:
                    db = next(iter(verified))
                    db_note = f"from {verified[db][0]}"
                elif len(verified) > 1:
                    attention.append((dom, "ambiguous - several existing databases referenced: "
                                      + "; ".join(f"{k} ({v[0]})" for k, v in sorted(verified.items()))
                                      + f"  -> pass --db {dom}=NAME")); unresolved = True
                elif found:
                    attention.append((dom, "DB name(s) found but no such database here: "
                                      + "; ".join(f"{k} ({v[0]})" for k, v in sorted(found.items()))
                                      + f"  -> remote DB? stale config? pass --db {dom}=NAME, or --db {dom}= if it has none"))
                    unresolved = True
                else:
                    db_note = "no DB reference found (static site?)"
            if db and not DB_RE.match(db):
                attention.append((dom, f"database '{db}' has characters the manifest cannot carry")); unresolved = True
        if unresolved:
            skipped.append((dom, "held back: database unresolved (see NEEDS REVIEW)")); continue

        # target
        if dom in target_over:
            target, t_note = target_over[dom], "set by --target"
        elif dom in LARGER2:
            target, t_note = LARGER2_ALIAS, ""
        else:
            target, t_note = a.default_target, ""
            parent = next((p for p in LARGER2 if dom.endswith("." + p)), None)
            if parent:
                notes[dom].append(f"subdomain of {parent} (a {LARGER2_ALIAS} domain) but assigned to {target} - override with --target if wrong")

        if r.get("htaccess_php_files"):
            notes[dom].append(f"{len(r['htaccess_php_files'])} .htaccess file(s) with mod_php directives - run classify-htaccess.py before go-live")
        rows.append({"domain": dom, "root": root, "db": db, "target": target,
                     "db_note": db_note, "t_note": t_note})

    # cross-row checks
    by_root, by_db = defaultdict(list), defaultdict(list)
    for row in rows:
        by_root[row["root"]].append(row["domain"])
        if row["db"]:
            by_db[row["db"]].append(row["domain"])
    for root, doms in by_root.items():
        if len(doms) > 1:
            attention.append((", ".join(doms), f"share one docroot {root} - each would become its own copy; one vhost with ServerAlias is probably what you want"))
    for db, doms in by_db.items():
        if len(doms) > 1:
            for d in doms:
                notes[d].append(f"database {db} is shared with {', '.join(x for x in doms if x != d)} - dumped and imported once per row")
    unassigned = sorted(dbs - set(by_db)) if dbs is not None else []

    # --- write manifest (only now, so an error above leaves nothing behind) ---
    lines = ["domain,root,db,target_server"] + [f"{r['domain']},{r['root']},{r['db']},{r['target']}" for r in rows]
    data = "\n".join(lines) + "\n"
    if a.output:
        tmp = a.output + ".tmp"
        old = os.umask(0o077)
        try:
            with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(data)
            os.replace(tmp, a.output)
        finally:
            os.umask(old)
    else:
        sys.stdout.write(data)

    # --- report ---------------------------------------------------------------
    out = open(a.report, "w", encoding="utf-8") if a.report else sys.stderr
    per_target = defaultdict(int)
    for r in rows:
        per_target[r["target"]] += 1
    w = lambda s="": print(s, file=out)
    w(f"Manifest: {len(rows)} rows ({', '.join(f'{t} {n}' for t, n in sorted(per_target.items()))})"
      f" -> {a.output or 'stdout'}   [scan: {len(recs)} vhosts]")
    if stale_excludes:
        w(); w(f"NOTE: excluded but not in the scan: {', '.join(stale_excludes)}")
    if attention:
        w(); w(f"NEEDS REVIEW ({len(attention)})")
        for d, msg in attention:
            w(f"  {d}: {msg}")
    if skipped:
        w(); w(f"SKIPPED ({len(skipped)})")
        width = max(len(d) for d, _ in skipped)
        for d, why in skipped:
            w(f"  {d:<{width}}  {why}")
    if rows:
        w(); w("INCLUDED")
        width = max(len(r["domain"]) for r in rows)
        for r in rows:
            w(f"  {r['domain']:<{width}}  -> {r['target']:<10} db: {r['db'] or '-':<18} {r['db_note']}")
            for n in ([r["t_note"]] if r["t_note"] else []) + notes.get(r["domain"], []):
                w(f"  {'':<{width}}     note: {n}")
    if unassigned:
        w(); w(f"DATABASES ON THIS SERVER NOT IN THE MANIFEST ({len(unassigned)}) - check none is missing a row")
        w("  " + ", ".join(unassigned))
    if a.report:
        out.close()
    return 2 if attention else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(1)
