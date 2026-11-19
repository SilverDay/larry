#!/usr/bin/env bash
#
# create-migration-packages.sh  --  v2 (2026-11-01)
#
# Changes since the July version (all tested against a real SSH target; each
# bug was reproduced on the old version before it was fixed):
#   - Every manifest row is processed. v1 read the manifest on stdin and the
#     first `ssh` swallowed the rest of it, so only the first row with a
#     target_server was handled and the run still reported success.
#   - --resume works (v1 matched "^DONE:" against timestamp-prefixed lines).
#   - umask 077 and a 0700 staging dir: DB dumps were 0644 in /tmp.
#   - Each row runs with errexit genuinely on; a failed archive, manifest or
#     checksum step aborts that row instead of shipping a truncated package.
#     The package is written as .part and renamed only when complete.
#   - .sha256 records the bare file name (was the absolute staging path).
#   - Remote verification uses sha256sum's exit status, not an "OK" substring.
#   - DBs with non-transactional (MyISAM/Aria/...) tables are dumped with
#     --lock-tables; MariaDB silently drops --lock-tables when combined with
#     --single-transaction, which InnoDB-only DBs still use.
#   - Exit status is non-zero if any row failed.
#   - CRLF manifests (spreadsheet exports) work: the trailing \r used to end
#     up in the last field, so ssh got "larger2\r" (or a db name was skipped).
#
# Reads a manifest CSV (domain,root,db,target_server) and, for each row:
#   1. Archives the vhost directory ONE LEVEL ABOVE the given webroot
#      (e.g. root=/srv/vhosts/foo.com/public -> archives /srv/vhosts/foo.com/*)
#      so that anything living alongside the webroot (Laravel's storage/,
#      .env, vendor/, etc.) comes along, not just the doc root itself.
#   2. Dumps the database, if one is listed, using a read-only migration
#      user via a mysqldump defaults file (keeps the password out of the
#      process list and shell history).
#   3. Packages both into a single per-domain archive with a manifest.json
#      recording the source webroot's folder name (needed on the target
#      side, since old servers used inconsistent names like httpdocs/public).
#   4. Transfers the package to the domain's target_server over rsync,
#      using an SSH config Host alias, and verifies the remote checksum.
#
# Usage:
#   ./create-migration-packages.sh manifest.csv [options]
#
# Options:
#   --dry-run              Show what would happen, do not archive/dump/transfer
#   --only domain1,domain2 Restrict to specific domains from the manifest
#   --staging-dir DIR      Local working directory (default: /tmp/migration-packages)
#   --remote-dir DIR       Destination directory on target servers
#                          (default: /srv/migration-incoming)
#   --db-defaults-file F   mysqldump --defaults-extra-file to use
#                          (default: ./migration-db.cnf)
#   --ssh-config FILE      Use a specific SSH config file for ssh/rsync
#                          calls (e.g. the one written by
#                          setup-migration-auth.sh) instead of the
#                          system default ~/.ssh/config
#   --skip-transfer        Build packages locally but don't rsync them anywhere
#   --resume               Skip domains already marked done in the log
#
# Manifest CSV format (header row required):
#   domain,root,db,target_server
#   advent.silverday.de,/srv/vhosts/advent.silverday.de/public,adventdb,larger1
#   dagatal.de,/srv/vhosts/dagatal.de/public,,larger2
#
# Rows are skipped (with a warning, not an error) when:
#   - root is blank, "Default", "not deployed", "no vhost", or doesn't exist
#     on disk -> nothing to package for this domain right now
#   - db is blank or not a bare [A-Za-z0-9_-]+ name -> no db dump attempted
#   - target_server is blank -> package is built locally but not transferred
#
set -euo pipefail
umask 077    # packages and dumps contain DB contents and app secrets

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGING_DIR="/tmp/migration-packages"
REMOTE_DIR="/srv/migration-incoming"
DB_DEFAULTS_FILE="${SCRIPT_DIR}/migration-db.cnf"
SSH_CONFIG=""
DRY_RUN=0
SKIP_TRANSFER=0
RESUME=0
ONLY_DOMAINS=""
LOG_FILE="${SCRIPT_DIR}/migration-package.log"

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit 1; }

MANIFEST="${1:-}"
[[ -z "$MANIFEST" || "$MANIFEST" == "-h" || "$MANIFEST" == "--help" ]] && usage
shift || true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1; shift ;;
    --only) ONLY_DOMAINS="$2"; shift 2 ;;
    --staging-dir) STAGING_DIR="$2"; shift 2 ;;
    --remote-dir) REMOTE_DIR="$2"; shift 2 ;;
    --db-defaults-file) DB_DEFAULTS_FILE="$2"; shift 2 ;;
    --ssh-config) SSH_CONFIG="$2"; shift 2 ;;
    --skip-transfer) SKIP_TRANSFER=1; shift ;;
    --resume) RESUME=1; shift ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
done

[[ -f "$MANIFEST" ]] || { echo "Manifest not found: $MANIFEST" >&2; exit 1; }

# The staging dir usually lives in /tmp: refuse one we did not create.
STAGING_DIR="${STAGING_DIR%/}"
if [[ -L "$STAGING_DIR" ]]; then
  echo "Staging dir $STAGING_DIR is a symlink - refusing." >&2; exit 1
fi
mkdir -p "$STAGING_DIR"
if [[ "$(stat -c %u "$STAGING_DIR")" != "$EUID" ]]; then
  echo "Staging dir $STAGING_DIR is not owned by you - refusing." >&2; exit 1
fi
chmod 0700 "$STAGING_DIR"
touch "$LOG_FILE"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }

SSH_CMD=(ssh)
RSYNC_SSH_OPT="ssh"
if [[ -n "$SSH_CONFIG" ]]; then
  [[ -f "$SSH_CONFIG" ]] || { echo "SSH config not found: $SSH_CONFIG" >&2; exit 1; }
  SSH_CMD=(ssh -F "$SSH_CONFIG")
  RSYNC_SSH_OPT="ssh -F $SSH_CONFIG"
fi

should_process() {
  local domain="$1"
  if [[ -n "$ONLY_DOMAINS" ]]; then
    [[ ",${ONLY_DOMAINS}," == *",${domain},"* ]] || return 1
  fi
  # log() prefixes a timestamp, so match "] DONE:<domain>:" literally.
  if [[ "$RESUME" == "1" ]] && grep -qF "] DONE:${domain}:" "$LOG_FILE" 2>/dev/null; then
    return 1
  fi
  return 0
}

is_real_root() {
  local root="$1"
  case "$root" in
    ""|"Default"|"default"|"not deployed"|"no vhost"|"stale entry"|"redirect only") return 1 ;;
  esac
  [[ -d "$root" ]]
}

is_real_db() {
  local db="$1"
  [[ "$db" =~ ^[A-Za-z0-9_-]+$ ]]
}

process_row() {
  local domain="$1" root="$2" db="$3" target="$4"

  should_process "$domain" || { log "SKIP (filtered or already done): $domain"; return 0; }

  if ! is_real_root "$root"; then
    log "SKIP (no real webroot on disk): $domain (root='$root')"
    return 0
  fi

  local vhost_dir webroot_basename parent_dir pkg_dir
  webroot_basename="$(basename "$root")"
  vhost_dir="$(dirname "$root")"
  parent_dir="$(dirname "$vhost_dir")"
  pkg_dir="${STAGING_DIR}/${domain}"

  log "START: $domain (vhost_dir=$vhost_dir, webroot=$webroot_basename, db=${db:-none}, target=${target:-none})"

  if [[ "$DRY_RUN" == "1" ]]; then
    log "DRY-RUN: would archive $vhost_dir, dump db '${db:-<none>}', transfer to '${target:-<none>}'"
    return 0
  fi

  rm -rf "$pkg_dir"
  mkdir -p "$pkg_dir"

  # 1. Archive the vhost directory (one level above webroot)
  if ! tar czf "${pkg_dir}/files.tar.gz" -C "$parent_dir" "$(basename "$vhost_dir")"; then
    log "FAIL: $domain - tar archive failed"
    return 1
  fi

  # 2. Dump the database, if any
  local db_dumped=0
  if is_real_db "$db"; then
    if [[ ! -f "$DB_DEFAULTS_FILE" ]]; then
      log "FAIL: $domain - db='$db' listed but no defaults file at $DB_DEFAULTS_FILE"
      return 1
    fi
    # --single-transaction gives a consistent snapshot of InnoDB only, and
    # MariaDB silently ignores --lock-tables when both are given. So: lock
    # the tables of any DB holding non-transactional tables (blocks writes to
    # that DB while it dumps), snapshot the rest.
    local nontx consistency=(--single-transaction)
    nontx="$(mysql --defaults-extra-file="$DB_DEFAULTS_FILE" -N -B -e \
      "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='${db}' AND TABLE_TYPE='BASE TABLE' AND ENGINE NOT IN ('InnoDB')")"
    if [[ "$nontx" -gt 0 ]]; then
      consistency=(--lock-tables)
      log "  $domain - $nontx non-InnoDB table(s) in '$db': dumping with --lock-tables"
    fi
    if mysqldump --defaults-extra-file="$DB_DEFAULTS_FILE" \
        "${consistency[@]}" --routines --triggers --events \
        --databases "$db" 2>>"$LOG_FILE" | gzip > "${pkg_dir}/db.sql.gz"; then
      db_dumped=1
    else
      log "FAIL: $domain - mysqldump failed for db '$db'"
      return 1
    fi
  elif [[ -n "$db" ]]; then
    log "WARN: $domain - db field '$db' doesn't look like a plain db name, skipping dump"
  fi

  # 3. Write package manifest
  cat > "${pkg_dir}/manifest.json" <<JSON
{
  "domain": "$domain",
  "source_webroot_basename": "$webroot_basename",
  "db": "$([[ "$db_dumped" == "1" ]] && echo "$db" || echo "")",
  "packaged_at": "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
}
JSON

  # 4. Combine into single archive + checksum. Written as .part and renamed
  #    only once complete, so a failure (e.g. /tmp full) never leaves a
  #    truncated package under the real name.
  local final_pkg="${STAGING_DIR}/${domain}.pkg.tar.gz"
  rm -f "$final_pkg" "${final_pkg}.sha256"
  tar czf "${final_pkg}.part" -C "$STAGING_DIR" "$domain"
  mv "${final_pkg}.part" "$final_pkg"
  # Record the bare file name, not the staging path: the remote check below
  # and deploy-migration-package.sh both verify from a different directory.
  (cd "$STAGING_DIR" && sha256sum "$(basename "$final_pkg")") > "${final_pkg}.sha256"
  log "PACKAGED: $domain -> $final_pkg ($(du -h "$final_pkg" | cut -f1))"

  # 5. Transfer
  if [[ "$SKIP_TRANSFER" == "1" ]]; then
    log "SKIP-TRANSFER: $domain (package left at $final_pkg)"
    return 0
  fi
  if [[ -z "$target" ]]; then
    log "NO-TARGET: $domain - package built but no target_server given, not transferred"
    return 0
  fi

  if ! "${SSH_CMD[@]}" "$target" "mkdir -p '$REMOTE_DIR'"; then
    log "FAIL: $domain - could not create $REMOTE_DIR on $target (check SSH config alias)"
    return 1
  fi
  if ! rsync -avz --progress -e "$RSYNC_SSH_OPT" "$final_pkg" "${final_pkg}.sha256" "${target}:${REMOTE_DIR}/" >>"$LOG_FILE" 2>&1; then
    log "FAIL: $domain - rsync transfer to $target failed"
    return 1
  fi

  local remote_check
  if ! remote_check="$("${SSH_CMD[@]}" "$target" "cd '$REMOTE_DIR' && sha256sum -c '$(basename "$final_pkg").sha256'" 2>&1)"; then
    log "FAIL: $domain - remote checksum verification failed on $target: $remote_check"
    return 1
  fi

  log "DONE:${domain}: transferred and verified on $target"
}

# --- main loop ---
# The manifest is read on fd 3, not stdin: ssh reads stdin, and in v1 the
# first ssh call swallowed every remaining row.
# Each row runs in a subshell with errexit really active; `process_row || x`
# would silently disable it for everything inside the function.
OK=0; FAILED=()
{
  read -r header <&3
  header="${header%$'\r'}"
  [[ "$header" == "domain,root,db,target_server" ]] || log "WARN: unexpected header '$header' - continuing anyway"
  while IFS=',' read -r domain root db target <&3 || [[ -n "$domain" ]]; do
    # CRLF from a spreadsheet export: \r would stick to whichever field is last
    domain="${domain%$'\r'}"; root="${root%$'\r'}"; db="${db%$'\r'}"; target="${target%$'\r'}"
    [[ -z "$domain" ]] && continue
    set +e
    (
      set -Eeuo pipefail
      trap '(( BASH_SUBSHELL > 1 )) || [[ $BASH_COMMAND == process_row* || $BASH_COMMAND == return* ]] || log "FAIL: ${domain} - \"${BASH_COMMAND}\" failed (line ${LINENO})"' ERR
      process_row "$domain" "$root" "$db" "$target"
    ) 3<&-
    rc=$?
    set -e
    if (( rc == 0 )); then OK=$((OK + 1)); else FAILED+=("$domain"); log "ERROR: $domain - see above"; fi
  done
} 3< "$MANIFEST"

log "All rows processed: $OK ok, ${#FAILED[@]} failed. See $LOG_FILE for full detail."
for d in "${FAILED[@]}"; do log "  failed: $d"; done
(( ${#FAILED[@]} == 0 ))
