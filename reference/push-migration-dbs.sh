#!/usr/bin/env bash
#
# push-migration-dbs.sh  --  v1 (2026-11-01)
#
# Runs on the legacy box. Dumps ONLY the databases of the selected manifest
# rows and pushes them to each row's target_server -- for re-syncing dynamic
# sites whose files were already migrated. Uses the same manifest, SSH config
# and DB credentials as create-migration-packages.sh.
#
# Per row that has a db:
#   1. Dump it: --lock-tables if the DB has non-InnoDB (MyISAM/Aria) tables,
#      otherwise --single-transaction; always with routines, triggers and
#      events. Written as <domain>.db.sql.gz, whose first line names the
#      domain and database for the import side.
#   2. Checksum (bare file name), rsync to <target>:<remote-dir>, verify there.
#
# Importing is a separate step ON THE TARGET, as root -- the migrate user has
# no database rights, on purpose:
#   ./import-migration-dbs.sh /srv/migration-incoming/<domain>.db.sql.gz
#
# Usage:
#   ./push-migration-dbs.sh manifest.csv --only dom1,dom2 --ssh-config FILE
#
# Options:
#   --only d1,d2           Only these domains (default: every row with a db)
#   --ssh-config FILE      SSH config for ssh/rsync (the migration one)
#   --db-defaults-file F   Read-only DB credentials (default: ./migration-db.cnf
#                          next to this script)
#   --staging-dir DIR      Local working dir (default: /tmp/migration-dbs)
#   --remote-dir DIR       Destination on the targets (default: /srv/migration-incoming)
#   --dry-run              Show what would happen, dump and send nothing
#
# Exit status is non-zero if any row failed.
#
set -euo pipefail
umask 077    # dumps contain everything in the databases

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STAGING_DIR="/tmp/migration-dbs"
REMOTE_DIR="/srv/migration-incoming"
DB_DEFAULTS_FILE="${SCRIPT_DIR}/migration-db.cnf"
SSH_CONFIG=""
ONLY_DOMAINS=""
DRY_RUN=0
LOG_FILE="${SCRIPT_DIR}/migration-dbs.log"

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit 1; }

MANIFEST="${1:-}"
[[ -z "$MANIFEST" || "$MANIFEST" == -* ]] && usage
shift
while [[ $# -gt 0 ]]; do
  case "$1" in
    --only)             ONLY_DOMAINS="${2:?}"; shift 2 ;;
    --ssh-config)       SSH_CONFIG="${2:?}"; shift 2 ;;
    --db-defaults-file) DB_DEFAULTS_FILE="${2:?}"; shift 2 ;;
    --staging-dir)      STAGING_DIR="${2:?}"; shift 2 ;;
    --remote-dir)       REMOTE_DIR="${2:?}"; shift 2 ;;
    --dry-run)          DRY_RUN=1; shift ;;
    -h|--help)          usage ;;
    *) echo "Unknown option: $1" >&2; usage ;;
  esac
done

[[ -f "$MANIFEST" ]] || { echo "Manifest not found: $MANIFEST" >&2; exit 1; }
[[ -f "$DB_DEFAULTS_FILE" ]] || { echo "No DB credentials at $DB_DEFAULTS_FILE" >&2; exit 1; }

SSH_CMD=(ssh); RSYNC_SSH_OPT="ssh"
if [[ -n "$SSH_CONFIG" ]]; then
  [[ -f "$SSH_CONFIG" ]] || { echo "SSH config not found: $SSH_CONFIG" >&2; exit 1; }
  SSH_CMD=(ssh -F "$SSH_CONFIG"); RSYNC_SSH_OPT="ssh -F $SSH_CONFIG"
fi

# The staging dir usually lives in /tmp: refuse one we did not create.
STAGING_DIR="${STAGING_DIR%/}"
if [[ -L "$STAGING_DIR" ]]; then echo "Staging dir $STAGING_DIR is a symlink - refusing." >&2; exit 1; fi
mkdir -p "$STAGING_DIR"
if [[ "$(stat -c %u "$STAGING_DIR")" != "$EUID" ]]; then echo "Staging dir $STAGING_DIR is not owned by you - refusing." >&2; exit 1; fi
chmod 0700 "$STAGING_DIR"
touch "$LOG_FILE"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"; }

push_row() {
  local domain="$1" db="$2" target="$3"
  if [[ -n "$ONLY_DOMAINS" && ",${ONLY_DOMAINS}," != *",${domain},"* ]]; then return 0; fi
  if [[ -z "$db" ]]; then log "SKIP: $domain - no database in the manifest"; return 0; fi
  if [[ ! "$db" =~ ^[A-Za-z0-9_-]+$ ]]; then log "FAIL: $domain - '$db' is not a plain database name"; return 1; fi
  if [[ -z "$target" ]]; then log "FAIL: $domain - no target_server"; return 1; fi

  local nontx consistency=(--single-transaction)
  nontx="$(mysql --defaults-extra-file="$DB_DEFAULTS_FILE" -N -B -e \
    "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='${db}' AND TABLE_TYPE='BASE TABLE' AND ENGINE NOT IN ('InnoDB')" </dev/null)"
  if [[ "$nontx" -gt 0 ]]; then consistency=(--lock-tables); fi

  if (( DRY_RUN )); then
    log "DRY-RUN: $domain - would dump '$db' (${consistency[0]}) and send it to $target:$REMOTE_DIR"
    return 0
  fi

  local name="${domain}.db.sql.gz" out="${STAGING_DIR}/${domain}.db.sql.gz"
  log "START: $domain - dumping '$db' (${consistency[0]})"
  rm -f "$out" "${out}.sha256"
  { printf -- '-- migration-db: domain=%s db=%s source=%s dumped_at=%s\n' \
      "$domain" "$db" "$(hostname -f 2>/dev/null || hostname)" "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    mysqldump --defaults-extra-file="$DB_DEFAULTS_FILE" "${consistency[@]}" \
      --routines --triggers --events --databases "$db" 2>>"$LOG_FILE" </dev/null
  } | gzip > "${out}.part"
  mv "${out}.part" "$out"
  (cd "$STAGING_DIR" && sha256sum "$name") > "${out}.sha256"

  if ! "${SSH_CMD[@]}" "$target" "mkdir -p '$REMOTE_DIR'" </dev/null; then
    log "FAIL: $domain - could not reach $target (check the SSH config)"; return 1
  fi
  if ! rsync -az -e "$RSYNC_SSH_OPT" "$out" "${out}.sha256" "${target}:${REMOTE_DIR}/" >>"$LOG_FILE" 2>&1 </dev/null; then
    log "FAIL: $domain - rsync to $target failed"; return 1
  fi
  local check
  if ! check="$("${SSH_CMD[@]}" "$target" "cd '$REMOTE_DIR' && sha256sum -c '${name}.sha256'" 2>&1 </dev/null)"; then
    log "FAIL: $domain - checksum check on $target failed: $check"; return 1
  fi
  log "DONE: $domain - '$db' ($(du -h "$out" | cut -f1)) on $target:$REMOTE_DIR/$name"
}

# Manifest on fd 3, not stdin: ssh reads stdin and would swallow the rows.
OK=0; FAILED=()
{
  read -r header <&3
  header="${header%$'\r'}"
  [[ "$header" == "domain,root,db,target_server" ]] || log "WARN: unexpected header '$header' - continuing anyway"
  while IFS=',' read -r domain root db target <&3 || [[ -n "$domain" ]]; do
    domain="${domain%$'\r'}"; root="${root%$'\r'}"; db="${db%$'\r'}"; target="${target%$'\r'}"
    [[ -z "$domain" ]] && continue
    set +e
    (
      set -Eeuo pipefail
      trap '(( BASH_SUBSHELL > 1 )) || [[ $BASH_COMMAND == push_row* || $BASH_COMMAND == return* ]] || log "FAIL: ${domain} - \"${BASH_COMMAND}\" failed (line ${LINENO})"' ERR
      trap 'rm -f "${STAGING_DIR}/${domain}.db.sql.gz.part"' EXIT
      push_row "$domain" "$db" "$target"
    ) 3<&-
    rc=$?
    set -e
    if (( rc == 0 )); then OK=$((OK + 1)); else FAILED+=("$domain"); fi
  done
} 3< "$MANIFEST"

if [[ -n "$ONLY_DOMAINS" ]]; then
  IFS=',' read -ra want <<< "$ONLY_DOMAINS"
  for d in "${want[@]}"; do
    grep -qE "^${d//./\\.}," "$MANIFEST" || log "WARN: --only $d is not in the manifest"
  done
fi
log "Finished: ${#FAILED[@]} failed. See $LOG_FILE"
for d in "${FAILED[@]}"; do log "  failed: $d"; done
(( ${#FAILED[@]} == 0 ))
