#!/usr/bin/env bash
#
# import-migration-dbs.sh  --  v1 (2026-11-01)
#
# Runs on a target server, as root. Imports <domain>.db.sql.gz files written
# by push-migration-dbs.sh and REPLACES each database, so it matches the
# legacy one exactly -- tables dropped on legacy disappear here too.
#
# Per file:
#   1. Verify the checksum (hash only, so it works from any directory).
#   2. Read domain + database from the file's first line and check it
#      matches the dump's own USE statement.
#   3. If the database exists here and has tables: dump it to --backup-dir
#      first. If that backup fails, nothing is changed.
#   4. DROP DATABASE, then import. The dump re-creates the database with its
#      original character set. Database-level grants (the app's DB user)
#      are kept by MariaDB across DROP/CREATE.
#   5. Compare the table count with the dump; warn about DEFINER accounts
#      (views/triggers/routines) that don't exist here.
#
# The site is without its database while step 4 runs (seconds to minutes):
# put it in maintenance mode first if that matters.
#
# Usage:
#   ./import-migration-dbs.sh [options] FILE.db.sql.gz [FILE.db.sql.gz ...]
#
# Options:
#   --dry-run               Check everything, change nothing
#   --db-defaults-file F    Local admin credentials (default: ./deploy-db.cnf
#                           next to this script)
#   --backup-dir DIR        Where existing databases are dumped first
#                           (default: /var/backups/migration-deploy)
#
# Exit status is non-zero if any file failed.
#
set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DB_DEFAULTS_FILE="${SCRIPT_DIR}/deploy-db.cnf"
BACKUP_DIR="/var/backups/migration-deploy"
DRY_RUN=0
LOG_FILE="${SCRIPT_DIR}/migration-db-import.log"

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit "${1:-1}"; }
die()   { echo "ERROR: $*" >&2; exit 1; }

FILES=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)          DRY_RUN=1; shift ;;
    --db-defaults-file) DB_DEFAULTS_FILE="${2:?}"; shift 2 ;;
    --backup-dir)       BACKUP_DIR="${2:?}"; shift 2 ;;
    -h|--help)          usage 0 ;;
    -*)                 echo "Unknown option: $1" >&2; usage ;;
    *)                  FILES+=("$1"); shift ;;
  esac
done
(( ${#FILES[@]} )) || { echo "No files given." >&2; usage; }
[[ $EUID -eq 0 ]] || die "must run as root"
[[ -f "$DB_DEFAULTS_FILE" ]] || die "no DB admin credentials at $DB_DEFAULTS_FILE"

touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
exec 9>>"$LOG_FILE"
flock -n 9 || die "another import is running (lock on $LOG_FILE)"
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE" >&2; }

q() { mysql --defaults-extra-file="$DB_DEFAULTS_FILE" -N -B -e "$1" </dev/null; }

import_one() {
  local f="$1"
  CUR="$f"
  if [[ ! -f "$f" ]]; then log "FAIL: $f - file not found"; return 1; fi

  # 1. checksum
  local sumfile="${f}.sha256" expected actual
  if [[ ! -f "$sumfile" ]]; then log "FAIL: $f - no ${sumfile##*/} next to it; refusing"; return 1; fi
  expected="$(awk 'NR==1 {print tolower($1)}' "$sumfile")"
  actual="$(sha256sum -- "$f" | awk '{print $1}')"
  if [[ ! "$expected" =~ ^[0-9a-f]{64}$ || "$actual" != "$expected" ]]; then
    log "FAIL: $f - checksum mismatch (expected ${expected:-?}, got $actual)"; return 1
  fi

  # 2. header + USE line (only the start of the file is read)
  local head hdr domain db use_db="" line
  head="$( { gzip -dc -- "$f" 2>/dev/null || true; } | head -c 16384)"
  hdr="${head%%$'\n'*}"
  if [[ ! "$hdr" =~ ^--\ migration-db:\ domain=([A-Za-z0-9.-]+)\ db=([A-Za-z0-9_-]+)\  ]]; then
    log "FAIL: $f - not a push-migration-dbs.sh file (missing header line)"; return 1
  fi
  domain="${BASH_REMATCH[1]}"; db="${BASH_REMATCH[2]}"
  CUR="$domain"
  while IFS= read -r line; do
    if [[ "$line" =~ ^USE\ \`([^\`]+)\`\; ]]; then use_db="${BASH_REMATCH[1]}"; break; fi
  done <<< "$head"
  if [[ "$use_db" != "$db" ]]; then
    log "FAIL: $domain - header says db '$db' but the dump switches to '${use_db:-<none>}'"; return 1
  fi
  case "$db" in mysql|sys|information_schema|performance_schema)
    log "FAIL: $domain - refusing to replace system database '$db'"; return 1 ;; esac

  local exists ntab dump_tables
  exists="$(q "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='${db}'")"
  ntab="$(q "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='${db}' AND TABLE_TYPE='BASE TABLE'")"
  dump_tables="$( { gzip -dc -- "$f" | grep -c '^CREATE TABLE ' || true; } )"
  log "PLAN: $domain - database '$db': $( ((exists)) && echo "exists here with $ntab tables -> backup, drop, re-import" || echo "new here -> import" ) ($dump_tables tables in the dump, ${hdr#*dumped_at=})"
  if (( DRY_RUN )); then log "DRY-RUN: $domain - nothing changed"; return 0; fi

  # 3. backup what is there now
  if (( exists )) && (( ntab > 0 )); then
    mkdir -p "$BACKUP_DIR"; chmod 0700 "$BACKUP_DIR"
    local nontx consistency=(--single-transaction) bak
    nontx="$(q "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='${db}' AND TABLE_TYPE='BASE TABLE' AND ENGINE NOT IN ('InnoDB')")"
    if [[ "$nontx" -gt 0 ]]; then consistency=(--lock-tables); fi
    bak="$(mktemp --suffix=.sql.gz "$BACKUP_DIR/${db}-$(date +%Y%m%d-%H%M%S)-XXXX")"
    mysqldump --defaults-extra-file="$DB_DEFAULTS_FILE" "${consistency[@]}" \
      --routines --triggers --events --databases "$db" </dev/null | gzip > "$bak"
    log "  backup ....... $bak"
  fi

  # 4. replace
  q "DROP DATABASE IF EXISTS \`${db}\`"
  gzip -dc -- "$f" | mysql --defaults-extra-file="$DB_DEFAULTS_FILE"
  local now; now="$(q "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='${db}' AND TABLE_TYPE='BASE TABLE'")"
  if [[ "$now" == "$dump_tables" ]]; then
    log "  imported ..... '$db' with $now tables (matches the dump)"
  else
    log "  WARN: '$db' has $now tables after import, the dump has $dump_tables CREATE TABLE statements"
  fi

  # 5. definers
  local def du dh cnt
  while IFS= read -r def; do
    [[ -n "$def" ]] || continue
    du="${def%%@*}"; dh="${def#*@}"
    if [[ "$du" =~ ^[A-Za-z0-9_.-]+$ && "$dh" =~ ^[A-Za-z0-9_.%:-]+$ ]]; then
      cnt="$(q "SELECT COUNT(*) FROM mysql.user WHERE User='${du}' AND Host='${dh}'")"
      [[ "$cnt" -gt 0 ]] || log "  WARN: definer '${du}'@'${dh}' does not exist here - views/triggers/routines it owns will fail until you create it"
    else
      log "  WARN: unusual definer '$def' - check it by hand"
    fi
  done < <( { gzip -dc -- "$f" | grep -oE 'DEFINER=`[^`]+`@`[^`]+`' || true; } \
            | sed -E 's/^DEFINER=`([^`]+)`@`([^`]+)`$/\1@\2/' | sort -u )

  log "DONE: $domain - '$db' replaced from $(basename "$f")"
}

FAILED=()
for f in "${FILES[@]}"; do
  set +e
  (
    set -Eeuo pipefail
    CUR="$f"
    trap '(( BASH_SUBSHELL > 1 )) || [[ $BASH_COMMAND == import_one* || $BASH_COMMAND == return* ]] || log "FAIL: ${CUR} - \"${BASH_COMMAND}\" failed (line ${LINENO})"' ERR
    import_one "$f"
  )
  rc=$?
  set -e
  (( rc == 0 )) || FAILED+=("$f")
done
log "Finished: $(( ${#FILES[@]} - ${#FAILED[@]} )) ok, ${#FAILED[@]} failed. Log: $LOG_FILE"
for f in "${FAILED[@]}"; do log "  failed: $f"; done
(( ${#FAILED[@]} == 0 ))
