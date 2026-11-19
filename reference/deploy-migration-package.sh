#!/usr/bin/env bash
#
# deploy-migration-package.sh  --  v2 (2026-11-01)
#
# Runs on a target server. Deploys .pkg.tar.gz files produced by
# create-migration-packages.sh into vhosts that have ALREADY been provisioned
# with create-apache-vhost.sh (and, where used, fix-vhost-docroot.sh).
#
# Everything about the target is read from the live config, never derived
# from the domain name:
#   docroot     DocumentRoot in <apache-sites>/<domain>.conf (+ -le-ssl.conf)
#   owner       the PHP-FPM pool whose `listen =` matches the vhost's
#               proxy:unix: handler -> its `user =`
#   deploy ACL  re-applied only if the docroot already carries one for the
#               deploy user, i.e. the vhost was provisioned with it
#
# Per package:
#   1. Verify the checksum by hash (independent of the path in .sha256).
#   2. Refuse if the target tree holds files owned by another vhost's pool
#      user -- same guard as create-apache-vhost.sh; --adopt overrides.
#   3. Snapshot existing files, and dump the database if it already has
#      tables, into --backup-dir. A re-run never loses data.
#   4. Copy the legacy webroot's contents into the live docroot (whatever it
#      is called) and its siblings (.env, storage/, ...) into the vhost dir.
#      Never writes into another vhost's tree nested inside this one; skips a
#      top-level subdomains/ (Plesk) unless --include-subdomains.
#   5. <pool user>:www-data, dirs 0750, files 0640, then deploy ACL (rwx on
#      dirs, rw- on files, a default entry on every directory) and explicit
#      group:: entries -- the state create-apache-vhost.sh leaves a docroot in.
#   6. Create the database and import the dump.
#   7. Check the PHP worker, Apache and the deploy user can actually reach
#      the docroot, and warn about things that break after a move.
#
# Usage:
#   ./deploy-migration-package.sh [options] package.pkg.tar.gz [...]
#   ./deploy-migration-package.sh [options] --all /srv/migration-incoming
#
# Options:
#   --all DIR               Process every *.pkg.tar.gz in DIR
#   --dry-run               Resolve and check everything, change nothing
#   --vhost-base DIR        Docroots must live under this (default: /srv/vhosts)
#   --apache-sites DIR      Vhost configs (default: /etc/apache2/sites-available)
#   --db-defaults-file F    Local admin DB credentials (default: ./deploy-db.cnf)
#   --backup-dir DIR        Pre-deploy snapshots
#                           (default: /var/backups/migration-deploy)
#   --deploy-user USER      Deploy user to look for on the docroot ACL
#                           (default: silverday)
#   --no-deploy-acl         Never touch the deploy ACL
#   --include-subdomains    Also copy a top-level subdomains/ directory
#   --adopt                 Proceed even if another pool user owns files in
#                           the target tree
#
set -Eeuo pipefail
umask 027

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VHOST_BASE="/srv/vhosts"
APACHE_SITES="/etc/apache2/sites-available"
DB_DEFAULTS_FILE="${SCRIPT_DIR}/deploy-db.cnf"
BACKUP_DIR="/var/backups/migration-deploy"
DEPLOY_USER="silverday"
DEPLOY_ACL=1
INCLUDE_SUBDOMAINS=0
ADOPT=0
DRY_RUN=0
ALL_DIR=""
LOG_FILE="${SCRIPT_DIR}/migration-deploy.log"
WEB_GROUP="www-data"

usage() { awk 'NR>1 && /^#/ {sub(/^# ?/, ""); print; next} NR>1 {exit}' "$0"; exit "${1:-1}"; }
die()   { echo "ERROR: $*" >&2; exit 1; }

PACKAGES=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --all)                ALL_DIR="${2:?--all needs a directory}"; shift 2 ;;
    --dry-run)            DRY_RUN=1; shift ;;
    --vhost-base)         VHOST_BASE="${2:?}"; shift 2 ;;
    --apache-sites)       APACHE_SITES="${2:?}"; shift 2 ;;
    --db-defaults-file)   DB_DEFAULTS_FILE="${2:?}"; shift 2 ;;
    --backup-dir)         BACKUP_DIR="${2:?}"; shift 2 ;;
    --deploy-user)        DEPLOY_USER="${2:?}"; shift 2 ;;
    --no-deploy-acl)      DEPLOY_ACL=0; shift ;;
    --include-subdomains) INCLUDE_SUBDOMAINS=1; shift ;;
    --adopt)              ADOPT=1; shift ;;
    --create-vhost-script)
      die "--create-vhost-script was removed in v2. create-apache-vhost.sh needs an
       e-mail argument and asks questions, so it cannot be driven from here.
       Provision first, e.g.:  create-apache-vhost.sh <domain> <email> --docroot-name=httpdocs" ;;
    -h|--help)            usage 0 ;;
    -*)                   echo "Unknown option: $1" >&2; usage ;;
    *)                    PACKAGES+=("$1"); shift ;;
  esac
done

[[ $EUID -eq 0 ]] || die "must run as root (chown, setfacl, DB admin)"
for c in rsync setfacl getfacl setpriv sha256sum tar realpath flock; do
  command -v "$c" >/dev/null || die "required command not found: $c"
done
getent group "$WEB_GROUP" >/dev/null || die "group $WEB_GROUP does not exist"
VHOST_BASE="$(realpath -e -- "$VHOST_BASE")" || die "--vhost-base does not exist"
[[ -d "$APACHE_SITES" ]] || die "apache sites dir not found: $APACHE_SITES"

if [[ -n "$ALL_DIR" ]]; then
  [[ -d "$ALL_DIR" ]] || die "--all: not a directory: $ALL_DIR"
  shopt -s nullglob
  for f in "$ALL_DIR"/*.pkg.tar.gz; do PACKAGES+=("$f"); done
  shopt -u nullglob
fi
(( ${#PACKAGES[@]} )) || { echo "No packages given. Use a path or --all DIR." >&2; usage; }

touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
exec 9>>"$LOG_FILE"
flock -n 9 || die "another run is in progress (lock on $LOG_FILE)"

# Logs go to stderr so they never end up inside a $(...) capture.
log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE" >&2; }

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

# under PATH DIR -> PATH is strictly below DIR
under() { [[ "$1" == "$2"/* ]]; }

# First `key = value` in an ini-style file (PHP-FPM pool configs).
ini_value() {
  local v
  v="$(sed -nE "s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*([^[:space:];]+).*/\1/p" "$1" 2>/dev/null || true)"
  printf '%s' "${v%%$'\n'*}"
}

# Every DocumentRoot in the given vhost files, normalised, one per line.
docroots_of() {
  { grep -hiE '^[[:space:]]*DocumentRoot[[:space:]]' "$@" 2>/dev/null || true; } \
    | sed -E 's/^[[:space:]]*[Dd]ocument[Rr]oot[[:space:]]+//; s/^"//; s/"[[:space:]]*$//; s/[[:space:]]+$//; s#/+$##' \
    | sort -u
}

json_field() {
  { grep -o "\"$2\": *\"[^\"]*\"" "$1" || true; } | sed 's/.*: *"//; s/"$//'
}

# find, but never descending into another vhost's tree nested inside ours.
# Usage: find_pruned ROOT <expression with an explicit action>
NESTED=()
find_pruned() {
  local root="$1"; shift
  if (( ${#NESTED[@]} )); then
    local expr=() n
    for n in "${NESTED[@]}"; do expr+=(-path "$n" -o); done
    unset 'expr[${#expr[@]}-1]'
    find "$root" \( "${expr[@]}" \) -prune -o "$@"
  else
    find "$root" "$@"
  fi
}

# Run a test as another identity, the way PHP-FPM/Apache would hold it.
can_as() {  # can_as USER GROUP test-args...
  local u="$1" g="$2"; shift 2
  setpriv --reuid="$u" --regid="$g" --init-groups test "$@" 2>/dev/null
}

WORK_DIR=""
cleanup_work() {
  if [[ -n "$WORK_DIR" && "$WORK_DIR" == /tmp/deploy-migration.* && -d "$WORK_DIR" ]]; then
    rm -rf -- "$WORK_DIR"
  fi
}

# ---------------------------------------------------------------------------
# one package
# ---------------------------------------------------------------------------
deploy_one() {
  local pkg="$1"
  CUR="$pkg"
  if [[ ! -f "$pkg" ]]; then log "FAIL: $pkg - file not found"; return 1; fi

  # --- 1. checksum ---------------------------------------------------------
  # Compare the hash only. Unpatched create-migration-packages.sh writes the
  # package's absolute STAGING path into the .sha256, so `sha256sum -c` run
  # from any other directory (e.g. /srv/migration-incoming) reports the file
  # missing -- or, on a box where that path exists, checks the wrong file.
  local sumfile="${pkg}.sha256" expected actual
  if [[ ! -f "$sumfile" ]]; then
    log "FAIL: $pkg - no ${sumfile##*/} next to it; refusing to deploy an unverified package"
    return 1
  fi
  expected="$(awk 'NR==1 {print tolower($1)}' "$sumfile")"
  if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then log "FAIL: $pkg - malformed ${sumfile##*/}"; return 1; fi
  actual="$(sha256sum -- "$pkg" | awk '{print $1}')"
  if [[ "$actual" != "$expected" ]]; then
    log "FAIL: $pkg - checksum mismatch (expected $expected, got $actual)"
    return 1
  fi

  # --- 2. unpack into scratch ---------------------------------------------
  # --no-same-owner: the legacy box's numeric UIDs/GIDs mean nothing here (and
  # 7 vhosts there already carry orphaned GIDs); ownership is set in step 5.
  WORK_DIR="$(mktemp -d /tmp/deploy-migration.XXXXXX)"
  tar -xzf "$pkg" -C "$WORK_DIR" --no-same-owner

  local tops=()
  mapfile -t tops < <(find "$WORK_DIR" -mindepth 1 -maxdepth 1 -printf '%f\n')
  if (( ${#tops[@]} != 1 )) || [[ ! -d "$WORK_DIR/${tops[0]}" ]]; then
    log "FAIL: $pkg - expected exactly one top-level directory, found: ${tops[*]:-none}"
    return 1
  fi
  local domain="${tops[0]}"
  if [[ ! "$domain" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ || "$domain" == *..* ]]; then
    log "FAIL: $pkg - '$domain' is not a valid domain name"
    return 1
  fi
  CUR="$domain"

  local meta="$WORK_DIR/$domain/manifest.json" webroot_basename db_name
  if [[ ! -f "$meta" ]]; then log "FAIL: $domain - manifest.json missing from package"; return 1; fi
  webroot_basename="$(json_field "$meta" source_webroot_basename)"
  db_name="$(json_field "$meta" db)"
  if [[ ! "$webroot_basename" =~ ^[A-Za-z0-9._-]+$ || "$webroot_basename" == "." || "$webroot_basename" == ".." ]]; then
    log "FAIL: $domain - bad source_webroot_basename '$webroot_basename' in manifest"
    return 1
  fi
  if [[ -n "$db_name" && ! "$db_name" =~ ^[A-Za-z0-9_-]+$ ]]; then
    log "FAIL: $domain - bad db name '$db_name' in manifest"
    return 1
  fi

  local files_tar="$WORK_DIR/$domain/files.tar.gz"
  if [[ ! -f "$files_tar" ]]; then log "FAIL: $domain - files.tar.gz missing from package"; return 1; fi
  mkdir "$WORK_DIR/files"
  tar -xzf "$files_tar" -C "$WORK_DIR/files" --no-same-owner
  local inner=()
  mapfile -t inner < <(find "$WORK_DIR/files" -mindepth 1 -maxdepth 1 -printf '%f\n')
  if (( ${#inner[@]} != 1 )) || [[ ! -d "$WORK_DIR/files/${inner[0]}" ]]; then
    log "FAIL: $domain - files.tar.gz should hold exactly one directory, found: ${inner[*]:-none}"
    return 1
  fi
  local src="$WORK_DIR/files/${inner[0]}"      # legacy vhost dir, one above webroot
  local src_webroot="$src/$webroot_basename"
  if [[ ! -d "$src_webroot" ]]; then
    log "FAIL: $domain - webroot '$webroot_basename' not found in archive"
    return 1
  fi

  # --- 3. resolve the live target from Apache + PHP-FPM config ------------
  local vconf="$APACHE_SITES/$domain.conf"
  if [[ ! -f "$vconf" ]]; then
    log "FAIL: $domain - no vhost config at $vconf. Provision it first:"
    log "        keep legacy name:  create-apache-vhost.sh $domain <email> --docroot-name=$webroot_basename"
    log "        use public/:       create-apache-vhost.sh $domain <email>"
    return 1
  fi
  local conf_files=("$vconf")
  if [[ -f "$APACHE_SITES/$domain-le-ssl.conf" ]]; then conf_files+=("$APACHE_SITES/$domain-le-ssl.conf"); fi

  local roots=()
  mapfile -t roots < <(docroots_of "${conf_files[@]}")
  if (( ${#roots[@]} != 1 )); then
    log "FAIL: $domain - expected one DocumentRoot across ${conf_files[*]}, found ${#roots[@]}: ${roots[*]:-none}"
    return 1
  fi
  local doc_root target
  if ! doc_root="$(realpath -e -- "${roots[0]}")"; then
    log "FAIL: $domain - DocumentRoot ${roots[0]} does not exist"
    return 1
  fi
  target="$(dirname "$doc_root")"
  if ! under "$doc_root" "$VHOST_BASE" || ! under "$target" "$VHOST_BASE"; then
    log "FAIL: $domain - docroot $doc_root is not inside a vhost dir under $VHOST_BASE; refusing"
    return 1
  fi

  local socks=()
  mapfile -t socks < <( { grep -hoE 'proxy:unix:[^|"]+' "${conf_files[@]}" || true; } | sed 's/^proxy:unix://' | sort -u)
  if (( ${#socks[@]} != 1 )); then
    log "FAIL: $domain - expected one proxy:unix: PHP-FPM handler, found ${#socks[@]}: ${socks[*]:-none}"
    log "        (static-only vhost? there is no pool user to derive - set ownership by hand)"
    return 1
  fi
  local pool_conf="" c
  while IFS= read -r c; do
    if [[ "$(ini_value "$c" listen)" == "${socks[0]}" ]]; then pool_conf="$c"; break; fi
  done < <(find /etc/php -type f -path '*/fpm/pool.d/*.conf' 2>/dev/null | sort)
  if [[ -z "$pool_conf" ]]; then
    log "FAIL: $domain - no PHP-FPM pool in /etc/php/*/fpm/pool.d listens on ${socks[0]}"
    return 1
  fi
  local pool_user pool_group
  pool_user="$(ini_value "$pool_conf" user)"
  pool_group="$(ini_value "$pool_conf" group)"
  if [[ -z "$pool_user" ]] || ! id "$pool_user" >/dev/null 2>&1; then
    log "FAIL: $domain - pool $pool_conf has no usable 'user =' (got '${pool_user}')"
    return 1
  fi
  [[ -n "$pool_group" ]] || pool_group="$(id -gn "$pool_user")"

  # Deploy ACL: mirror provisioning. Read before anything is copied.
  local acl_user="" acl_now
  if (( DEPLOY_ACL )); then
    acl_now="$(getfacl -pc -- "$doc_root" 2>/dev/null || true)"
    if grep -qE "^(default:)?user:${DEPLOY_USER}:" <<<"$acl_now"; then
      if id "$DEPLOY_USER" >/dev/null 2>&1; then acl_user="$DEPLOY_USER"
      else log "WARN: $domain - docroot ACL names '$DEPLOY_USER' but that user does not exist"; fi
    else
      log "NOTE: $domain - docroot has no ACL for '$DEPLOY_USER' (provisioned with --no-deploy-acl?); ACLs left alone"
    fi
  fi

  # Other vhosts whose tree sits inside ours (nested legacy layout kept via
  # fix-vhost-docroot.sh --docroot). We never copy into, chown or ACL them.
  NESTED=()
  local f d2 cand own
  while IFS= read -r f; do
    own=0
    for c in "${conf_files[@]}"; do if [[ "$f" == "$c" ]]; then own=1; fi; done
    (( own )) && continue
    while IFS= read -r d2; do
      [[ -n "$d2" ]] || continue
      d2="$(realpath -m -- "$d2")"
      if [[ "$d2" == "$doc_root" ]]; then log "NOTE: $domain - ${f##*/} serves the same docroot"; continue; fi
      cand="$(dirname "$d2")"
      if [[ "$cand" == "$target" || "$cand" == "$doc_root" ]]; then cand="$d2"; fi
      if under "$cand" "$target"; then NESTED+=("$cand"); fi
    done < <(docroots_of "$f")
  done < <(find "$APACHE_SITES" -maxdepth 1 -name '*.conf' \( -type f -o -type l \) | sort)
  if (( ${#NESTED[@]} )); then mapfile -t NESTED < <(printf '%s\n' "${NESTED[@]}" | sort -u); fi

  # Guard: never take over another vhost's files (as create-apache-vhost.sh).
  local foreign
  foreign="$( { find_pruned "$target" -printf '%u\n' 2>/dev/null || true; } \
              | sort -u | { grep -E '^php-' || true; } | { grep -vxF "$pool_user" || true; } )"
  if [[ -n "$foreign" ]]; then
    log "$( ((ADOPT)) && echo WARN || echo FAIL ): $domain - $target holds files owned by another vhost's pool user:"
    local o ex
    while IFS= read -r o; do
      ex="$( { find_pruned "$target" -user "$o" -printf '%p\n' 2>/dev/null || true; } | sort)"
      log "        $o   e.g. ${ex%%$'\n'*}"
    done <<<"$foreign"
    if (( ! ADOPT )); then
      log "        Taking these over would break that vhost and expose its files to $pool_user."
      log "        Nothing changed. If they are stale, re-run with --adopt."
      return 1
    fi
  fi

  # A legacy sibling with the live docroot's name would be merged into it.
  local live_name; live_name="$(basename "$doc_root")"
  if [[ "$live_name" != "$webroot_basename" && -e "$src/$live_name" ]]; then
    log "FAIL: $domain - legacy tree has '$live_name' next to its webroot '$webroot_basename';"
    log "        copying it would merge it into the live docroot $doc_root. Resolve by hand."
    return 1
  fi

  local sib_ex=(--exclude="/$webroot_basename") web_ex=() n skipped_sub=0
  if (( ! INCLUDE_SUBDOMAINS )) && [[ -d "$src/subdomains" ]]; then
    sib_ex+=(--exclude=/subdomains); skipped_sub=1
  fi
  for n in "${NESTED[@]}"; do
    if under "$n" "$doc_root"; then web_ex+=(--exclude="/${n#"$doc_root"/}")
    else sib_ex+=(--exclude="/${n#"$target"/}"); fi
  done

  # Things that will need attention after the move, measured on the source.
  local exec_files abs_links htaccess_php src_prune=()
  (( skipped_sub )) && src_prune=(-path "$src/subdomains" -prune -o)
  exec_files="$(find "$src" "${src_prune[@]}" -type f -perm /111 -printf '%P\n' 2>/dev/null | sort || true)"
  abs_links="$(find "$src" "${src_prune[@]}" -type l \( -lname '/*' -o -lname '*../*' -o -lname '..' \) -printf '%P -> %l\n' 2>/dev/null | sort || true)"
  htaccess_php="$( { find "$src_webroot" -type f -name .htaccess \
      -exec grep -lE '^[[:space:]]*php_(value|flag|admin_value|admin_flag)[[:space:]]' {} + 2>/dev/null || true; } \
      | sed "s#^$src_webroot/##" | sort)"

  local ntab=""
  if [[ -n "$db_name" && -f "$DB_DEFAULTS_FILE" ]]; then
    ntab="$(mysql --defaults-extra-file="$DB_DEFAULTS_FILE" -N -B \
            -e "SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA='${db_name}'")"
  fi

  log "PLAN: $domain"
  log "  docroot ........ $doc_root   (legacy webroot: $webroot_basename)"
  log "  vhost dir ...... $target"
  log "  owner .......... ${pool_user}:${WEB_GROUP}   (pool ${pool_conf##*/}, worker group $pool_group)"
  log "  deploy ACL ..... ${acl_user:-not applied}"
  (( ${#NESTED[@]} )) && log "  left alone ..... ${NESTED[*]}   (nested vhost)"
  (( skipped_sub ))   && log "  skipped ........ subdomains/   (deploy each subdomain from its own package; --include-subdomains to copy)"
  if [[ -n "$db_name" ]]; then
    log "  database ....... $db_name$( [[ -n "$ntab" && "$ntab" -gt 0 ]] && echo "   (exists with $ntab tables - will be dumped to $BACKUP_DIR first)" )"
  fi

  if (( DRY_RUN )); then
    [[ -n "$db_name" && ! -f "$DB_DEFAULTS_FILE" ]] && log "  WARN: no $DB_DEFAULTS_FILE - a real run would fail at the DB step"
    log "DRY-RUN: $domain - nothing changed"
    return 0
  fi
  if [[ -n "$db_name" && ! -f "$DB_DEFAULTS_FILE" ]]; then
    log "FAIL: $domain - db import needed but no defaults file at $DB_DEFAULTS_FILE"
    return 1
  fi

  # --- 4. snapshot what is there now ---------------------------------------
  mkdir -p "$BACKUP_DIR"; chmod 0700 "$BACKUP_DIR"
  local stamp; stamp="$(date +%Y%m%d-%H%M%S)"
  if [[ -n "$(find_pruned "$target" ! -type d -printf x -quit 2>/dev/null || true)" ]]; then
    local snap tex=()
    snap="$(mktemp --suffix=.files.tar.gz "$BACKUP_DIR/${domain}-${stamp}-XXXX")"
    for n in "${NESTED[@]}"; do tex+=(--exclude="$(basename "$target")/${n#"$target"/}"); done
    tar --acls --xattrs --anchored "${tex[@]}" -czf "$snap" -C "$(dirname "$target")" "$(basename "$target")"
    log "  snapshot ....... $snap"
  fi
  if [[ -n "$db_name" && -n "$ntab" && "$ntab" -gt 0 ]]; then
    local dbsnap
    dbsnap="$(mktemp --suffix=.sql.gz "$BACKUP_DIR/${db_name}-${stamp}-XXXX")"
    mysqldump --defaults-extra-file="$DB_DEFAULTS_FILE" --single-transaction \
      --routines --triggers --events --databases "$db_name" | gzip > "$dbsnap"
    log "  db snapshot .... $dbsnap"
  fi

  # --- 5. copy, then ownership / modes / ACLs -----------------------------
  rsync -a --no-devices --no-specials "${sib_ex[@]}" "$src/" "$target/"
  rsync -a --no-devices --no-specials "${web_ex[@]}" "$src_webroot/" "$doc_root/"

  find_pruned "$target" -exec chown -h "${pool_user}:${WEB_GROUP}" {} +
  find_pruned "$target" -type d -exec chmod 0750 {} +
  find_pruned "$target" -type f -exec chmod 0640 {} +

  if [[ -n "$acl_user" ]]; then
    # -type d/-type f is load-bearing: setfacl via find follows symlinks, so
    # a legacy symlink would otherwise hand the deploy user its target.
    # Explicit per type, not rwX: copied files inherit the docroot's
    # default:user:<deploy>:rwx, and X keeps an execute bit that is already
    # there -- so rwX would leave every file executable for the deploy user.
    find_pruned "$doc_root" -type d -exec setfacl -m "u:${acl_user}:rwx" {} +
    find_pruned "$doc_root" -type f -exec setfacl -m "u:${acl_user}:rw-" {} +
    find_pruned "$doc_root" -type d -exec setfacl -d -m "u:${acl_user}:rwx" {} +
  fi
  # chmod cannot set group:: once an ACL exists (it writes the mask), and
  # copied files inherit default:group::r-x. Normalise per type, as
  # create-apache-vhost.sh does: dirs r-x for Apache traversal, files r--.
  find_pruned "$doc_root" -type d -exec setfacl -m g::r-x {} +
  find_pruned "$doc_root" -type f -exec setfacl -m g::r-- {} +

  # --- 6. database ---------------------------------------------------------
  if [[ -n "$db_name" ]]; then
    local dump="$WORK_DIR/$domain/db.sql.gz"
    if [[ ! -f "$dump" ]]; then
      log "FAIL: $domain - manifest lists db '$db_name' but db.sql.gz is missing"
      return 1
    fi
    mysql --defaults-extra-file="$DB_DEFAULTS_FILE" \
      -e "CREATE DATABASE IF NOT EXISTS \`${db_name}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
    gunzip -c "$dump" | mysql --defaults-extra-file="$DB_DEFAULTS_FILE"
    log "  database ....... '$db_name' imported"

    # Views/triggers/routines run as their DEFINER; if that account does not
    # exist here they fail at query time, not at import time.
    local def du dh cnt
    while IFS= read -r def; do
      [[ -n "$def" ]] || continue
      du="${def%%@*}"; dh="${def#*@}"
      if [[ "$du" =~ ^[A-Za-z0-9_.-]+$ && "$dh" =~ ^[A-Za-z0-9_.%:-]+$ ]]; then
        cnt="$(mysql --defaults-extra-file="$DB_DEFAULTS_FILE" -N -B \
               -e "SELECT COUNT(*) FROM mysql.user WHERE User='${du}' AND Host='${dh}'")"
        [[ "$cnt" -gt 0 ]] || log "  WARN: definer '${du}'@'${dh}' does not exist here - views/triggers/routines it owns will fail until you create it"
      else
        log "  WARN: unusual definer '$def' - check it by hand"
      fi
    done < <( { gunzip -c "$dump" | grep -oE 'DEFINER=`[^`]+`@`[^`]+`' || true; } \
              | sed -E 's/^DEFINER=`([^`]+)`@`([^`]+)`$/\1@\2/' | sort -u )
  fi

  # --- 7. verify access and report -----------------------------------------
  local probe pgid wgid
  probe="$(find "$doc_root" -maxdepth 1 -type f -name 'index.*' -print -quit)"
  [[ -n "$probe" ]] || probe="$(find "$doc_root" -maxdepth 1 -type f -print -quit)"
  pgid="$(getent group "$pool_group" | cut -d: -f3)"
  wgid="$(getent group "$WEB_GROUP" | cut -d: -f3)"
  if can_as "$pool_user" "$pgid" -x "$doc_root" && { [[ -z "$probe" ]] || can_as "$pool_user" "$pgid" -r "$probe"; }; then
    log "  check .......... PHP worker ($pool_user) can read the docroot"
  else
    log "  WARN: PHP worker $pool_user cannot read $doc_root${probe:+ / ${probe##*/}} - check traverse ACLs on parent dirs (reconcile-vhosts.py --check-only)"
  fi
  if can_as www-data "$wgid" -x "$doc_root"; then
    log "  check .......... Apache (www-data) can traverse the docroot"
  else
    log "  WARN: www-data cannot traverse $doc_root - static files will 403"
  fi
  if [[ -n "$acl_user" ]]; then
    if can_as "$acl_user" "$(id -g "$acl_user")" -w "$doc_root" && { [[ -z "$probe" ]] || can_as "$acl_user" "$(id -g "$acl_user")" -w "$probe"; }; then
      log "  check .......... deploy user ($acl_user) can write"
    else
      log "  WARN: deploy user $acl_user cannot write $doc_root${probe:+ / ${probe##*/}}"
    fi
  fi

  show() {  # show LABEL MULTILINE-LIST
    local lines=() max=8 i
    mapfile -t lines <<<"$2"
    log "  WARN: $1 (${#lines[@]}):"
    for (( i=0; i<${#lines[@]} && i<max; i++ )); do log "          ${lines[$i]}"; done
    (( ${#lines[@]} > max )) && log "          ... $(( ${#lines[@]} - max )) more"
    return 0
  }
  [[ -z "$htaccess_php" ]] || show "mod_php directives in .htaccess - these 500 under PHP-FPM; run classify-htaccess.py" "$htaccess_php"
  [[ -z "$abs_links" ]]    || show "symlinks with absolute or ../ targets - check they still resolve here" "$abs_links"
  [[ -z "$exec_files" ]]   || show "files that lost their execute bit (0640 policy)" "$exec_files"
  if [[ "$live_name" != "$webroot_basename" ]]; then
    local hard
    hard="$( { find_pruned "$target" -type f -size -2M \
              \( -name '*.php' -o -name '*.inc' -o -name '.htaccess' -o -name '.user.ini' -o -name '*.ini' \
                 -o -name '.env' -o -name '*.json' -o -name '*.yml' -o -name '*.yaml' -o -name '*.xml' -o -name '*.conf' \) \
              -exec grep -lE "/${webroot_basename}(/|['\"]|\$)" {} + 2>/dev/null || true; } | sed "s#^$target/##" | sort)"
    [[ -z "$hard" ]] || show "files mentioning '/$webroot_basename' - docroot is now '$live_name', check hard-coded paths" "$hard"
  fi

  log "DONE: $domain - deployed to $doc_root"
}

# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
# Each package runs in its own subshell with errexit genuinely active: a
# function called as `f || handler` runs with -e silently disabled, which is
# how the v1 loop could carry on past a failed tar or cp.
OK=(); FAILED=()
(( DRY_RUN )) && log "DRY RUN - no changes will be made"
for pkg in "${PACKAGES[@]}"; do
  set +e
  (
    set -Eeuo pipefail
    CUR="$pkg"
    # Reports unexpected failures; deliberate `return 1`s have logged already.
    trap '(( BASH_SUBSHELL > 1 )) || [[ $BASH_COMMAND == deploy_one* || $BASH_COMMAND == return* ]] || log "FAIL: ${CUR} - \"${BASH_COMMAND}\" failed (line ${LINENO})"' ERR
    trap cleanup_work EXIT
    deploy_one "$pkg"
  )
  rc=$?
  set -e
  if (( rc == 0 )); then OK+=("$pkg"); else FAILED+=("$pkg"); fi
done

log "Finished: ${#OK[@]} ok, ${#FAILED[@]} failed. Log: $LOG_FILE"
for pkg in "${FAILED[@]}"; do log "  failed: $pkg"; done
if (( ! DRY_RUN && ${#OK[@]} )); then
  echo >&2
  echo "Reminder: app DB credentials (e.g. wp-config.php, .env) still need to point" >&2
  echo "at this server's local DB user/password - the import only recreates the data." >&2
  echo "Certificates are not part of this package - run certbot once DNS is cut over." >&2
fi
(( ${#FAILED[@]} == 0 ))
