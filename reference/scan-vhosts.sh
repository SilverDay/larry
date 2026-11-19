#!/usr/bin/env bash
#
# scan-vhosts.sh -- inventory Apache vhosts into a JSON Lines manifest.
#
# Runs on BOTH the legacy 20.04 box and the new 24.04 hosts. Read-only: it
# never modifies Apache, PHP-FPM, or any site content. Deliberately free of
# external dependencies (no jq) so it can run on legacy without installing
# anything.
#
# WHY apache2ctl -S RATHER THAN GREPPING sites-available
#   -S is Apache's own parsed vhost map. It resolves Include directives, it
#   reflects what is actually ENABLED rather than what merely exists on disk,
#   and it reports the file:line where each vhost is defined. Grepping
#   sites-available inventories stale, disabled and duplicate entries as if
#   they were live.
#
# OUTPUT: one JSON object per line (JSONL), keys sorted, to stdout or --output.
#
#   domain, aliases[], conf_files[], docroot, docroots[], docroot_conflict,
#   docroot_exists, docroot_style, vhost_root, ssl, php_mode, php_version,
#   fpm_socket, pool_conf, pool_user, pool_group, open_basedir[], owner_user,
#   owner_group, dir_mode, file_mode,
#   htaccess_php_files[], abs_path_hits, scanned_host, scanned_at
#
#   docroot_style is one of: public | httpdocs | nested | other
#   php_mode is one of:      fpm | mod_php | static | unknown
#
# USAGE
#   ./scan-vhosts.sh                     # to stdout
#   ./scan-vhosts.sh -o legacy.jsonl     # to a file
#   ./scan-vhosts.sh --base /srv/vhosts  # vhost base for style classification
#   ./scan-vhosts.sh --no-content-scan   # skip .htaccess / abs-path scanning
#
set -euo pipefail

VHOST_BASE="/srv/vhosts"
OUTPUT=""
CONTENT_SCAN=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--output) OUTPUT="${2:?}"; shift 2 ;;
    --base)      VHOST_BASE="${2:?}"; shift 2 ;;
    --no-content-scan) CONTENT_SCAN=0; shift ;;
    -h|--help)   sed -n '2,/^set -euo/p' "$0" | sed 's/^# \{0,1\}//; $d'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "must run as root (needs to read pool configs and site trees)" >&2; exit 1; }
command -v apache2ctl >/dev/null || { echo "apache2ctl not found" >&2; exit 1; }

# --- JSON emitters (no jq dependency) --------------------------------------
json_str() {
  local s="${1-}"
  s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
  s="${s//$'\t'/\\t}"; s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"
  printf '"%s"' "$s"
}
json_arr() {
  local out="" i
  for i in "$@"; do out="${out:+$out,}$(json_str "$i")"; done
  printf '[%s]' "$out"
}
json_bool() { [[ "${1:-0}" == "1" ]] && printf 'true' || printf 'false'; }

# A silent truncation is the worst failure mode for an inventory, so make any
# unexpected abort visible and name the vhost being processed at the time.
trap 'rc=$?; [[ $rc -ne 0 ]] && echo "scan-vhosts: ABORTED (exit $rc) while processing ${domain:-<startup>}" >&2; exit $rc' EXIT

SCAN_HOST="$(hostname -f 2>/dev/null || hostname)"
SCAN_AT="$(date -Is)"

# --- enumerate vhosts from apache2ctl -S ------------------------------------
# Lines look like:
#   port 80 namevhost example.com (/etc/apache2/sites-enabled/example.conf:1)
#           alias www.example.com
VHOST_DUMP="$(apache2ctl -S 2>/dev/null || true)"
[[ -n "$VHOST_DUMP" ]] || { echo "apache2ctl -S produced no output" >&2; exit 1; }

declare -A V_CONFS V_ALIASES V_SEEN
CURRENT=""
while IFS= read -r line; do
  # Two forms appear in `apache2ctl -S`:
  #   "port 443 namevhost NAME (FILE:LINE)"  -- name-based
  #   "1.2.3.4:80         NAME (FILE:LINE)"  -- IP-based / default vhost
  # Matching only the first silently drops IP-based vhosts and default-ssl.
  if [[ "$line" =~ (namevhost|default[[:space:]]server)[[:space:]]+([^[:space:]]+)[[:space:]]+\((.+):([0-9]+)\) ]]; then
    CURRENT="${BASH_REMATCH[2]}"
    conf="${BASH_REMATCH[3]}"
    # resolve sites-enabled symlink back to the real file
    [[ -L "$conf" ]] && conf="$(readlink -f "$conf")"
    V_SEEN["$CURRENT"]=1
    case " ${V_CONFS[$CURRENT]:-} " in
      *" $conf "*) : ;;
      *) V_CONFS["$CURRENT"]="${V_CONFS[$CURRENT]:-}${V_CONFS[$CURRENT]:+ }$conf" ;;
    esac
  elif [[ "$line" =~ ^[^[:space:]]+:[0-9*]+[[:space:]]+([^[:space:]]+)[[:space:]]+\((.+):([0-9]+)\)[[:space:]]*$ ]]; then
    CURRENT="${BASH_REMATCH[1]}"
    conf="${BASH_REMATCH[2]}"
    [[ -L "$conf" ]] && conf="$(readlink -f "$conf")"
    V_SEEN["$CURRENT"]=1
    case " ${V_CONFS[$CURRENT]:-} " in
      *" $conf "*) : ;;
      *) V_CONFS["$CURRENT"]="${V_CONFS[$CURRENT]:-}${V_CONFS[$CURRENT]:+ }$conf" ;;
    esac
  elif [[ "$line" =~ ^[[:space:]]+alias[[:space:]]+([^[:space:]]+) ]] && [[ -n "$CURRENT" ]]; then
    a="${BASH_REMATCH[1]}"
    case " ${V_ALIASES[$CURRENT]:-} " in
      *" $a "*) : ;;
      *) V_ALIASES["$CURRENT"]="${V_ALIASES[$CURRENT]:-}${V_ALIASES[$CURRENT]:+ }$a" ;;
    esac
  fi
done <<< "$VHOST_DUMP"

# --- helper: pull a directive out of the vhost's config files ---------------
directive() { # directive <name> <file...>
  local name="$1" out; shift
  # NB: no `head` in the pipeline. head exits after the first line, which sends
  # SIGPIPE upstream; under `set -o pipefail` the pipeline then returns 141 and
  # `set -e` aborts the whole scan mid-loop, silently truncating the output.
  out="$(grep -hiE "^[[:space:]]*${name}[[:space:]]" "$@" 2>/dev/null || true)"
  [[ -n "$out" ]] || return 0
  printf '%s' "${out%%$'\n'*}" \
    | sed -E 's/^[[:space:]]*[A-Za-z]+[[:space:]]+//; s/^"//; s/"[[:space:]]*$//; s/[[:space:]]+$//; s#/+$##'
}

emit() { if [[ -n "$OUTPUT" ]]; then printf '%s\n' "$1" >> "$OUTPUT"; else printf '%s\n' "$1"; fi; }
[[ -n "$OUTPUT" ]] && : > "$OUTPUT"

# --- per-vhost record -------------------------------------------------------
for domain in $(printf '%s\n' "${!V_SEEN[@]}" | sort); do
  read -ra CONFS <<< "${V_CONFS[$domain]}"
  read -ra ALIASES <<< "${V_ALIASES[$domain]:-}"

  # Collect ALL distinct DocumentRoot values across this domain's config files.
  # If the :80 and :443 vhosts disagree (a typo in one of them, say) taking the
  # first would hide the broken one behind the working one.
  DR_ALL=()
  while IFS= read -r _d; do [[ -n "$_d" ]] && DR_ALL+=("$_d"); done < <(
    grep -hiE '^[[:space:]]*DocumentRoot[[:space:]]' "${CONFS[@]}" 2>/dev/null \
      | sed -E 's/^[[:space:]]*[A-Za-z]+[[:space:]]+//; s/^"//; s/"[[:space:]]*$//; s/[[:space:]]+$//; s#/+$##' \
      | sort -u || true)

  # Prefer a docroot that actually exists; otherwise keep the first.
  DOCROOT=""
  for _d in ${DR_ALL[@]+"${DR_ALL[@]}"}; do
    if [[ -d "$_d" ]]; then DOCROOT="$_d"; break; fi
  done
  [[ -n "$DOCROOT" ]] || DOCROOT="${DR_ALL[0]:-}"
  DOCROOT_CONFLICT=0; (( ${#DR_ALL[@]} > 1 )) && DOCROOT_CONFLICT=1
  DOCROOT_EXISTS=0; [[ -n "$DOCROOT" && -d "$DOCROOT" ]] && DOCROOT_EXISTS=1
  VHOST_ROOT=""; [[ -n "$DOCROOT" ]] && VHOST_ROOT="$(dirname "$DOCROOT")"

  # classify layout relative to the vhost base
  STYLE="other"
  if [[ -n "$DOCROOT" ]]; then
    REL="${DOCROOT#"${VHOST_BASE%/}/"}"
    DEPTH="$(awk -F/ '{print NF}' <<< "$REL")"
    LEAF="$(basename "$DOCROOT")"
    if (( DEPTH > 2 )); then STYLE="nested"
    elif [[ "$LEAF" == "public" ]]; then STYLE="public"
    elif [[ "$LEAF" == "httpdocs" ]]; then STYLE="httpdocs"
    fi
  fi

  # certbot's -le-ssl.conf usually has no literal "SSLEngine on" -- that lives
  # in options-ssl-apache.conf, which it Includes. Detect the certificate
  # directive or a :443 VirtualHost instead.
  SSL=0
  if grep -qiE '^[[:space:]]*(SSLEngine[[:space:]]+on|SSLCertificateFile)|<VirtualHost[^>]*:443' \
       "${CONFS[@]}" 2>/dev/null; then SSL=1; fi

  # --- PHP wiring ---
  FPM_RAW="$(grep -hoE 'proxy:unix:[^|]+\|' "${CONFS[@]}" 2>/dev/null || true)"
  FPM_SOCK=""
  if [[ -n "$FPM_RAW" ]]; then
    FPM_SOCK="${FPM_RAW%%$'\n'*}"; FPM_SOCK="${FPM_SOCK#proxy:unix:}"; FPM_SOCK="${FPM_SOCK%|}"
  fi
  POOL_CONF=""; POOL_USER=""; POOL_GROUP=""; PHP_VER=""; PHP_MODE="unknown"
  OB_PARTS=()

  if [[ -n "$FPM_SOCK" ]]; then
    PHP_MODE="fpm"
    while IFS= read -r cand; do
      if grep -qE "^[[:space:]]*listen[[:space:]]*=[[:space:]]*${FPM_SOCK//\//\\/}[[:space:]]*$" "$cand" 2>/dev/null; then
        POOL_CONF="$cand"; break
      fi
    done < <(find /etc/php -type f -path '*/fpm/pool.d/*.conf' 2>/dev/null | sort)
    if [[ -n "$POOL_CONF" ]]; then
      POOL_USER="$(sed -nE 's/^[[:space:]]*user[[:space:]]*=[[:space:]]*([^[:space:];]+).*/\1/p' "$POOL_CONF" || true)"
      POOL_USER="${POOL_USER%%$'\n'*}"
      POOL_GROUP="$(sed -nE 's/^[[:space:]]*group[[:space:]]*=[[:space:]]*([^[:space:];]+).*/\1/p' "$POOL_CONF" || true)"
      POOL_GROUP="${POOL_GROUP%%$'\n'*}"
      PHP_VER="$(sed -E 's#^/etc/php/([^/]+)/.*#\1#' <<< "$POOL_CONF")"
      OB_RAW="$(sed -nE 's/^[[:space:]]*php_admin_value\[open_basedir\][[:space:]]*=[[:space:]]*(.*)$/\1/p' "$POOL_CONF" || true)"
      OB_RAW="${OB_RAW%%$'\n'*}"
      [[ -n "$OB_RAW" ]] && IFS=':' read -ra OB_PARTS <<< "$OB_RAW"
    fi
  elif apache2ctl -M 2>/dev/null | grep -qiE 'php[0-9_]*_module'; then
    PHP_MODE="mod_php"
    PHP_VER="$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;' 2>/dev/null || true)"
  elif [[ -n "$DOCROOT" ]] && (( DOCROOT_EXISTS )) && ! find "$DOCROOT" -maxdepth 2 -name '*.php' -print -quit 2>/dev/null | grep -q .; then
    PHP_MODE="static"
  fi

  # --- observed ownership and modes on the docroot ---
  OWNER_U=""; OWNER_G=""; DIR_MODE=""; FILE_MODE=""
  if (( DOCROOT_EXISTS )); then
    OWNER_U="$(stat -c '%U' "$DOCROOT")"
    OWNER_G="$(stat -c '%G' "$DOCROOT")"
    DIR_MODE="0$(stat -c '%a' "$DOCROOT")"
    # most common file mode inside the docroot, rather than a single sample
    MODES="$(find "$DOCROOT" -type f -printf '%m\n' 2>/dev/null || true)"
    if [[ -n "$MODES" ]]; then
      TALLY="$(printf '%s\n' "$MODES" | sort | uniq -c | sort -rn)"
      FILE_MODE="0$(printf '%s' "${TALLY%%$'\n'*}" | awk '{print $2}')"
    fi
  fi

  # --- content scan (the two things that reliably break on migration) ---
  HT_FILES=(); ABS_HITS=0
  if (( CONTENT_SCAN )) && (( DOCROOT_EXISTS )); then
    while IFS= read -r f; do [[ -n "$f" ]] && HT_FILES+=("$f"); done < <(
      find "$DOCROOT" -name '.htaccess' -type f -exec grep -lE '^[[:space:]]*php_(value|flag|admin_value|admin_flag)[[:space:]]' {} + 2>/dev/null || true)
    # grep exits 1 on no matches; under `set -o pipefail` that would fail the
    # whole pipeline, so absorb it INSIDE the pipe rather than with a trailing
    # `|| echo 0` (which would append a second value to wc's output).
    ABS_HITS="$( { grep -rlF "$VHOST_BASE" --include='*.php' --include='*.inc' --include='*.ini' "$DOCROOT" 2>/dev/null || true; } | wc -l )"
  fi

  printf -v REC '{"abs_path_hits":%s,"aliases":%s,"conf_files":%s,"dir_mode":%s,"docroot":%s,"docroot_conflict":%s,"docroot_exists":%s,"docroot_style":%s,"docroots":%s,"domain":%s,"file_mode":%s,"fpm_socket":%s,"htaccess_php_files":%s,"open_basedir":%s,"owner_group":%s,"owner_user":%s,"php_mode":%s,"php_version":%s,"pool_conf":%s,"pool_group":%s,"pool_user":%s,"scanned_at":%s,"scanned_host":%s,"ssl":%s,"vhost_root":%s}' \
    "${ABS_HITS:-0}" \
    "$(json_arr "${ALIASES[@]+"${ALIASES[@]}"}")" \
    "$(json_arr "${CONFS[@]}")" \
    "$(json_str "$DIR_MODE")" \
    "$(json_str "$DOCROOT")" \
    "$(json_bool "$DOCROOT_CONFLICT")" \
    "$(json_bool "$DOCROOT_EXISTS")" \
    "$(json_str "$STYLE")" \
    "$(json_arr "${DR_ALL[@]+"${DR_ALL[@]}"}")" \
    "$(json_str "$domain")" \
    "$(json_str "$FILE_MODE")" \
    "$(json_str "$FPM_SOCK")" \
    "$(json_arr "${HT_FILES[@]+"${HT_FILES[@]}"}")" \
    "$(json_arr "${OB_PARTS[@]+"${OB_PARTS[@]}"}")" \
    "$(json_str "$OWNER_G")" \
    "$(json_str "$OWNER_U")" \
    "$(json_str "$PHP_MODE")" \
    "$(json_str "$PHP_VER")" \
    "$(json_str "$POOL_CONF")" \
    "$(json_str "$POOL_GROUP")" \
    "$(json_str "$POOL_USER")" \
    "$(json_str "$SCAN_AT")" \
    "$(json_str "$SCAN_HOST")" \
    "$(json_bool "$SSL")" \
    "$(json_str "$VHOST_ROOT")"

  emit "$REC"
done

if [[ -n "$OUTPUT" ]]; then
  chmod 0600 "$OUTPUT"
  echo "wrote $(wc -l < "$OUTPUT") vhost record(s) to $OUTPUT" >&2
fi
