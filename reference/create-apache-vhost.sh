#!/usr/bin/env bash
#
# create-apache-vhost.sh
#
# Creates an Apache virtual host for a given (sub-)domain on Ubuntu 24.04,
# with the document root at /srv/vhosts/<domain>/public, and obtains a
# Let's Encrypt certificate for it via certbot's Apache plugin.
#
# DIRECTORY LAYOUT (as specified):
#   /srv/vhosts/<domain>/public   <- DocumentRoot, web content goes here
#   /srv/vhosts/<domain>/logs     <- per-vhost access.log / error.log
#
# ASSUMPTIONS (stated, not silently applied -- adjust if they don't fit):
#   - Ownership: <dedicated-domain-user>:www-data, directories 750, files
#     640. Each domain gets its own dedicated system user (see PHP-FPM note
#     below) which owns its files; www-data is the group so Apache can
#     still read static assets directly. If a separate deploy/SFTP user
#     needs to upload files directly, add that user to the domain's group.
#   - PHP-FPM isolation: each vhost gets its own dedicated PHP-FPM pool
#     (own system user, own Unix socket) rather than sharing the server's
#     default pool -- so one compromised/misbehaving site's PHP process
#     can't read another site's files. Pool sizing defaults to
#     pm=ondemand, max_children=4; override with --max-children=N. This
#     was verified end-to-end in a sandbox (dedicated pool spawns under the
#     dedicated user, vhost-level handler correctly overrides the global
#     one) before being written into this script.
#   - www. alias: auto-added for apex domains (e.g. example.com -> also
#     configures www.example.com, same vhost, same cert) but NOT for
#     subdomains (e.g. shop.example.com stays as just that). Detection is a
#     simple label-count heuristic and gets compound-TLD domains wrong
#     (example.co.uk has 3 labels but is apex, not a subdomain of .co.uk) --
#     override with --www or --no-www when that matters.
#   - AllowOverride All is set (so .htaccess works out of the box) --
#     tighten to AllowOverride None if you don't need it.
#
# USAGE:
#   sudo bash create-apache-vhost.sh <domain> [admin-email] [--www|--no-www] [--max-children=N]
#   (admin-email is only used for Let's Encrypt renewal notices -- if
#   omitted, you'll be prompted. --www/--no-www override the automatic
#   apex-domain detection described above. --max-children sets this
#   domain's PHP-FPM pool worker cap, default 4 -- size deliberately if
#   this server hosts many domains sharing one RAM budget.)
#
# Re-running for the same domain is safe: directories/ownership, the
# dedicated user, and the FPM pool config are all idempotent; the vhost
# config is overwritten with the same content; certbot itself skips
# re-issuing a still-valid certificate.

set -euo pipefail

# ---------------------------------------------------------------------------
# 0. Preflight
# ---------------------------------------------------------------------------

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: this script must be run as root (sudo bash $0 <domain> [email] [--www|--no-www])" >&2
  exit 1
fi

DOMAIN=""
ADMIN_EMAIL=""
WWW_MODE="auto"   # auto | force | skip -- see label-count logic below
MAX_CHILDREN=4    # PHP-FPM pool worker cap for this domain; see --max-children

for arg in "$@"; do
  case "$arg" in
    --www)    WWW_MODE="force" ;;
    --no-www) WWW_MODE="skip" ;;
    --max-children=*) MAX_CHILDREN="${arg#*=}" ;;
    *)
      if [[ -z "$DOMAIN" ]]; then
        DOMAIN="$arg"
      elif [[ -z "$ADMIN_EMAIL" ]]; then
        ADMIN_EMAIL="$arg"
      fi
      ;;
  esac
done

if [[ -z "$DOMAIN" ]]; then
  read -rp "(Sub-)domain for the new vhost (e.g. shop.example.com): " DOMAIN
fi

# Basic FQDN sanity check -- catches copy-paste mistakes (protocol prefixes,
# trailing slashes, stray whitespace) before they end up in Apache config
# and a certbot request.
if [[ ! "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$ ]]; then
  echo "ERROR: '$DOMAIN' doesn't look like a valid domain (no protocol, no path, no trailing dot/slash)." >&2
  exit 1
fi

if [[ -z "$ADMIN_EMAIL" ]]; then
  read -rp "Admin email for Let's Encrypt renewal notices: " ADMIN_EMAIL
  [[ -n "$ADMIN_EMAIL" ]] || { echo "Admin email is required for certbot."; exit 1; }
fi

# Apex-vs-subdomain detection: a domain with exactly 2 labels (example.com)
# is treated as apex -> auto-add the www. alias, same cert, same vhost. A
# domain with 3+ labels (shop.example.com) is treated as a subdomain -> no
# www. alias, since "www.shop.example.com" is not what most people mean.
# CAVEAT: this simple label-count heuristic gets compound-TLD domains wrong
# (e.g. "example.co.uk" has 3 labels but is actually apex, not a subdomain
# of ".co.uk") -- there's no public-suffix-list lookup here. Override
# explicitly with --www or --no-www when the domain's TLD has more than one
# label.
LABEL_COUNT=$(awk -F'.' '{print NF}' <<< "$DOMAIN")
if [[ "$WWW_MODE" == "force" ]]; then
  ADD_WWW=1; WWW_REASON="--www flag"
elif [[ "$WWW_MODE" == "skip" ]]; then
  ADD_WWW=0; WWW_REASON="--no-www flag"
elif [[ "$LABEL_COUNT" -eq 2 ]]; then
  ADD_WWW=1; WWW_REASON="${DOMAIN} has 2 labels, treated as an apex domain"
else
  ADD_WWW=0; WWW_REASON="${DOMAIN} has ${LABEL_COUNT} labels, treated as a subdomain"
fi
WWW_DOMAIN="www.${DOMAIN}"

if [[ "$ADD_WWW" -eq 1 ]]; then
  echo "-> Will also configure ${WWW_DOMAIN} (${WWW_REASON}). Override with --no-www if that's wrong."
else
  echo "-> Not adding a www. alias (${WWW_REASON}). Override with --www if that's wrong (e.g. compound TLDs like .co.uk)."
fi

if ! [[ "$MAX_CHILDREN" =~ ^[1-9][0-9]*$ ]]; then
  echo "ERROR: --max-children must be a positive integer, got '${MAX_CHILDREN}'." >&2
  exit 1
fi

# Derive a safe pool name / dedicated Unix username from the domain.
# useradd caps usernames at 32 chars on Debian/Ubuntu -- long domains get
# truncated and disambiguated with a short hash rather than silently
# colliding. Verified against real domain examples (including a
# compound-TLD subdomain over the 32-char limit) before relying on this.
sanitize_pool_name() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+//; s/-+$//'
}
sanitize_username() {
  local domain="$1" base
  base="php-$(sanitize_pool_name "$domain")"
  if [[ ${#base} -gt 32 ]]; then
    local hash
    hash=$(echo -n "$domain" | md5sum | cut -c1-8)
    base="${base:0:23}-${hash}"
  fi
  printf '%s' "$base"
}
POOL_NAME=$(sanitize_pool_name "$DOMAIN")
DOM_USER=$(sanitize_username "$DOMAIN")

VHOST_ROOT="/srv/vhosts/${DOMAIN}"
DOC_ROOT="${VHOST_ROOT}/public"
LOG_DIR="${VHOST_ROOT}/logs"
VHOST_CONF="/etc/apache2/sites-available/${DOMAIN}.conf"

echo
echo "Domain:       ${DOMAIN}"
[[ "$ADD_WWW" -eq 1 ]] && echo "WWW alias:    ${WWW_DOMAIN}"
echo "Document root: ${DOC_ROOT}"
echo "Vhost config:  ${VHOST_CONF}"
echo "Admin email:   ${ADMIN_EMAIL}"
echo

# ---------------------------------------------------------------------------
# 1. Make sure Apache + certbot are present (idempotent if already installed
#    -- e.g. by the LAMP/mail-server setup script)
# ---------------------------------------------------------------------------

export DEBIAN_FRONTEND=noninteractive
if ! command -v apache2ctl >/dev/null 2>&1; then
  apt-get update
  apt-get -y install apache2
fi
if ! command -v certbot >/dev/null 2>&1; then
  apt-get -y install certbot python3-certbot-apache
elif ! dpkg -l python3-certbot-apache >/dev/null 2>&1; then
  apt-get -y install python3-certbot-apache
fi
if ! command -v php >/dev/null 2>&1; then
  apt-get -y install php-fpm php-cli
fi

a2enmod rewrite ssl headers proxy_fcgi setenvif >/dev/null
systemctl enable --now apache2 >/dev/null

# Detect the actual PHP version/service name rather than hardcoding --
# matches the same approach used in setup-mail-lamp-server.sh, so both
# scripts stay correct together if the PHP version ever changes.
PHP_VERSION=$(php -r 'echo PHP_MAJOR_VERSION.".".PHP_MINOR_VERSION;')
PHP_FPM_SERVICE="php${PHP_VERSION}-fpm"
PHP_FPM_SOCK="/run/php/php${PHP_VERSION}-fpm-${POOL_NAME}.sock"
PHP_FPM_POOL_CONF="/etc/php/${PHP_VERSION}/fpm/pool.d/${POOL_NAME}.conf"
systemctl enable --now "${PHP_FPM_SERVICE}" >/dev/null

# ---------------------------------------------------------------------------
# 2. Directory structure
# ---------------------------------------------------------------------------

mkdir -p "${DOC_ROOT}" "${LOG_DIR}"

if [[ ! -f "${DOC_ROOT}/index.html" ]]; then
  cat > "${DOC_ROOT}/index.html" <<EOF
<!DOCTYPE html>
<html><head><title>${DOMAIN}</title></head>
<body><h1>${DOMAIN}</h1><p>Vhost provisioned -- replace this file.</p></body>
</html>
EOF
fi

# ---------------------------------------------------------------------------
# 3. Dedicated PHP-FPM pool (per-domain isolation)
# ---------------------------------------------------------------------------
#
# Each domain runs its own PHP-FPM pool as its own system user, instead of
# sharing the server's default pool -- so a compromised or misbehaving site
# can't read another site's files or touch its processes. Ownership below
# is <DOM_USER>:www-data so PHP (running as DOM_USER) has full read/write
# and Apache (www-data, serving static assets directly without going
# through PHP) can still read via the group.

if id "${DOM_USER}" >/dev/null 2>&1; then
  echo "Dedicated user ${DOM_USER} already exists -- reusing."
else
  useradd --system --no-create-home --shell /usr/sbin/nologin "${DOM_USER}"
  echo "Created dedicated system user ${DOM_USER} for ${DOMAIN}."
fi

chown -R "${DOM_USER}:www-data" "${VHOST_ROOT}"
find "${VHOST_ROOT}" -type d -exec chmod 750 "{}" \;
find "${VHOST_ROOT}" -type f -exec chmod 640 "{}" \;

cat > "${PHP_FPM_POOL_CONF}" <<EOF
[${POOL_NAME}]
user = ${DOM_USER}
group = ${DOM_USER}
listen = ${PHP_FPM_SOCK}
listen.owner = www-data
listen.group = www-data
listen.mode = 0660
pm = ondemand
pm.max_children = ${MAX_CHILDREN}
pm.process_idle_timeout = 10s
pm.max_requests = 500
php_admin_value[error_log] = ${LOG_DIR}/php-fpm-error.log
php_admin_flag[log_errors] = on
EOF

if ! php-fpm"${PHP_VERSION}" -t >/dev/null; then
  echo "ERROR: PHP-FPM pool config test failed -- not reloading. Check ${PHP_FPM_POOL_CONF}." >&2
  exit 1
fi
systemctl reload "${PHP_FPM_SERVICE}"

echo "Dedicated PHP-FPM pool ready: [${POOL_NAME}] user=${DOM_USER} socket=${PHP_FPM_SOCK} max_children=${MAX_CHILDREN}."

# ---------------------------------------------------------------------------
# 4. Apache vhost config (port 80 -- certbot adds the :443 block itself,
#    copying this block including the PHP handler override below)
# ---------------------------------------------------------------------------

cat > "${VHOST_CONF}" <<EOF
<VirtualHost *:80>
    ServerName ${DOMAIN}
$( [[ "$ADD_WWW" -eq 1 ]] && echo "    ServerAlias ${WWW_DOMAIN}" )
    ServerAdmin ${ADMIN_EMAIL}
    DocumentRoot ${DOC_ROOT}

    ErrorLog ${LOG_DIR}/error.log
    CustomLog ${LOG_DIR}/access.log combined

    # Routes this vhost's PHP requests to its own dedicated FPM pool,
    # overriding any global/shared PHP handler for just this domain.
    <FilesMatch "\.php\$">
        SetHandler "proxy:unix:${PHP_FPM_SOCK}|fcgi://localhost/"
    </FilesMatch>

    <Directory ${DOC_ROOT}>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
</VirtualHost>
EOF

a2ensite "${DOMAIN}.conf" >/dev/null

# Validate config before touching the running server.
if ! apache2ctl configtest; then
  echo "ERROR: Apache config test failed -- not reloading. Check ${VHOST_CONF}." >&2
  exit 1
fi
systemctl reload apache2

echo "Vhost created and enabled (HTTP only so far)."

# ---------------------------------------------------------------------------
# 5. Firewall -- idempotent, harmless if already allowed
# ---------------------------------------------------------------------------

if command -v ufw >/dev/null 2>&1; then
  ufw allow 80/tcp >/dev/null
  ufw allow 443/tcp >/dev/null
fi

# ---------------------------------------------------------------------------
# 6. Let's Encrypt
# ---------------------------------------------------------------------------

echo
CERTBOT_DOMAINS=(-d "${DOMAIN}")
if [[ "$ADD_WWW" -eq 1 ]]; then
  CERTBOT_DOMAINS+=(-d "${WWW_DOMAIN}")
fi

echo "Before requesting a certificate: confirm DNS for ${DOMAIN}$( [[ "$ADD_WWW" -eq 1 ]] && echo " AND ${WWW_DOMAIN}" ) already"
echo "resolves to this server's public IP, and that ports 80/443 are"
echo "reachable from the internet (check any upstream firewall/security"
echo "group too, not just this server's ufw)."
read -rp "Ready to request the certificate now? [y/N] " CERT_READY

CERTBOT_CMD_STR="certbot --apache ${CERTBOT_DOMAINS[*]} --agree-tos -m ${ADMIN_EMAIL} --redirect"

if [[ "${CERT_READY,,}" == "y" ]]; then
  if certbot --apache "${CERTBOT_DOMAINS[@]}" --non-interactive --agree-tos -m "${ADMIN_EMAIL}" --redirect; then
    echo "Certificate obtained and HTTPS vhost configured for ${DOMAIN}$( [[ "$ADD_WWW" -eq 1 ]] && echo " and ${WWW_DOMAIN}" )."
  else
    echo "WARNING: certbot failed. The site is still live over HTTP at"
    echo "http://${DOMAIN}/. Re-run once DNS/firewall are ready:"
    echo "  ${CERTBOT_CMD_STR}"
  fi
else
  echo "Skipped. Site is live over HTTP at http://${DOMAIN}/ for now."
  echo "Run this when ready:"
  echo "  ${CERTBOT_CMD_STR}"
fi

# ---------------------------------------------------------------------------
# 7. Summary
# ---------------------------------------------------------------------------

echo
echo "=============================================================="
echo "Domain:        ${DOMAIN}"
[[ "$ADD_WWW" -eq 1 ]] && echo "WWW alias:     ${WWW_DOMAIN} (same vhost, same cert)"
echo "Document root: ${DOC_ROOT}   (upload your site content here)"
echo "Logs:          ${LOG_DIR}/{access,error}.log"
echo "Vhost config:  ${VHOST_CONF}"
echo "Owner:         ${DOM_USER}:www-data, dirs 750 / files 640"
echo "PHP-FPM pool:  [${POOL_NAME}] user=${DOM_USER}, max_children=${MAX_CHILDREN}"
echo "               ${PHP_FPM_POOL_CONF}"
echo "               socket: ${PHP_FPM_SOCK}"
echo "=============================================================="
