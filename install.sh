#!/usr/bin/env bash
set -Eeuo pipefail

readonly REPOSITORY="wanbnn/ntslock"
readonly INSTALL_ROOT="${INLOCK_INSTALL_DIR:-/opt/inlock}"
readonly CONFIG_ROOT="${INLOCK_CONFIG_DIR:-/etc/inlock}"
readonly DATA_ROOT="${INLOCK_DATA_DIR:-/var/lib/inlock}"
readonly SERVICE_FILE="/etc/systemd/system/inlock.service"
readonly SOURCE_REF="${INLOCK_VERSION:-main}"

log() { printf '\033[1;35m→\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31mErro:\033[0m %s\n' "$*" >&2; exit 1; }

if [[ "${EUID}" -ne 0 ]]; then
  fail "execute como root: curl -fsSL https://raw.githubusercontent.com/${REPOSITORY}/main/install.sh | sudo bash"
fi

if [[ ! -r /etc/os-release ]]; then
  fail "sistema não suportado; este instalador requer Debian ou Ubuntu"
fi

# shellcheck disable=SC1091
source /etc/os-release
case "${ID:-}" in
  debian|ubuntu) ;;
  *) fail "distribuição '${ID:-desconhecida}' não suportada; use Debian ou Ubuntu" ;;
esac

command -v apt-get >/dev/null || fail "apt-get não encontrado"
log "Instalando dependências do sistema"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq ca-certificates curl openssl python3 python3-venv >/dev/null

python3 - <<'PY' || fail "Python 3.11+ é necessário; atualize o Python da distribuição"
import sys
raise SystemExit(0 if sys.version_info >= (3, 11) else 1)
PY

archive_dir="$(mktemp -d /tmp/inlock-install.XXXXXX)"
cleanup() { rm -rf -- "${archive_dir}"; }
trap cleanup EXIT

log "Baixando Inlock (${SOURCE_REF})"
curl -fsSL --retry 3 \
  "https://github.com/${REPOSITORY}/archive/refs/heads/${SOURCE_REF}.tar.gz" \
  -o "${archive_dir}/inlock.tar.gz" || \
curl -fsSL --retry 3 \
  "https://github.com/${REPOSITORY}/archive/refs/tags/${SOURCE_REF}.tar.gz" \
  -o "${archive_dir}/inlock.tar.gz"
mkdir "${archive_dir}/source"
tar -xzf "${archive_dir}/inlock.tar.gz" --strip-components=1 -C "${archive_dir}/source"

log "Preparando ambiente isolado"
install -d -m 0755 "${INSTALL_ROOT}"
python3 -m venv "${INSTALL_ROOT}/venv"
"${INSTALL_ROOT}/venv/bin/python" -m pip install --quiet --upgrade pip
"${INSTALL_ROOT}/venv/bin/python" -m pip install --quiet "${archive_dir}/source"

if ! id inlock >/dev/null 2>&1; then
  useradd --system --home-dir "${DATA_ROOT}" --shell /usr/sbin/nologin inlock
fi
install -d -o inlock -g inlock -m 0750 "${DATA_ROOT}"
install -d -o root -g inlock -m 0750 "${CONFIG_ROOT}"

if getent group docker >/dev/null 2>&1; then
  usermod -aG docker inlock
  docker_group_line="SupplementaryGroups=docker"
else
  docker_group_line=""
fi

env_file="${CONFIG_ROOT}/inlock.env"
if [[ ! -f "${env_file}" ]]; then
  admin_token="$(openssl rand -hex 32)"
  secret_key="$(openssl rand -hex 48)"
  umask 0077
  {
    printf 'INLOCK_DATA_DIR=%s\n' "${DATA_ROOT}"
    printf 'INLOCK_ADMIN_TOKEN=%s\n' "${admin_token}"
    printf 'INLOCK_SECRET_KEY=%s\n' "${secret_key}"
    printf 'INLOCK_PUBLIC_URL=http://localhost:14900\n'
    printf 'INLOCK_SECURE_COOKIES=false\n'
    printf 'INLOCK_TRUSTED_PROXIES=127.0.0.1/32,::1/128\n'
  } > "${env_file}"
  chown root:inlock "${env_file}"
  chmod 0640 "${env_file}"
else
  admin_token="$(sed -n 's/^INLOCK_ADMIN_TOKEN=//p' "${env_file}" | head -n 1)"
fi

log "Configurando serviço systemd"
cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=Inlock application firewall
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=inlock
Group=inlock
${docker_group_line}
EnvironmentFile=${env_file}
ExecStart=${INSTALL_ROOT}/venv/bin/uvicorn inlock.main:app --host 0.0.0.0 --port 14900 --proxy-headers --forwarded-allow-ips 127.0.0.1
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_ROOT}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now inlock.service >/dev/null

for _ in {1..20}; do
  if curl -fsS http://127.0.0.1:14900/health >/dev/null 2>&1; then
    printf '\n\033[1;32mInlock instalado com sucesso.\033[0m\n'
    printf 'Painel: http://SEU-IP:14900\n'
    printf 'Token administrativo: %s\n' "${admin_token}"
    printf 'Configuração: %s\n' "${env_file}"
    printf 'Serviço: systemctl status inlock\n'
    exit 0
  fi
  sleep 1
done

systemctl status inlock.service --no-pager || true
fail "o serviço foi instalado, mas não respondeu em http://127.0.0.1:14900/health"
