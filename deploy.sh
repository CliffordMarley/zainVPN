#!/usr/bin/env bash
# Deploys or updates the zainVPN coordinator on this server with Docker:
# pulls the latest code, builds the image and (re)starts the container.
#
#   bash deploy.sh
#
# Safe to re-run any time. Settings live in .env (created on the first run).
set -euo pipefail

IMAGE=zainvpn-coordinator:latest
CONTAINER=zainvpn-coordinator
VOLUME=zainvpn-data

cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -t 1 ]; then
  BOLD=$'\e[1m' DIM=$'\e[2m' RED=$'\e[31m' GREEN=$'\e[32m' YELLOW=$'\e[33m' BLUE=$'\e[34m' RESET=$'\e[0m'
else
  BOLD='' DIM='' RED='' GREEN='' YELLOW='' BLUE='' RESET=''
fi

step() { printf '\n%s==> %s%s\n' "$BLUE$BOLD" "$*" "$RESET"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '%sWARNING:%s %s\n' "$YELLOW$BOLD" "$RESET" "$*" >&2; }
die() { printf '\n%sERROR:%s %s\n' "$RED$BOLD" "$RESET" "$*" >&2; exit 1; }

is_root() { [ "$(id -u)" -eq 0 ]; }

as_root() {
  if is_root; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    die "This step needs root: re-run as root or install sudo."
  fi
}

# --- Docker -------------------------------------------------------------------

install_docker() {
  command -v docker >/dev/null 2>&1 && return
  step "Installing Docker"
  [ -r /etc/os-release ] || die "Can't detect the Linux distribution (no /etc/os-release). Install Docker yourself and re-run."
  local id version_id like
  id=$(. /etc/os-release && printf '%s' "${ID:-}")
  version_id=$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")
  like=$(. /etc/os-release && printf '%s' "${ID_LIKE:-}")

  case "$id" in
    amzn)
      if [ "$version_id" = 2 ]; then
        if command -v amazon-linux-extras >/dev/null 2>&1; then
          as_root amazon-linux-extras install -y docker
        else
          as_root yum install -y docker
        fi
      else
        as_root dnf install -y docker
      fi
      ;;
    ubuntu | debian)
      as_root apt-get update
      as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io
      ;;
    *)
      case " $like " in
        *" debian "* | *" ubuntu "*)
          as_root apt-get update
          as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y docker.io
          ;;
        *) die "Unsupported distribution '$id'. Install Docker (https://docs.docker.com/engine/install/) and re-run this script." ;;
      esac
      ;;
  esac
  as_root systemctl enable --now docker
  if ! is_root; then
    as_root usermod -aG docker "$(id -un)" || true
    info "Added $(id -un) to the docker group (applies from your next login; using sudo until then)."
  fi
}

DOCKER=(docker)

# Picks plain "docker" or "sudo docker" depending on access to the socket.
select_docker() {
  if docker info >/dev/null 2>&1; then
    DOCKER=(docker)
    return
  fi
  if ! is_root && command -v sudo >/dev/null 2>&1 && sudo docker info >/dev/null 2>&1; then
    DOCKER=(sudo docker)
    return
  fi
  info "Docker daemon isn't responding; starting it."
  as_root systemctl enable --now docker || true
  if docker info >/dev/null 2>&1; then
    DOCKER=(docker)
  elif ! is_root && sudo docker info >/dev/null 2>&1; then
    DOCKER=(sudo docker)
  else
    die "Can't talk to the Docker daemon. Check 'systemctl status docker'."
  fi
}

docker_() { "${DOCKER[@]}" "$@"; }

# The coordinator asks for 4 MiB UDP socket buffers so relay bursts aren't
# dropped, but Linux silently caps them at net.core.rmem_max/wmem_max (often
# ~208 KiB). Raise the caps now and on every boot. Failures only warn.
tune_udp_buffers() {
  local want=4194304 key cur changed="" conf=()
  if ! is_root && ! command -v sudo >/dev/null 2>&1; then return; fi
  for key in rmem_max wmem_max; do
    cur=$(cat "/proc/sys/net/core/$key" 2>/dev/null || echo "$want")
    if [ "$cur" -lt "$want" ]; then
      if as_root sysctl -q -w "net.core.$key=$want" >/dev/null 2>&1; then
        changed=1
        cur=$want
      else
        warn "Couldn't raise net.core.$key to $want; UDP relay buffers stay at $cur bytes."
      fi
    fi
    if [ "$cur" -ge "$want" ]; then
      conf+=("net.core.$key = $cur") # never persists a lower value than now
    fi
  done
  if [ -n "$changed" ] && [ -d /etc/sysctl.d ]; then
    printf '%s\n' "# Written by zainVPN deploy.sh: room for the coordinator's 4 MiB UDP buffers." "${conf[@]}" |
      as_root tee /etc/sysctl.d/90-zainvpn.conf >/dev/null || true
    info "Raised the kernel's UDP buffer limits to $want bytes (/etc/sysctl.d/90-zainvpn.conf)."
  fi
}

# --- Code -----------------------------------------------------------------------

# Runs git as the checkout's owner, so "sudo bash deploy.sh" works too
# (avoids git's "dubious ownership" check and uses the owner's credentials).
git_() {
  local owner
  owner=$(stat -c %U . 2>/dev/null || echo root)
  if is_root && [ "$owner" != root ] && command -v sudo >/dev/null 2>&1; then
    sudo -u "$owner" git "$@"
  else
    git "$@"
  fi
}

update_code() {
  step "Updating code"
  if ! command -v git >/dev/null 2>&1 || [ ! -e .git ]; then
    warn "Not a git checkout; deploying the files as they are."
    return
  fi
  if git_ rev-parse --abbrev-ref --symbolic-full-name '@{u}' >/dev/null 2>&1; then
    local before
    before=$(cksum <deploy.sh)
    git_ pull --ff-only || die "git pull failed (local changes or diverged history?). Resolve it and re-run."
    if [ "$(cksum <deploy.sh)" != "$before" ] && [ -z "${ZAINVPN_DEPLOY_REEXEC:-}" ]; then
      info "deploy.sh itself was updated; running the new version."
      export ZAINVPN_DEPLOY_REEXEC=1
      exec bash deploy.sh
    fi
  else
    warn "This branch has no upstream; skipping git pull."
  fi
  info "Deploying commit: $(git_ log -1 --format='%h %s (%cr)')"
}

build_version() {
  local v=""
  if command -v git >/dev/null 2>&1 && [ -e .git ]; then
    v=$(git_ describe --tags --always --dirty 2>/dev/null || true)
  fi
  printf '%s' "${v:-$(date -u +%Y%m%d-%H%M%S)}"
}

# --- Settings -------------------------------------------------------------------

NEW_PASSWORD=""

random_password() {
  local pw=""
  if command -v openssl >/dev/null 2>&1; then
    pw=$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9')
  fi
  if [ "${#pw}" -lt 24 ]; then
    pw=$(head -c 96 /dev/urandom | base64 | tr -dc 'A-Za-z0-9')
  fi
  printf '%s' "${pw:0:24}"
}

ensure_env() {
  step "Checking settings"
  if [ -f .env ]; then
    info "Using existing .env"
  else
    NEW_PASSWORD=$(random_password)
    [ "${#NEW_PASSWORD}" -ge 20 ] || die "Couldn't generate a random password."
    (
      umask 077
      cat >.env <<EOF
# zainVPN coordinator settings, created by deploy.sh. See .env.example.
ZAINVPN_LISTEN=:29814
ZAINVPN_HTTP=:21958
ZAINVPN_ADMIN_PASSWORD=$NEW_PASSWORD
EOF
    )
    chmod 600 .env
    info "Created .env with a random admin password (shown at the end)."
  fi
  local pw
  pw=$(env_get ZAINVPN_ADMIN_PASSWORD)
  if [ -z "$pw" ]; then
    warn "ZAINVPN_ADMIN_PASSWORD is empty in .env: the dashboard stays disabled."
  elif [ "${#pw}" -lt 12 ] || [[ "$pw" == change-me* ]]; then
    warn "ZAINVPN_ADMIN_PASSWORD in .env is weak; use 12+ random characters."
  fi
}

# Prints the last value of KEY from .env (empty if unset).
env_get() {
  { grep -E "^[[:space:]]*$1=" .env 2>/dev/null || true; } | tail -n 1 | cut -d= -f2- | tr -d '\r'
}

env_has() { grep -qE "^[[:space:]]*$1=" .env 2>/dev/null; }

port_of() { printf '%s' "${1##*:}"; }

# --- Container ------------------------------------------------------------------

build_image() {
  local version
  version=$(build_version)
  step "Building image $IMAGE (version $version)"
  docker_ build --pull -t "$IMAGE" --build-arg VERSION="$version" .
}

restart_container() {
  step "Restarting container"
  docker_ stop -t 10 "$CONTAINER" >/dev/null 2>&1 || true
  docker_ rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker_ run -d \
    --name "$CONTAINER" \
    --restart unless-stopped \
    --network host \
    --env-file .env \
    -v "$VOLUME:/data" \
    --log-opt max-size=10m --log-opt max-file=3 \
    "$IMAGE" >/dev/null
  docker_ image prune -f >/dev/null
  info "Started $CONTAINER"
}

container_running() {
  [ "$(docker_ inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null)" = true ]
}

http_ok() {
  if command -v curl >/dev/null 2>&1; then
    curl -fsS -m 2 -o /dev/null "$1" 2>/dev/null
  elif command -v wget >/dev/null 2>&1; then
    wget -q -T 2 -O /dev/null "$1"
  else
    docker_ exec "$CONTAINER" wget -q -T 2 -O /dev/null "$1"
  fi
}

fail_with_logs() {
  printf '\n%sLast log lines:%s\n' "$BOLD" "$RESET" >&2
  docker_ logs --tail 50 "$CONTAINER" >&2 || true
  die "$1"
}

wait_healthy() {
  step "Waiting for the coordinator"
  if [ -z "$HTTP_ADDR" ] || [ "$HTTP_ADDR" = off ]; then
    sleep 3
    container_running || fail_with_logs "The container stopped right after starting."
    info "Running (dashboard disabled, so no health check)."
    return
  fi
  local host url
  host=${HTTP_ADDR%:*}
  case "$host" in "" | 0.0.0.0 | "[::]" | "::") host=127.0.0.1 ;; esac
  url="http://$host:$(port_of "$HTTP_ADDR")/healthz"
  for _ in $(seq 1 30); do
    if http_ok "$url"; then
      info "Healthy ($url)"
      return
    fi
    container_running || break
    sleep 1
  done
  fail_with_logs "The coordinator didn't become healthy at $url."
}

# --- Summary --------------------------------------------------------------------

public_ip() {
  local token="" ip="" imds=http://169.254.169.254/latest
  if command -v curl >/dev/null 2>&1; then
    token=$(curl -fsS -m 2 -X PUT "$imds/api/token" -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' 2>/dev/null || true)
    if [ -n "$token" ]; then ip=$(curl -fsS -m 2 -H "X-aws-ec2-metadata-token: $token" "$imds/meta-data/public-ipv4" 2>/dev/null || true); fi
  elif command -v wget >/dev/null 2>&1; then
    token=$(wget -q -T 2 -O - --method=PUT --header='X-aws-ec2-metadata-token-ttl-seconds: 60' "$imds/api/token" 2>/dev/null || true)
    if [ -n "$token" ]; then ip=$(wget -q -T 2 -O - --header="X-aws-ec2-metadata-token: $token" "$imds/meta-data/public-ipv4" 2>/dev/null || true); fi
  fi
  if [[ "$ip" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
    printf '%s' "$ip"
  else
    printf '<your-server-ip>'
  fi
}

summary() {
  local ip control dash_port sudo_prefix=""
  ip=$(public_ip)
  control=$(port_of "$LISTEN_ADDR")
  if [ "${DOCKER[0]}" = sudo ]; then sudo_prefix="sudo "; fi

  printf '\n%s%szainVPN coordinator is running.%s\n\n' "$GREEN" "$BOLD" "$RESET"
  printf '  %-22s %s%s:%s%s\n' "Coordinator address" "$BOLD" "$ip" "$control" "$RESET"
  printf '  %-22s %s\n' "" "${DIM}use it as: build.ps1 -Server $ip:$control${RESET}"
  if [ -n "$HTTP_ADDR" ] && [ "$HTTP_ADDR" != off ]; then
    dash_port=$(port_of "$HTTP_ADDR")
    printf '  %-22s %shttp://%s:%s%s\n' "Admin dashboard" "$BOLD" "$ip" "$dash_port" "$RESET"
  else
    printf '  %-22s disabled (ZAINVPN_HTTP)\n' "Admin dashboard"
  fi
  if [ -n "$NEW_PASSWORD" ]; then
    printf '\n  %s%sAdmin password: %s%s\n' "$YELLOW" "$BOLD" "$NEW_PASSWORD" "$RESET"
    printf '  %s\n' "Save it now; it won't be shown again (it's stored in .env)."
  else
    printf '  %-22s %s\n' "Admin password" "ZAINVPN_ADMIN_PASSWORD in .env"
  fi

  printf '\n%sAWS security group, inbound rules:%s\n' "$BOLD" "$RESET"
  printf '  %-12s %-6s %-16s %s\n' "Custom TCP" "$control" "0.0.0.0/0" "clients' control connection"
  printf '  %-12s %-6s %-16s %s\n' "Custom UDP" "$control" "0.0.0.0/0" "peer traffic and hole punching"
  if [ -n "${dash_port:-}" ]; then
    printf '  %-12s %-6s %-16s %s\n' "Custom TCP" "$dash_port" "0.0.0.0/0" "dashboard + installer download (admin pages need the password)"
  fi
  printf '  %s\n' "${DIM}If the server also runs a firewall (ufw, firewalld), open the same ports there.${RESET}"

  printf '\n%sUseful commands:%s\n' "$BOLD" "$RESET"
  printf '  %-44s %s\n' "${sudo_prefix}docker logs -f $CONTAINER" "follow the logs"
  printf '  %-44s %s\n' "bash deploy.sh" "update to the latest commit"
  printf '  %-44s %s\n' "${sudo_prefix}docker restart $CONTAINER" "restart without rebuilding"
  printf '\n'
}

# --- Main -----------------------------------------------------------------------

main() {
  [ -f Dockerfile ] || die "Run this from the zainVPN repository (no Dockerfile in $(pwd))."
  install_docker
  select_docker
  update_code
  ensure_env
  tune_udp_buffers

  LISTEN_ADDR=$(env_get ZAINVPN_LISTEN)
  LISTEN_ADDR=${LISTEN_ADDR:-:29814}
  if env_has ZAINVPN_HTTP; then
    HTTP_ADDR=$(env_get ZAINVPN_HTTP)
  else
    HTTP_ADDR=:21958
  fi

  build_image
  restart_container
  wait_healthy
  summary
}

main "$@"
exit
