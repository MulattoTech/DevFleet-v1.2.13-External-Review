#!/usr/bin/env bash
set -Eeuo pipefail

PAYLOAD=${1:?payload path required}
export DEBIAN_FRONTEND=noninteractive
SECRETS_SOURCE=""
if [[ "${2:-}" == "--secrets-stdin" ]]; then
  SECRETS_SOURCE=$(mktemp /run/devfleet-node-secrets.XXXXXX)
  chmod 0600 "$SECRETS_SOURCE"
  trap 'rm -f -- "${SECRETS_SOURCE-}" "${DOCKER_KEY-}" "${TAILSCALE_KEY-}"; [[ -z "${NPM_TMP-}" ]] || rm -rf -- "$NPM_TMP"' EXIT
  cat >"$SECRETS_SOURCE"
else
  echo 'Refusing legacy plaintext node-secrets.json input; use --secrets-stdin.' >&2
  exit 64
fi
[[ -f "$SECRETS_SOURCE" ]] || { echo "missing secret input; use stdin transport" >&2; exit 2; }

JQ() { jq -r "$1" "$SECRETS_SOURCE"; }
NODE_NAME=$(JQ .NodeName); NODE_ROLE=$(JQ .NodeRole); FRIENDLY_NAME=$(JQ '.FriendlyName // .NodeName')
PORT=$(JQ .PortalPort); ADMIN_USER=$(JQ .AdminUser); ADMIN_PASSWORD=$(JQ .AdminPassword); API_TOKEN=$(JQ .ApiToken)
DEPLOYMENT_ID=$(JQ '.DeploymentId // ""'); NODE_ID=$(JQ .NodeId); COORDINATOR_NODE_ID=$(JQ '.CoordinatorNodeId // ""')
PROTOCOL_VERSION=$(JQ '.ProtocolVersion // 1'); OLLAMA_BASE=$(JQ .OllamaBaseUrl); OLLAMA_MODEL=$(JQ .OllamaModel)
OLLAMA_PROFILE=$(JQ '.OllamaProfile // "stable-interactive"'); DEVELOPMENT_PROFILE=$(JQ '.DevelopmentProfile // "strict"')
DOCKER_MODE=$(JQ '.DockerMode // "rootless"'); SHARED_CACHES=$(JQ '.EnableSharedCaches // false')
ANALYZER_CACHE=$(JQ '.EnableAnalyzerCache // true'); AUTO_CODEX=$(JQ '.AutoStartCodexPro // true')
ALLOW_TAILNET=$(JQ '.AllowTailnetPorts // false'); BACKUP_REBUILD=$(JQ '.BackupBeforeRebuild // false')
BACKUP_QUARANTINE=$(JQ '.BackupBeforeQuarantine // true'); BACKUP_INTERVAL=$(JQ '.BackupIntervalMinutes // 15')
PACKAGE_VERSION=$(JQ .PackageVersion)
[[ $PACKAGE_VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "invalid PackageVersion" >&2; exit 2; }
[[ -n "$NODE_ID" ]] || { echo "missing node identity" >&2; exit 3; }
[[ $DEVELOPMENT_PROFILE =~ ^(strict|balanced|fast)$ ]] || { echo "invalid development profile" >&2; exit 2; }
[[ $DOCKER_MODE =~ ^(rootless|rootful)$ ]] || { echo "invalid Docker mode" >&2; exit 2; }
[[ $PORT =~ ^[0-9]+$ && $PORT -ge 1024 && $PORT -le 65535 ]] || { echo "invalid portal port" >&2; exit 2; }
[[ $BACKUP_INTERVAL =~ ^[0-9]+$ && $BACKUP_INTERVAL -ge 1 && $BACKUP_INTERVAL -le 10080 ]] || { echo "invalid backup interval" >&2; exit 2; }
for value_name in NODE_NAME NODE_ROLE FRIENDLY_NAME ADMIN_USER ADMIN_PASSWORD API_TOKEN DEPLOYMENT_ID NODE_ID COORDINATOR_NODE_ID OLLAMA_BASE OLLAMA_MODEL OLLAMA_PROFILE; do
  value=${!value_name-}
  [[ $value != *$'\r'* && $value != *$'\n'* ]] || { echo "invalid newline in $value_name" >&2; exit 2; }
done

POLICY="$PAYLOAD/linux/dependency-policy.json"
[[ -f "$POLICY" ]] || { echo "missing dependency policy" >&2; exit 4; }
JQ_POLICY() { jq -r "$1" "$POLICY"; }
EXPECTED_TAILSCALE_FPR=$(JQ_POLICY .tailscale.signingKeySha256Fingerprint)
EXPECTED_DOCKER_FPR=$(JQ_POLICY .docker.signingKeySha256Fingerprint)
NODE_MIN_MAJOR=$(JQ_POLICY .node.minimumMajor)
NODE_CLI_VERSION=$(JQ_POLICY .node.devcontainersCliVersion)
NODE_CLI_INTEGRITY=$(JQ_POLICY .node.devcontainersCliIntegrity)
MUTABLE_PATH_CONTRACT="$PAYLOAD/app/systemd/mutable-paths.json"
[[ -f "$MUTABLE_PATH_CONTRACT" ]] || { echo "missing systemd mutable-path contract" >&2; exit 4; }
[[ $(jq -er ".schema_version" "$MUTABLE_PATH_CONTRACT") == 1 ]] || { echo "unsupported systemd mutable-path contract" >&2; exit 4; }
WORKSPACES=$(jq -er ".workspace" "$MUTABLE_PATH_CONTRACT")
QUARANTINE=$(jq -er ".quarantine" "$MUTABLE_PATH_CONTRACT")
TRANSACTION_ROOT=$(jq -er ".transaction_root" "$MUTABLE_PATH_CONTRACT")
for mutable_path in "$WORKSPACES" "$QUARANTINE" "$TRANSACTION_ROOT"; do
  [[ $mutable_path =~ ^/[A-Za-z0-9._/-]+$ && $mutable_path != *//* && $mutable_path != */../* && $mutable_path != */.. ]] || {
    echo "unsafe systemd mutable path contract" >&2
    exit 4
  }
done
[[ $WORKSPACES != "$QUARANTINE" ]] || { echo "systemd mutable paths must be distinct" >&2; exit 4; }
[[ $TRANSACTION_ROOT == "$WORKSPACES/.devfleet-transactions" ]] || { echo "restore transaction root must be a protected workspace sibling" >&2; exit 4; }

apt-get update
apt-get install -y ca-certificates curl gnupg jq unzip acl python3-venv python3-pip uidmap dbus-user-session slirp4netns fuse-overlayfs iptables ufw restic git openssl
install -m 0755 -d /etc/apt/keyrings
. /etc/os-release
ARCH=$(dpkg --print-architecture)

DOCKER_KEY=$(mktemp)
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "https://download.docker.com/linux/ubuntu/gpg" -o "$DOCKER_KEY"
OBSERVED_DOCKER_FPR=$(gpg --show-keys --with-colons "$DOCKER_KEY" | awk -F: '$1=="fpr"{print toupper($10);exit}')
[[ "$OBSERVED_DOCKER_FPR" == "$EXPECTED_DOCKER_FPR" ]] || { echo "Docker signing-key identity mismatch" >&2; exit 4; }
gpg --dearmor < "$DOCKER_KEY" > /etc/apt/keyrings/docker.gpg
rm -f "$DOCKER_KEY"
chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$ARCH signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $VERSION_CODENAME stable" > /etc/apt/sources.list.d/docker.list
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras

TAILSCALE_KEY=$(mktemp)
curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "https://pkgs.tailscale.com/stable/ubuntu/$VERSION_CODENAME.noarmor.gpg" -o "$TAILSCALE_KEY"
OBSERVED_TAILSCALE_FPR=$(gpg --show-keys --with-colons "$TAILSCALE_KEY" | awk -F: '$1=="fpr"{print toupper($10);exit}')
[[ "$OBSERVED_TAILSCALE_FPR" == "$EXPECTED_TAILSCALE_FPR" ]] || { echo "Tailscale signing-key identity mismatch" >&2; exit 4; }
install -m 0644 "$TAILSCALE_KEY" /usr/share/keyrings/tailscale-archive-keyring.gpg
rm -f "$TAILSCALE_KEY"
echo "deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/ubuntu $VERSION_CODENAME main" > /etc/apt/sources.list.d/tailscale.list
apt-get update
apt-get install -y tailscale
systemctl enable --now tailscaled

# Rootless Docker is the default and devrunner must not inherit the
# host-equivalent rootful docker-group privilege.  A deliberate rootful
# deployment requires an explicitly privileged helper/profile outside the
# normal DevFleet service account.
getent passwd devfleet-control >/dev/null || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin devfleet-control
getent passwd devfleet-backup >/dev/null || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin devfleet-backup
usermod --append --groups devrunner devfleet-control
gpasswd --delete devrunner sudo >/dev/null 2>&1 || true
rm -f /etc/sudoers.d/devfleet-devrunner
getent group docker >/dev/null || true
install -d -o root -g devfleet-control -m 0750 "$WORKSPACES" "$QUARANTINE"
install -d -o devfleet-control -g devfleet-control -m 0700 "$TRANSACTION_ROOT"
install -d -o devrunner -g devrunner -m 0700 /home/devrunner/.devfleet
install -d -o devfleet-control -g devfleet-control -m 0750 /var/lib/devfleet/runtime /var/lib/devfleet/migrations
install -d -o devrunner -g devrunner /var/cache/devfleet
setfacl -m u:devrunner:rx,u:devfleet-backup:rwx,d:u:devrunner:rwx,d:u:devfleet-backup:rwx "$WORKSPACES" "$QUARANTINE"
setfacl -m u:devfleet-backup:rwx /home/devrunner/.devfleet
setfacl -m u:devfleet-control:rwx,d:u:devfleet-control:rwx "$WORKSPACES" "$QUARANTINE"
for d in pip uv npm pnpm maven gradle nuget go-mod go-build cargo-registry cargo-git composer bundler buildkit; do install -d -o devrunner -g devrunner "/var/cache/devfleet/$d"; done
grep -q '^devrunner:' /etc/subuid || echo 'devrunner:100000:65536' >> /etc/subuid
grep -q '^devrunner:' /etc/subgid || echo 'devrunner:100000:65536' >> /etc/subgid
loginctl enable-linger devrunner
systemctl start "user@$(id -u devrunner).service" || true
install -d -o devrunner -g devrunner /home/devrunner/.config/environment.d
printf 'PATH=/usr/bin:/bin:/usr/local/bin\n' > /home/devrunner/.config/environment.d/docker.conf
chown -R devrunner:devrunner /home/devrunner/.config /home/devrunner/.devfleet*

uid=$(id -u devrunner)
if [[ ! -f /home/devrunner/.config/systemd/user/docker.service ]]; then
  sudo -u devrunner env HOME=/home/devrunner XDG_RUNTIME_DIR=/run/user/$uid DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus dockerd-rootless-setuptool.sh install --force
fi
if [[ $DOCKER_MODE == rootless ]]; then
  systemctl disable --now docker.service docker.socket containerd.service 2>/dev/null || true
  sudo -u devrunner env HOME=/home/devrunner XDG_RUNTIME_DIR=/run/user/$uid DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$uid/bus systemctl --user enable --now docker
else
  echo 'Rootful Docker mode requires a separately provisioned privileged helper; bootstrap refuses to grant devrunner docker-group access.' >&2
  exit 5
fi
if [[ -d "/run/user/$uid" ]]; then
  setfacl -m u:devfleet-control:rx "/run/user/$uid"
  [[ -S "/run/user/$uid/docker.sock" ]] && setfacl -m u:devfleet-control:rw "/run/user/$uid/docker.sock" || true
fi

if ! command -v node >/dev/null; then apt-get install -y nodejs npm; fi
NODE_MAJOR=$(node --version | sed -E 's/^v([0-9]+).*/\1/')
[[ $NODE_MAJOR =~ ^[0-9]+$ && $NODE_MAJOR -ge $NODE_MIN_MAJOR ]] || { echo "Ubuntu signed Node.js package is below the supported major version." >&2; exit 4; }
NPM_TMP=$(mktemp -d)
npm pack --ignore-scripts --pack-destination "$NPM_TMP" "@devcontainers/cli@$NODE_CLI_VERSION" >/dev/null
NPM_TARBALL=$(find "$NPM_TMP" -maxdepth 1 -type f -name '*.tgz' -print -quit)
NPM_INTEGRITY="sha512-$(openssl dgst -sha512 -binary "$NPM_TARBALL" | base64 -w0)"
[[ "$NPM_INTEGRITY" == "$NODE_CLI_INTEGRITY" ]] || { echo "@devcontainers/cli artifact integrity mismatch" >&2; exit 4; }
npm install --global --ignore-scripts "$NPM_TARBALL"

rm -rf /opt/devfleet
install -d /opt/devfleet
cp -a "$PAYLOAD/app/." /opt/devfleet/
install -m 0644 "$PAYLOAD/VERSION" /opt/devfleet/VERSION
cp -a "$PAYLOAD/templates" /opt/devfleet/project-templates
[[ -f /opt/devfleet/requirements-hashed.txt ]] || { echo "missing hash-bound Python dependency lock" >&2; exit 4; }
python3 -m venv /opt/devfleet/venv
/opt/devfleet/venv/bin/pip install --no-deps --require-hashes -r /opt/devfleet/requirements-hashed.txt
VENV_ORIGIN=$(/opt/devfleet/venv/bin/python - <<'PY'
import importlib.metadata as metadata
import sys
from pathlib import Path

prefix = Path(sys.prefix).resolve()
if Path(sys.base_prefix).resolve() == prefix:
    raise SystemExit("DevFleet venv is not isolated from the system interpreter")
for distribution in metadata.distributions():
    location = Path(distribution.locate_file("")).resolve()
    if prefix not in location.parents and location != prefix:
        raise SystemExit(f"runtime distribution escaped the DevFleet venv: {distribution.metadata['Name']}")
print(prefix)
PY
)
[[ "$VENV_ORIGIN" == "/opt/devfleet/venv" ]] || { echo "runtime package origin is outside the DevFleet venv" >&2; exit 4; }
chown -R root:root /opt/devfleet

install -d -m 0750 -o root -g devfleet-control /etc/devfleet
jq -n --arg schema "2" --arg version "$PACKAGE_VERSION" --arg node "$NODE_NAME" --arg role "$NODE_ROLE" --arg friendly "$FRIENDLY_NAME" --arg deployment "$DEPLOYMENT_ID" --arg id "$NODE_ID" --arg coordinator "$COORDINATOR_NODE_ID" --arg protocol "$PROTOCOL_VERSION" --arg port "$PORT" --arg ollamaBase "$OLLAMA_BASE" --arg ollamaModel "$OLLAMA_MODEL" --arg ollamaProfile "$OLLAMA_PROFILE" --arg profile "$DEVELOPMENT_PROFILE" --arg docker "$DOCKER_MODE" --arg tailnetCidr "100.64.0.0/10" --arg workspaces "$WORKSPACES" --arg quarantine "$QUARANTINE" --argjson shared "$SHARED_CACHES" --argjson analyzer "$ANALYZER_CACHE" --argjson auto "$AUTO_CODEX" --argjson tailnet "$ALLOW_TAILNET" --argjson rebuild "$BACKUP_REBUILD" --argjson quarantineEnabled "$BACKUP_QUARANTINE" --argjson portNumber "$PORT" '{schema_version:($schema|tonumber),package_version:$version,node_name:$node,node_role:$role,friendly_name:$friendly,deployment_id:$deployment,node_id:$id,coordinator_node_id:(if $coordinator == "" then "" else $coordinator end),protocol_version:($protocol|tonumber),portal_port:$portNumber,workspaces:$workspaces,quarantine:$quarantine,peer_file:"/etc/devfleet/peer.json",runtime_root:"/var/lib/devfleet/runtime",cache_root:"/var/cache/devfleet",ollama_base_url:$ollamaBase,ollama_model:$ollamaModel,ollama_profile:$ollamaProfile,development_profile:$profile,docker_mode:$docker,enable_shared_caches:$shared,enable_analyzer_cache:$analyzer,auto_start_codexpro:$auto,allow_tailnet_ports:$tailnet,require_tailscale:true,tailnet_cidr:$tailnetCidr,public_binding_allowed:false,backup_before_rebuild:$rebuild,backup_before_quarantine:$quarantineEnabled}' > /etc/devfleet/config.json
jq -n --arg deployment "$DEPLOYMENT_ID" --arg id "$NODE_ID" --arg node "$NODE_NAME" --arg role "$NODE_ROLE" --arg coordinator "$COORDINATOR_NODE_ID" --arg protocol "$PROTOCOL_VERSION" '{schema_version:1,deployment_id:$deployment,node_id:$id,node_name:$node,node_role:$role,coordinator_node_id:$coordinator,protocol_version:($protocol|tonumber),registration_state:(if $role == "primary" then "coordinator" else "awaiting-primary-join" end)}' > /etc/devfleet/node-identity.json
if [[ -n "$DEPLOYMENT_ID" ]]; then
  install -d -o devfleet-control -g devfleet-control -m 0750 /var/lib/devfleet/runtime
  jq -n --arg deployment "$DEPLOYMENT_ID" --arg id "$NODE_ID" --arg node "$NODE_NAME" --arg friendly "$FRIENDLY_NAME" --arg role "$NODE_ROLE" --arg protocol "$PROTOCOL_VERSION" '{schema_version:1,deployment_id:$deployment,nodes:[{deployment_id:$deployment,node_id:$id,node_name:$node,friendly_name:$friendly,node_role:$role,capabilities:["primary-control","compute","backup"],coordinator_node_id:null,protocol_version:($protocol|tonumber),registration_state:"registered",connectivity:"online"}]}' > /var/lib/devfleet/runtime/node-registry.json
  chown devfleet-control:devfleet-control /var/lib/devfleet/runtime/node-registry.json; chmod 0640 /var/lib/devfleet/runtime/node-registry.json
fi
SECRETS_ENV_TMP=$(mktemp /etc/devfleet/.secrets.env.XXXXXX)
python3 - "$SECRETS_ENV_TMP" "$SECRETS_SOURCE" <<'PY'
import json, sys
from pathlib import Path

def encode(value: str) -> str:
    if any(char in value for char in ('\x00', '\r', '\n')):
        raise SystemExit('secret contains a forbidden control character')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('$', '\\$').replace('`', '\\`') + '"'

rows = {
    'DEVFLEET_ADMIN_USER': '',
    'DEVFLEET_ADMIN_PASSWORD': '',
    'DEVFLEET_API_TOKEN': '',
}
source = json.loads(Path(sys.argv[2]).read_text(encoding='utf-8'))
rows['DEVFLEET_ADMIN_USER'] = str(source.get('AdminUser', ''))
rows['DEVFLEET_ADMIN_PASSWORD'] = str(source.get('AdminPassword', ''))
rows['DEVFLEET_API_TOKEN'] = str(source.get('ApiToken', ''))
target = Path(sys.argv[1])
target.write_text(''.join(f'{key}={encode(value)}\n' for key, value in rows.items()), encoding='utf-8', newline='\n')
target.chmod(0o640)
target.replace('/etc/devfleet/secrets.env')
PY
rm -f -- "$SECRETS_SOURCE"
[[ -f /etc/devfleet/peer.json ]] || printf '{}\n' > /etc/devfleet/peer.json
chown root:devfleet-control /etc/devfleet/*; chmod 0640 /etc/devfleet/*
chown root:devfleet-control /etc/devfleet/secrets.env; chmod 0640 /etc/devfleet/secrets.env
for f in devfleet-health devfleet-purge-quarantine devfleet-backup devfleet-restore-project devfleet-user-repair devfleet-docker-mode-report; do install -m 0755 "$PAYLOAD/linux/$f" "/usr/local/bin/$f"; done
for f in devfleet-repair devfleet-safe-update devfleet-configure-backup devfleet-set-peer devfleet-switch-docker-mode devfleet-register-node devfleet-join-deployment; do install -m 0755 "$PAYLOAD/linux/$f" "/usr/local/sbin/$f"; done
cp /opt/devfleet/systemd/devfleet.service /etc/systemd/system/devfleet.service
sed -i "s|__PORT__|$PORT|g;s|__DEVRUNNER_UID__|$uid|g;s|__WORKSPACES__|$WORKSPACES|g;s|__QUARANTINE__|$QUARANTINE|g;s|__TRANSACTION_ROOT__|$TRANSACTION_ROOT|g" /etc/systemd/system/devfleet.service
cp /opt/devfleet/systemd/devfleet-backup.service /etc/systemd/system/
sed -i "s|__WORKSPACES__|$WORKSPACES|g;s|__QUARANTINE__|$QUARANTINE|g" /etc/systemd/system/devfleet-backup.service
cp /opt/devfleet/systemd/devfleet-backup.timer /etc/systemd/system/
sed -i "s/__BACKUP_INTERVAL_MINUTES__/$BACKUP_INTERVAL/g" /etc/systemd/system/devfleet-backup.timer
systemctl daemon-reload; systemctl enable --now devfleet.service devfleet-backup.timer
# Add only the exact DevFleet-owned rules. Do not change the host's global
# default policy or activate UFW on behalf of an unrelated administrator.
ufw allow in on tailscale0 to any port 22 proto tcp comment 'DevFleet-owned tailscale SSH'
ufw allow in on tailscale0 to any port "$PORT" proto tcp comment 'DevFleet-owned tailscale Portal'
echo "DevFleet compute bootstrap complete: $NODE_NAME ($NODE_ROLE, $DEVELOPMENT_PROFILE, $DOCKER_MODE)"
