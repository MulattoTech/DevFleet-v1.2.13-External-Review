#!/usr/bin/env bash
set -Eeuo pipefail
PAYLOAD=${1:?payload path required}
export DEBIAN_FRONTEND=noninteractive
SECRETS="$PAYLOAD/vault-secrets.json"
POLICY="$PAYLOAD/linux/dependency-policy.json"
[[ -f "$POLICY" ]] || { echo 'Missing canonical dependency policy.' >&2; exit 4; }
PORT=$(jq -r .VaultPort "$SECRETS")
REST_USER=$(jq -r .RestUser "$SECRETS")
REST_PASSWORD=$(jq -r .RestPassword "$SECRETS")
RESTIC_PASSWORD=$(jq -r .ResticPassword "$SECRETS")
REST_SERVER_TAG=$(jq -r .restServer.tag "$POLICY")
REST_SERVER_SHA256=$(jq -r .restServer.sha256 "$POLICY")
CLUSTER=$(jq -r .ClusterName "$SECRETS")
DEPLOYMENT_ID=$(jq -r .DeploymentId "$SECRETS")
NODE_ID=$(jq -r .NodeId "$SECRETS")
NODE_NAME=$(jq -r .NodeName "$SECRETS")
[[ ( -z $DEPLOYMENT_ID || $DEPLOYMENT_ID =~ ^[0-9a-fA-F-]{36}$ ) && $NODE_ID =~ ^[0-9a-fA-F-]{36}$ && -n $NODE_NAME ]] || { echo 'Vault immutable identity is incomplete.' >&2; exit 4; }
[[ "$PORT" =~ ^[0-9]{1,5}$ ]] && (( PORT >= 1 && PORT <= 65535 )) || { echo 'Vault port is invalid.' >&2; exit 4; }
[[ "$REST_USER" =~ ^[A-Za-z0-9._-]+$ ]] || { echo 'Vault REST user contains unsupported characters.' >&2; exit 4; }
[[ "$CLUSTER" =~ ^[A-Za-z0-9._-]+$ ]] || { echo 'Vault cluster name contains unsupported characters.' >&2; exit 4; }
apt-get update
apt-get install -y curl ca-certificates jq apache2-utils ufw restic
if ! command -v tailscale >/dev/null; then echo 'Tailscale must be installed from the verified signed repository before Vault provisioning.' >&2; exit 4; fi
TAILSCALE_IP=$(tailscale ip -4 2>/dev/null | awk 'NR==1 {print $1}')
[[ "$TAILSCALE_IP" =~ ^100\.([0-9]{1,3}\.){2}[0-9]{1,3}$ ]] || { echo 'Vault refuses to start without an authenticated Tailscale IPv4 address.' >&2; exit 4; }
systemctl enable --now tailscaled

# Resolve current rest-server/restic release binaries from the official GitHub API.
install_github_binary(){
  local repo=$1 asset_regex=$2 binary=$3
  local url
  local tag=${REST_SERVER_TAG:?REST_SERVER_TAG must be supplied by the pinned dependency policy}
  local digest=${REST_SERVER_SHA256:?REST_SERVER_SHA256 must be supplied by the pinned dependency policy}
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "Invalid pinned release tag" >&2; exit 3; }
  [[ "$digest" =~ ^[0-9a-fA-F]{64}$ ]] || { echo "Invalid pinned release digest" >&2; exit 3; }
  local asset="rest-server_${tag#v}_linux_amd64.tar.gz"
  local url="https://github.com/$repo/releases/download/$tag/$asset"
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' RETURN
  curl --fail --silent --show-error --location --proto '=https' --tlsv1.2 "$url" -o "$tmp/pkg"
  printf '%s  %s\n' "$digest" "$tmp/pkg" | sha256sum --check --status || { echo "Pinned digest mismatch for $repo/$asset" >&2; exit 3; }
  tar -C "$tmp" -xzf "$tmp/pkg"; find "$tmp" -type f -name "$binary" -exec install -m 0755 {} "/usr/local/bin/$binary" \; -quit
}
[[ "$REST_SERVER_TAG" != "null" && "$REST_SERVER_SHA256" != "null" ]] || { echo 'Pinned rest-server policy is incomplete.' >&2; exit 4; }
install_github_binary restic/rest-server 'unused' rest-server

install -d -o resticvault -g resticvault -m 0700 /srv/restic
install -d -o root -g resticvault -m 0750 /etc/rest-server
install -d -o root -g root -m 0700 /root/.config/devfleet
printf '%s\n' "$REST_PASSWORD" | htpasswd -iBc /etc/rest-server/htpasswd "$REST_USER"
chown root:resticvault /etc/rest-server/htpasswd
chmod 0640 /etc/rest-server/htpasswd
export DEVFLEET_RESTIC_REPOSITORY="/srv/restic/$REST_USER/$CLUSTER"
export DEVFLEET_RESTIC_PASSWORD="$RESTIC_PASSWORD"
python3 - <<'PY'
import os

def systemd_quote(value: str) -> str:
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n') + '"'

with open('/etc/rest-server/vault-admin.env', 'w', encoding='utf-8') as fh:
    fh.write('RESTIC_REPOSITORY=' + systemd_quote(os.environ['DEVFLEET_RESTIC_REPOSITORY']) + '\n')
    fh.write('RESTIC_PASSWORD=' + systemd_quote(os.environ['DEVFLEET_RESTIC_PASSWORD']) + '\n')
PY
chmod 0600 /etc/rest-server/vault-admin.env
cat >/etc/systemd/system/rest-server.service <<EOF
[Unit]
Description=DevFleet append-only restic REST server
After=network-online.target tailscaled.service
Wants=network-online.target
[Service]
User=resticvault
Group=resticvault
ExecStart=/usr/local/bin/rest-server --path /srv/restic --listen $TAILSCALE_IP:$PORT --append-only --private-repos --htpasswd-file /etc/rest-server/htpasswd
Restart=on-failure
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/srv/restic
ProtectHome=true
[Install]
WantedBy=multi-user.target
EOF
install -m 0755 "$PAYLOAD/linux/devfleet-vault-health" /usr/local/sbin/devfleet-vault-health
install -m 0755 "$PAYLOAD/linux/devfleet-vault-maintenance" /usr/local/sbin/devfleet-vault-maintenance
systemctl daemon-reload
systemctl enable --now rest-server
ip link show tailscale0 >/dev/null 2>&1 || { echo 'Tailscale interface is unavailable; refusing broad Vault firewall rules.' >&2; exit 4; }
# Add only exact DevFleet-owned rules. Preserve unrelated administrator policy
# and do not enable or reset the host firewall here.
ufw allow in on tailscale0 to any port 22 proto tcp comment 'DevFleet-owned tailscale SSH'
ufw allow in on tailscale0 to any port "$PORT" proto tcp comment 'DevFleet-owned tailscale Vault'
cat >/usr/local/sbin/devfleet-vault-firewall-refresh <<'FIREWALL_REFRESH'
#!/usr/bin/env bash
set -Eeuo pipefail
ip link show tailscale0 >/dev/null 2>&1 || exit 4
ufw allow in on tailscale0 to any port 22 proto tcp comment 'DevFleet-owned tailscale SSH'
ufw allow in on tailscale0 to any port __VAULT_PORT__ proto tcp comment 'DevFleet-owned tailscale Vault'
FIREWALL_REFRESH
sed -i "s/__VAULT_PORT__/$PORT/g" /usr/local/sbin/devfleet-vault-firewall-refresh
chmod 0755 /usr/local/sbin/devfleet-vault-firewall-refresh
cat >/etc/systemd/system/devfleet-vault-firewall-refresh.service <<'FIREWALL_UNIT'
[Unit]
Description=Refresh DevFleet Vault private-network firewall rules
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/devfleet-vault-firewall-refresh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
FIREWALL_UNIT
systemctl daemon-reload
systemctl enable --now devfleet-vault-firewall-refresh.service
jq -n --arg cluster "$CLUSTER" --arg user "$REST_USER" --argjson port "$PORT" '{cluster:$cluster,port:$port,user:$user}' > /etc/devfleet-vault-public.json
jq -n --arg deployment "$DEPLOYMENT_ID" --arg id "$NODE_ID" --arg node "$NODE_NAME" '{schema_version:1,deployment_id:$deployment,node_id:$id,node_name:$node,node_role:"vault"}' > /etc/devfleet-vault-identity.json
chmod 0600 /etc/devfleet-vault-public.json
chmod 0600 /etc/devfleet-vault-identity.json
echo 'DevFleet vault bootstrap complete.'
