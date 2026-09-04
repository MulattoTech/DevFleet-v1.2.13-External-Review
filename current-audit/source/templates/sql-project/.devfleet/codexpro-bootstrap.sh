#!/usr/bin/env bash
set -Eeuo pipefail
root=$(pwd -P)
workspace_root=${DEVFLEET_WORKSPACES_ROOT:-/workspaces}
[[ "$workspace_root" == /* && "$workspace_root" != */ ]] || { echo 'DEVFLEET_WORKSPACES_ROOT must be an absolute directory.' >&2; exit 2; }
[[ "$root" == "$workspace_root"/* ]] || { echo "CodexPro root must be under $workspace_root." >&2; exit 2; }
project_rel=${root#"$workspace_root"/}
[[ "$project_rel" != */* && -n "$project_rel" ]] || { echo 'CodexPro root must identify one project.' >&2; exit 2; }
runtime="$root/.devfleet/runtime"; bridge="$root/.ai-bridge/local-agent"; mkdir -p "$runtime" "$bridge/logs"
log="$runtime/codexpro-bootstrap.log"; status="$runtime/codexpro-status.json"; now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
health_url=${DEVFLEET_CODEXPRO_HEALTH_URL:-http://127.0.0.1:8787/healthz}
write_status(){ python3 - "$status" "$1" "$2" "$now" <<'PY2'
import json,sys
p,state,msg,now=sys.argv[1:];open(p,'w').write(json.dumps({'state':state,'healthy':state=='healthy','message':msg,'updated_at':now},indent=2)+'\n')
PY2
}
if DEVFLEET_CODEXPRO_HEALTH_URL="$health_url" python3 - <<'PY2' >/dev/null 2>&1
import urllib.request
import os
urllib.request.urlopen(os.environ['DEVFLEET_CODEXPRO_HEALTH_URL'],timeout=2)
PY2
then write_status healthy 'CodexPro loopback health endpoint is responding.'; echo 'CodexPro is already healthy.' | tee -a "$log"; exit 0; fi
if ! command -v codexpro >/dev/null 2>&1; then write_status unavailable 'CodexPro executable is not installed in this project container.'; echo 'CodexPro is unavailable. Install it using your verified private/local installation source, then rerun this hook. No credential is embedded.' | tee -a "$log"; exit 0; fi
export CODEXPRO_TOOL_CARDS=${CODEXPRO_TOOL_CARDS:-1}
( codexpro start >>"$log" 2>&1 & )
sleep 2
if DEVFLEET_CODEXPRO_HEALTH_URL="$health_url" python3 - <<'PY2' >/dev/null 2>&1
import urllib.request
import os
urllib.request.urlopen(os.environ['DEVFLEET_CODEXPRO_HEALTH_URL'],timeout=2)
PY2
then write_status healthy 'CodexPro started successfully.'; exit 0; fi
write_status authorization-required 'CodexPro is installed but not healthy; inspect the log for authorization or configuration requirements.'
echo "CodexPro did not become healthy. Review $log"; exit 0
