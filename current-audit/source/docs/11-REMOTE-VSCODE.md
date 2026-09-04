# Remote VS Code

The laptop is the primary client and does not require Docker Desktop for main workloads. `Configure-SSH.ps1` creates `CodexDevVM` and failover aliases using the generated Ed25519 key and Tailscale IP. `Configure-DockerContext.ps1` creates Docker-over-SSH only; it never opens TCP 2375. `Configure-VSCode.ps1` installs real Remote SSH/Dev Containers and language extension groups and supplies exclusions for dependencies, caches, models, generated artifacts, and `.ai-bridge/local-agent`.

Typical commands:

```powershell
ssh CodexDevVM
code --remote ssh-remote+CodexDevVM /home/devrunner/workspaces/<project>
docker --context Codexdevvm ps
```


## Extension placement

Install Remote SSH and Remote Explorer on Windows. When VS Code opens `CodexDevVM`, allow language servers, linters, debuggers, and Dev Containers support to install in the remote environment when VS Code recommends it; UI-only extensions may remain local. The supplied extension lists are grouped so Python/web/enterprise/systems tooling can be added only for the projects that need it. The reference settings are copied for review rather than overwriting an existing personal `settings.json`.
