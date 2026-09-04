from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def test_ssh_safety():
 t=(ROOT/'client/ssh-config.example').read_text();assert 'Host CodexDevVM' in t and 'ForwardAgent no' in t and 'IdentitiesOnly yes' in t
def test_docker_context_uses_ssh_not_tcp():
 t=(ROOT/'client/Configure-DockerContext.ps1').read_text();assert 'ssh://devrunner@' in t and '2375' not in t
def test_vscode_exclusions():
 t=(ROOT/'client/vscode-settings.jsonc').read_text();assert 'node_modules' in t and '.ai-bridge/local-agent' in t and 'safetensors' in t
