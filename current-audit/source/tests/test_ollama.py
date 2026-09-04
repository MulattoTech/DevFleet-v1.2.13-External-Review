import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def test_profiles_and_scripts():
 p=json.loads((ROOT/'config/ollama-profiles.json').read_text());assert set(p)=={'stable-interactive','large-context','parallel-agents'};assert 'OLLAMA_NUM_PARALLEL' in p['parallel-agents']['Environment']
def test_no_invented_gpu_variables():
 t=(ROOT/'windows/Configure-Ollama.ps1').read_text();assert 'ROCM' not in t and 'HIP_' not in t and 'VULKAN' not in t
def test_shipping_config_does_not_hardcode_a_developer_ollama_host():assert '192.168.1.243:11434/v1' not in (ROOT/'config/devfleet.config.json').read_text()

def test_health_check_uses_openai_compatible_models_endpoint(monkeypatch):
 from devfleet import ollama
 class Response:
  status_code=200
  def raise_for_status(self):pass
  def json(self):return {'data':[{'id':'test-model'}]}
 seen=[]
 monkeypatch.setattr(ollama.httpx,'get',lambda url,timeout:(seen.append(url) or Response()))
 result=ollama.ollama_health()
 assert result['ok'] and result['model_available'] and seen[0].endswith('/v1/models')

def test_windows_configuration_prefers_magicdns_and_tailnet_scoped_firewall():
 t=(ROOT/'windows/Configure-Ollama.ps1').read_text()
 assert 'Self.DNSName' in t and '100.64.0.0/10' in t
 assert '0.0.0.0' in t and 'Wildcard Ollama binding is refused' in t
