import json
from pathlib import Path
from devfleet.language_policy import TEMPLATES,recommend_template
ROOT=Path(__file__).resolve().parents[1]
CORE={'generic','python','python-fastapi','node','typescript-node','typescript-next','go-service','dotnet-service','java-spring','rust-service'}
def test_legacy_and_new_templates_exist():
 assert {'generic','python','node'}<=set(TEMPLATES);assert len(TEMPLATES)==20
 for name in TEMPLATES:
  d=ROOT/'templates'/name;assert (d/'compose.yaml').is_file();assert (d/'.devcontainer/devcontainer.json').is_file();assert (d/'.devfleet/codexpro-bootstrap.sh').is_file();assert (d/'README.md').is_file();assert (d/'docs/architecture.md').is_file()
def test_core_metadata_commands():
 for name in CORE:
  data=json.loads((ROOT/'templates'/name/'.devfleet/template.json').read_text())
  for key in ('bootstrap_command','format_command','lint_command','test_command','health_command'):assert data[key]
def test_recommendations():assert recommend_template('python','fastapi')=='python-fastapi' and recommend_template('go')=='go-service'
def test_language_metadata_documented():
 for name in CORE:
  assert 'Language:' in (ROOT/'templates'/name/'README.md').read_text();assert 'Rationale:' in (ROOT/'templates'/name/'docs/architecture.md').read_text()
