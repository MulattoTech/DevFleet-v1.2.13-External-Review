import json,shutil,subprocess,uuid
from pathlib import Path
from devfleet import projects, workspace_archives
from devfleet.core import SETTINGS

ROOT=Path(__file__).resolve().parents[1]

def git(cwd,*args):
 return subprocess.run(['git',*args],cwd=cwd,text=True,capture_output=True,check=True)

def test_git_worktree_project_creation(monkeypatch):
 source=SETTINGS.workspaces/f'source-{uuid.uuid4().hex[:8]}'
 dest_slug=f'worktree-{uuid.uuid4().hex[:8]}'
 dest=SETTINGS.workspaces/dest_slug
 source.mkdir(parents=True)
 try:
  git(source,'init');git(source,'config','user.name','DevFleet Test');git(source,'config','user.email','devfleet@example.invalid')
  (source/'seed.txt').write_text('seed');git(source,'add','.');git(source,'commit','-m','seed');git(source,'branch','feature')
  monkeypatch.setattr(projects,'TEMPLATE_ROOT',ROOT/'templates')
  meta=projects.create_project(dest_slug,template='generic',worktree_source=source.name,worktree_branch='feature',use_ollama=False)
  assert meta['worktree'] and (dest/'.git').is_file() and json.loads((dest/'.devfleet/project.json').read_text())['identity']==dest_slug
 finally:
  if dest.exists():subprocess.run(['git','worktree','remove','--force',str(dest)],cwd=source,check=False)
  shutil.rmtree(source,ignore_errors=True);shutil.rmtree(dest,ignore_errors=True)

def test_v1_project_without_schema2_metadata_remains_discoverable(tmp_path):
 project=tmp_path/'legacy-project';project.mkdir()
 meta=projects.load_meta(project)
 assert meta['slug']=='legacy-project' and meta['template']=='existing'
 assert meta['runtime_provider']=='docker-compose' and meta['resource_profile']=='standard'
 assert meta['resource_limits']['memory_gb']==4.0 and meta['resource_limits']['cpus']==2.0

def test_canonical_vault_restore_quarantines_existing_v1_copy():
 text=(ROOT/'linux/devfleet-restore-project').read_text()
 assert 'transfer-replaced-' in text and 'mv "$target" "$quarantine"' in text

def test_workspace_restore_failure_restores_previous_canonical(tmp_path,monkeypatch):
 slug='rollback-fixture'
 source=tmp_path/slug;source.mkdir();(source/'old.txt').write_text('old');(source/'.devfleet').mkdir();(source/'.devfleet/project.json').write_text(json.dumps({'slug':slug,'schema_version':2}))
 archive=tmp_path/'backup.tar.gz'
 workspace_archives.create_workspace_archive(source,slug,archive)
 (source/'old.txt').write_text('original-must-survive')
 original=workspace_archives.inspect_workspace
 calls={'count':0}
 def fail_after_promotion(path):
  calls['count']+=1
  if calls['count'] == 1:
   raise RuntimeError('injected post-promotion failure')
  return original(path)
 monkeypatch.setattr(workspace_archives,'inspect_workspace',fail_after_promotion)
 try:
  workspace_archives.restore_workspace_archive(archive,source,slug)
 except RuntimeError:
  pass
 else:
  raise AssertionError('fault injection did not fail')
 assert (source/'old.txt').read_text() == 'original-must-survive'
