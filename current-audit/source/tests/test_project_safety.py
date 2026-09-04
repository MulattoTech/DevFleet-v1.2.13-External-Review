from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def test_backup_before_quarantine_code_order():
 t=(ROOT/'app/devfleet/projects.py').read_text();section=t[t.index('def quarantine_project'):t.index('def list_quarantine')];assert section.index('backup_project')<section.index('project.rename')
def test_restore_canonical_quarantines_old_copy():
 t=(ROOT/'linux/devfleet-restore-project').read_text();assert 'transfer-replaced-' in t and '--canonical' in t
def test_docker_switch_never_migrates_or_deletes_store():
 t=(ROOT/'linux/devfleet-switch-docker-mode').read_text();assert 'Stores were not migrated or deleted' in t and 'docker system prune' not in t
