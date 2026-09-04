import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def test_schema_and_names():
 c=json.loads((ROOT/'config/devfleet.config.json').read_text());assert c['SchemaVersion']==2 and c['Primary']['InstanceName']=='devfleet-primary' and c['Primary']['FriendlyName']=='CodexDevVM'
def test_required_docs():
 for n in range(14):assert list((ROOT/'docs').glob(f'{n:02d}-*.md'))
def test_original_ids_preserved():assert all((ROOT/'templates'/x).is_dir() for x in ('generic','python','node'))
def test_no_baseline_file_removed():
 baseline=(ROOT/'BASELINE-v1.0.0-FILES.txt').read_text().splitlines();assert all((ROOT/x).exists() for x in baseline)
