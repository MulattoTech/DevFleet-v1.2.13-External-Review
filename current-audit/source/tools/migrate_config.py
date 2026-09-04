#!/usr/bin/env python3
from __future__ import annotations
import argparse,json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from devfleet.configuration import migrate_cluster_config,validate_cluster_config
p=argparse.ArgumentParser();p.add_argument('source',type=Path);p.add_argument('--output',type=Path);p.add_argument('--clean-install',action='store_true');p.add_argument('--write',action='store_true');a=p.parse_args();data=json.loads(a.source.read_text());out,changes=migrate_cluster_config(data,clean_install=a.clean_install);validate_cluster_config(out);print(json.dumps({'changes':changes,'configuration':out},indent=2));
if a.write:(a.output or a.source).write_text(json.dumps(out,indent=2)+'\n')
