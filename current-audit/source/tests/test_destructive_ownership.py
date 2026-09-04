from __future__ import annotations

import json
from pathlib import Path

import pytest

from devfleet import projects


def _workspace(tmp_path: Path, slug: str = "owned-project", metadata: dict | None = None) -> Path:
    project = tmp_path / slug
    (project / ".devfleet").mkdir(parents=True)
    if metadata is not None:
        (project / ".devfleet" / "project.json").write_text(json.dumps(metadata), encoding="utf-8")
    return project


def _valid(slug: str = "owned-project") -> dict:
    return {
        "schema_version": 3,
        "managed_by": "devfleet",
        "project_id": "12345678-1234-1234-1234-123456789abc",
        "slug": slug,
        "runtime_provider": "docker-compose",
        "host_id": "test-node",
    }


@pytest.mark.parametrize(
    "metadata",
    [
        None,
        {"schema_version": 3, "managed_by": "devfleet", "slug": "owned-project"},
        {"schema_version": 3, "managed_by": "devfleet", "slug": "wrong", "project_id": "12345678-1234-1234-1234-123456789abc", "runtime_provider": "docker-compose", "host_id": "test-node"},
        {"schema_version": 3, "managed_by": "someone-else", "slug": "owned-project", "project_id": "12345678-1234-1234-1234-123456789abc", "runtime_provider": "docker-compose", "host_id": "test-node"},
        {"schema_version": 3, "managed_by": "devfleet", "slug": "owned-project", "project_id": "12345678-1234-1234-1234-123456789abc", "runtime_provider": "docker-compose"},
    ],
)
def test_ambiguous_project_identity_is_denied_for_mutation(tmp_path: Path, metadata):
    project = _workspace(tmp_path, metadata=metadata)
    with pytest.raises(ValueError, match="Mutation denied"):
        projects.load_authoritative_project_identity_for_mutation(project)


def test_malformed_metadata_is_denied_without_catalog_synthesis(tmp_path: Path):
    project = _workspace(tmp_path, metadata=None)
    metadata_file = project / ".devfleet" / "project.json"
    metadata_file.write_text("{not-json", encoding="utf-8")
    catalog = projects.load_project_for_catalog(project)
    assert catalog["slug"] == project.name
    with pytest.raises(ValueError, match="malformed"):
        projects.load_authoritative_project_identity_for_mutation(project)


def test_valid_legacy_migration_record_is_authoritative(tmp_path: Path):
    project = _workspace(tmp_path, metadata=_valid())
    identity = projects.load_authoritative_project_identity_for_mutation(project)
    assert identity["managed_by"] == "devfleet"
    assert identity["project_id"]
