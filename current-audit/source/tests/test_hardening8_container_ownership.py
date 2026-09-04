import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from devfleet import containers, projects
from devfleet.core import SETTINGS


CONTAINER_ID = "a" * 64
PROJECT_ID = "12345678-1234-1234-1234-123456789abc"


def _project(tmp_path: Path, *, slug: str = "owned-app") -> dict:
    project = tmp_path / slug
    (project / ".devfleet").mkdir(parents=True)
    metadata = {
        "schema_version": 5,
        "managed_by": "devfleet",
        "project_id": PROJECT_ID,
        "slug": slug,
        "runtime_provider": "docker-compose",
        "runtime_id": "df_owned_app",
        "deployment_id": "deployment-123",
        "host_id": "test-node",
    }
    (project / ".devfleet/project.json").write_text(json.dumps(metadata), encoding="utf-8")
    return metadata


def _labels(**changes) -> dict[str, str]:
    labels = {
        "io.devfleet.managed-by": "devfleet",
        "io.devfleet.project-id": PROJECT_ID,
        "io.devfleet.project-slug": "owned-app",
        "io.devfleet.runtime-id": "df_owned_app",
        "io.devfleet.deployment-id": "deployment-123",
        "io.devfleet.host-id": "test-node",
        "com.docker.compose.project": "df_owned_app",
        "com.docker.compose.service": "app",
    }
    labels.update(changes)
    return labels


def _inspect(container_id: str = CONTAINER_ID, labels: dict | None = None, name: str = "/renamed-app") -> dict:
    return {"Id": container_id, "Name": name, "Config": {"Labels": labels if labels is not None else _labels()}}


def _runner(first: dict, second: dict | None = None):
    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args[:2] == ["docker", "inspect"]:
            value = first if len([c for c in calls if c[:2] == ["docker", "inspect"]]) == 1 else second
            if value is None:
                return SimpleNamespace(returncode=1, stdout="", stderr="No such container")
            return SimpleNamespace(returncode=0, stdout=json.dumps([value]), stderr="")
        return SimpleNamespace(returncode=0, stdout=args[-1], stderr="")

    return fake_run, calls


def _configure(monkeypatch, tmp_path):
    _project(tmp_path)
    monkeypatch.setattr(containers, "SETTINGS", replace(SETTINGS, workspaces=tmp_path, node_name="test-node", deployment_id="deployment-123"))


@pytest.mark.parametrize(
    "labels",
    [
        {},
        {"io.devfleet.managed-by": "devfleet"},
        _labels(**{"io.devfleet.project-id": "22345678-1234-1234-1234-123456789abc"}),
        _labels(**{"io.devfleet.deployment-id": "other-deployment"}),
        _labels(**{"com.docker.compose.project": "foreign-compose"}),
    ],
)
def test_foreign_partial_and_mismatched_containers_are_preserved(monkeypatch, tmp_path, labels):
    _configure(monkeypatch, tmp_path)
    fake_run, calls = _runner(_inspect(labels=labels))
    monkeypatch.setattr(containers, "run", fake_run)

    with pytest.raises(ValueError, match="ownership"):
        containers.container_action("foreign-db", "remove")

    assert not any(call[:2] == ["docker", "rm"] for call in calls)


@pytest.mark.parametrize(
    ("action", "docker_command"),
    [("start", "start"), ("stop", "stop"), ("restart", "restart"), ("pause", "pause"), ("unpause", "unpause"), ("remove", "rm")],
)
def test_every_legitimate_action_mutates_verified_immutable_id(monkeypatch, tmp_path, action, docker_command):
    _configure(monkeypatch, tmp_path)
    inspected = _inspect(name="/renamed-current-container")
    fake_run, calls = _runner(inspected, inspected)
    monkeypatch.setattr(containers, "run", fake_run)

    containers.container_action("old-visible-name", action)

    assert calls[-1] == ["docker", docker_command, CONTAINER_ID]
    assert not any(call[-1:] == ["old-visible-name"] and call[:2] != ["docker", "inspect"] for call in calls)


def test_deleted_recreated_same_name_fails_closed_before_mutation(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    fake_run, calls = _runner(_inspect(), None)
    monkeypatch.setattr(containers, "run", fake_run)

    with pytest.raises(ValueError, match="disappeared"):
        containers.container_action("owned-app-1", "stop")

    assert not any(call[:2] == ["docker", "stop"] for call in calls)


def test_id_name_substitution_fails_closed_before_mutation(monkeypatch, tmp_path):
    _configure(monkeypatch, tmp_path)
    fake_run, calls = _runner(_inspect(), _inspect(container_id="b" * 64))
    monkeypatch.setattr(containers, "run", fake_run)

    with pytest.raises(ValueError, match="identity changed"):
        containers.container_action("owned-app-1", "pause")

    assert not any(call[:2] == ["docker", "pause"] for call in calls)


def test_compose_override_binds_every_service_to_complete_current_identity(tmp_path):
    metadata = _project(tmp_path)
    project = tmp_path / "owned-app"
    compose = project / "compose.yaml"
    compose.write_text("services:\n  app:\n    image: example/app\n  db:\n    image: example/db\n", encoding="utf-8")

    override = projects._write_current_compose_ownership(project, compose, metadata)
    document = yaml.safe_load(override.read_text(encoding="utf-8"))

    expected = _labels()
    expected.pop("com.docker.compose.project")
    expected.pop("com.docker.compose.service")
    assert document == {"services": {"app": {"labels": expected}, "db": {"labels": expected}}}
    args = projects.compose_args(project, compose)
    assert str(override) in args
    assert args[-2:] == ["-p", "df_owned_app"]
