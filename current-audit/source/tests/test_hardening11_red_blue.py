from __future__ import annotations

import json
import stat
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from devfleet import auth, containers, core
from devfleet.analyzer import analyze_project, has_blockers
from devfleet.core import SETTINGS


def _compose_project(tmp_path: Path, body: str) -> Path:
    project = tmp_path / "red-compose"
    project.mkdir()
    (project / "compose.yaml").write_text(body, encoding="utf-8")
    return project


@pytest.mark.parametrize("profile", ["strict", "balanced", "fast"])
@pytest.mark.parametrize(
    ("body", "code"),
    [
        ("services:\n  app:\n    privileged: true\n", "docker.privileged"),
        ("services:\n  app:\n    use_api_socket: true\n", "compose.use-api-socket"),
        ("services:\n  app:\n    volumes_from: [base]\n", "compose.volumes-from"),
        ("services:\n  app:\n    provider: {type: evil}\n", "compose.provider"),
        ("services:\n  app:\n    post_start: [{command: whoami, privileged: true}]\n", "compose.post-start"),
        ("services:\n  app:\n    future_execution_field: true\n", "compose.unknown-field"),
    ],
)
def test_compose_red_attack_corpus_blocks_every_profile(tmp_path: Path, profile: str, body: str, code: str) -> None:
    findings = analyze_project(_compose_project(tmp_path, body), profile, force=True)
    assert has_blockers(findings)
    assert code in {item["code"] for item in findings}


def test_compose_extends_nested_and_host_root_bind_are_not_effective_model_gaps(tmp_path: Path) -> None:
    project = _compose_project(
        tmp_path,
        """services:
  app:
    extends:
      file: middle.yml
      service: middle
""",
    )
    (project / "middle.yml").write_text(
        """services:
  middle:
    extends:
      file: evil.yml
      service: inherited
""",
        encoding="utf-8",
    )
    (project / "evil.yml").write_text(
        """services:
  inherited:
    privileged: true
    network_mode: host
    volumes: ["/:/host"]
""",
        encoding="utf-8",
    )
    findings = analyze_project(project, "strict", force=True)
    codes = {item["code"] for item in findings}
    assert has_blockers(findings)
    assert "compose.extends" in codes
    assert "docker.privileged" not in codes or "compose.extends" in codes


def test_compose_include_escape_and_symlink_escape_are_blocked(tmp_path: Path) -> None:
    project = _compose_project(tmp_path, "include:\n  - ../outside.yml\nservices: {}\n")
    findings = analyze_project(project, "strict", force=True)
    assert has_blockers(findings)
    assert "compose.include" in {item["code"] for item in findings}
    assert "compose.path-reference" in {item["code"] for item in findings}

    outside = tmp_path / "outside.yml"
    outside.write_text("services: {}\n", encoding="utf-8")
    link = project / "evil.yml"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("symbolic-link creation unavailable")
    (project / "compose.yaml").write_text("""services:
  app:
    extends: {file: evil.yml, service: x}
""", encoding="utf-8")
    findings = analyze_project(project, "strict", force=True)
    assert {"compose.path-escape", "project.symlink-escape"} & {item["code"] for item in findings}


@pytest.mark.parametrize("argument", [
    "--privileged", "--network=host", "--network", "host", "--pid=host", "--pid", "host",
    "--ipc", "--uts", "--userns=host", "--volume=/:/host", "-v", "/:/host", "--mount", "type=bind,src=/,dst=/host",
    "--device=/dev/kvm", "--cap-add=SYS_ADMIN", "--security-opt", "seccomp=unconfined", "--env-file=/tmp/x",
])
@pytest.mark.parametrize("profile", ["strict", "balanced", "fast"])
def test_devcontainer_structured_runargs_attack_corpus_blocks(tmp_path: Path, argument: str, profile: str) -> None:
    project = tmp_path / "devcontainer"
    (project / ".devcontainer").mkdir(parents=True)
    (project / ".devcontainer/devcontainer.json").write_text(json.dumps({"image": "alpine:3.20", "runArgs": [argument]}), encoding="utf-8")
    findings = analyze_project(project, profile, force=True)
    assert has_blockers(findings)
    assert "devcontainer.run-args" in {item["code"] for item in findings} or "devcontainer.run-args-dangerous" in {item["code"] for item in findings}


def test_devcontainer_jsonc_known_good_and_features_fail_closed(tmp_path: Path) -> None:
    project = tmp_path / "devcontainer"
    (project / ".devcontainer").mkdir(parents=True)
    config = """{
      // JSONC comments are part of the Dev Container format.
      "name": "safe",
      "image": "alpine:3.20",
      "remoteUser": "nobody",
    }
    """
    path = project / ".devcontainer/devcontainer.json"
    path.write_text(config, encoding="utf-8")
    findings = analyze_project(project, "strict", force=True)
    assert "devcontainer.json.invalid" not in {item["code"] for item in findings}
    assert not has_blockers(findings)
    path.write_text('{"image":"alpine:3.20","features":{"ghcr.io/devcontainers/features/node:1":{}}}', encoding="utf-8")
    findings = analyze_project(project, "strict", force=True)
    assert "devcontainer.features-unsupported" in {item["code"] for item in findings}


def test_analyzer_cache_invalidates_when_only_transitive_compose_file_changes(tmp_path: Path) -> None:
    project = _compose_project(tmp_path, """services:
  app:
    extends: {file: evil.yml, service: inherited}
""")
    inherited = project / "evil.yml"
    inherited.write_text("services:\n  inherited:\n    image: alpine:3.20\n", encoding="utf-8")
    analyze_project(project, "strict", force=True)
    cache = project / ".devfleet/runtime/analyzer-cache.json"
    first = cache.read_text(encoding="utf-8")
    inherited.write_text("services:\n  inherited:\n    privileged: true\n", encoding="utf-8")
    analyze_project(project, "strict")
    second = cache.read_text(encoding="utf-8")
    assert first != second


CONTAINER_ID = "a" * 64
FOREIGN_ID = "b" * 64
PROJECT_ID = "12345678-1234-1234-1234-123456789abc"


def _owned_project(tmp_path: Path) -> None:
    project = tmp_path / "owned-app"
    (project / ".devfleet").mkdir(parents=True)
    (project / ".devfleet/project.json").write_text(json.dumps({
        "managed_by": "devfleet", "project_id": PROJECT_ID, "slug": "owned-app", "runtime_provider": "docker-compose",
        "runtime_id": "df_owned_app", "deployment_id": "deployment-123", "host_id": "test-node",
    }), encoding="utf-8")


def _owned_labels() -> dict[str, str]:
    return {
        "io.devfleet.managed-by": "devfleet", "io.devfleet.project-id": PROJECT_ID, "io.devfleet.project-slug": "owned-app",
        "io.devfleet.runtime-id": "df_owned_app", "io.devfleet.deployment-id": "deployment-123", "io.devfleet.host-id": "test-node",
        "com.docker.compose.project": "df_owned_app", "com.docker.compose.service": "app",
    }


def _inspect(container_id: str, labels: dict[str, str], name: str) -> dict:
    return {"Id": container_id, "Name": f"/{name}", "Config": {"Labels": labels}, "Secret": "only-for-authorized-read"}


def test_container_reads_filter_foreign_and_authorize_inspect_logs(monkeypatch, tmp_path: Path) -> None:
    _owned_project(tmp_path)
    monkeypatch.setattr(containers, "SETTINGS", replace(SETTINGS, workspaces=tmp_path, node_name="test-node", deployment_id="deployment-123"))
    owned = _inspect(CONTAINER_ID, _owned_labels(), "owned-app")
    foreign = _inspect(FOREIGN_ID, {"io.devfleet.managed-by": "other"}, "foreign")
    calls: list[list[str]] = []

    def fake_run(args, **_kwargs):
        calls.append(list(args))
        if args[:2] == ["docker", "ps"]:
            return SimpleNamespace(returncode=0, stdout="\n".join(json.dumps(x) for x in [
                {"ID": CONTAINER_ID, "Names": "owned-app", "Image": "safe", "State": "running"},
                {"ID": FOREIGN_ID, "Names": "foreign", "Image": "evil", "State": "running"},
            ]), stderr="")
        if args[:2] == ["docker", "stats"]:
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        if args[:2] == ["docker", "inspect"]:
            value = owned if args[-1] in {CONTAINER_ID, "owned-app"} else foreign
            return SimpleNamespace(returncode=0, stdout=json.dumps([value]), stderr="")
        if args[:2] == ["docker", "logs"]:
            return SimpleNamespace(returncode=0, stdout="owned log", stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(containers, "run", fake_run)
    listed = containers.list_containers()
    assert [item["id"] for item in listed] == [CONTAINER_ID]
    assert containers.inspect_container("owned-app")["Id"] == CONTAINER_ID
    assert containers.container_logs("owned-app") == "owned log"
    with pytest.raises(ValueError, match="ownership"):
        containers.inspect_container("foreign")
    with pytest.raises(ValueError, match="ownership"):
        containers.container_logs("foreign")
    assert not any(call[:2] == ["docker", "logs"] and call[-1] == FOREIGN_ID for call in calls)


def test_container_same_name_replacement_and_partial_labels_fail_closed(monkeypatch, tmp_path: Path) -> None:
    _owned_project(tmp_path)
    monkeypatch.setattr(containers, "SETTINGS", replace(SETTINGS, workspaces=tmp_path, node_name="test-node", deployment_id="deployment-123"))
    calls = {"inspect": 0}

    def fake_run(args, **_kwargs):
        if args[:2] == ["docker", "inspect"]:
            calls["inspect"] += 1
            value = _inspect(CONTAINER_ID, _owned_labels(), "same-name") if calls["inspect"] == 1 else _inspect(FOREIGN_ID, {"io.devfleet.managed-by": "other"}, "same-name")
            return SimpleNamespace(returncode=0, stdout=json.dumps([value]), stderr="")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(containers, "run", fake_run)
    with pytest.raises(ValueError, match="ownership"):
        containers.inspect_container("same-name")


def test_rootless_endpoint_preserves_explicit_two_user_socket(monkeypatch) -> None:
    settings = replace(SETTINGS, docker_mode="rootless", docker_host="unix:///run/user/1000/docker.sock", docker_owner_uid=1000)
    monkeypatch.setattr(core, "SETTINGS", settings)
    monkeypatch.setattr(core.os, "lstat", lambda _path: SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=1000))
    captured = {}

    def fake_subprocess(_cmd, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(core.subprocess, "run", fake_subprocess)
    monkeypatch.setenv("DOCKER_HOST", "unix:///run/user/1000/docker.sock")
    core.run(["docker", "info"], check=False)
    assert captured["env"]["DOCKER_HOST"] == "unix:///run/user/1000/docker.sock"


@pytest.mark.parametrize("host", ["unix:///run/user/4242/docker.sock", "tcp://127.0.0.1:2375", "", "unix:///run/user/1000/not-docker.sock"])
def test_rootless_endpoint_rejects_wrong_identity_or_shape(monkeypatch, host: str) -> None:
    settings = replace(SETTINGS, docker_mode="rootless", docker_host=host, docker_owner_uid=1000)
    monkeypatch.setattr(core, "SETTINGS", settings)
    monkeypatch.setattr(core.os, "lstat", lambda _path: SimpleNamespace(st_mode=stat.S_IFSOCK, st_uid=1000))
    with pytest.raises(RuntimeError):
        core._validate_rootless_docker_host(host)


def test_rootless_deployment_contract_is_explicit() -> None:
    unit = Path("source/app/systemd/devfleet.service").read_text(encoding="utf-8")
    core_text = Path("source/app/devfleet/core.py").read_text(encoding="utf-8")
    assert "SupplementaryGroups=devrunner" in unit
    assert "Environment=DOCKER_HOST=unix:///run/user/__DEVRUNNER_UID__/docker.sock" in unit
    assert "os.getuid" not in core_text
    assert "_validate_rootless_docker_host" in core_text


def test_credential_comparison_count_is_constant(monkeypatch) -> None:
    monkeypatch.setattr(auth, "SETTINGS", replace(SETTINGS, admin_user="alice", admin_password="secret"))
    original = auth.hmac.compare_digest
    counts: list[int] = []
    calls = []

    def counted(left, right):
        calls.append((left, right))
        return original(left, right)

    monkeypatch.setattr(auth.hmac, "compare_digest", counted)
    for user, password in [("wrong", "wrong"), ("alice", "wrong"), ("wrong", "secret"), ("alice", "secret"), ("", "")]:
        calls.clear()
        auth.valid_credentials(user, password, source="red-blue-test")
        counts.append(len(calls))
    assert counts == [2, 2, 2, 2, 2]
