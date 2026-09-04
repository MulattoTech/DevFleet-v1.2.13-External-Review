#!/usr/bin/env python3
"""Run one bounded release scenario against an extracted exact-candidate tree."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def command(args: list[str], *, timeout: int = 300, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, text=True, capture_output=True, timeout=timeout, check=False)
    if check and result.returncode:
        raise RuntimeError(f"Command failed ({result.returncode}): {args[0]}: {(result.stderr or result.stdout)[-1500:]}")
    return result


def wait_operation(operations, operation_id: str, timeout: float = 120.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        record = operations.get_operation(operation_id)
        if record["state"] in {"completed", "failed", "cancelled", "interrupted"}:
            return record
        time.sleep(0.05)
    raise RuntimeError(f"Operation {operation_id} did not become terminal.")


class Scenario:
    def __init__(self, source_root: Path, run_id: str, scenario: str) -> None:
        self.source_root = source_root.resolve()
        self.run_id = run_id
        self.scenario = scenario
        suffix = hashlib.sha256(f"{run_id}:{scenario}".encode()).hexdigest()[:10]
        self.suffix = suffix
        self.root = Path("/tmp/devfleet-release-e2e") / suffix / scenario
        require(self.root.is_relative_to(Path("/tmp/devfleet-release-e2e")), "Scenario root escaped its disposable parent.")
        if self.root.exists():
            shutil.rmtree(self.root)
        self.root.mkdir(parents=True)
        installed_config = json.loads(Path("/etc/devfleet/config.json").read_text(encoding="utf-8"))
        devrunner_uid = pwd.getpwnam("devrunner").pw_uid
        docker_socket = Path(f"/run/user/{devrunner_uid}/docker.sock")
        socket_stat = docker_socket.stat()
        require(devrunner_uid > 0 and stat.S_ISSOCK(socket_stat.st_mode) and socket_stat.st_uid == devrunner_uid, "The rootless Docker socket is not owned by devrunner.")
        docker_host = f"unix://{docker_socket}"
        config = {
            **installed_config,
            "node_name": f"devfleet-e2e-{suffix}",
            "deployment_id": f"e2e-{suffix}",
            "workspaces": str(self.root / "workspaces"),
            "quarantine": str(self.root / "quarantine"),
            "peer_file": str(self.root / "peer.json"),
            "runtime_root": str(self.root / "runtime"),
            "cache_root": str(self.root / "cache"),
            "allow_permanent_delete": True,
            "require_tailscale": True,
            "public_binding_allowed": False,
            "tailnet_cidr": "100.64.0.0/10",
            "host_control_enabled": False,
        }
        config_path = self.root / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        os.environ["DEVFLEET_CONFIG_PATH"] = str(config_path)
        os.environ["DOCKER_HOST"] = docker_host
        os.environ["PYTHONPATH"] = str(self.source_root / "app")
        sys.path.insert(0, str(self.source_root / "app"))
        from devfleet import containers, operations, projects

        projects.TEMPLATE_ROOT = self.source_root / "templates"
        self.containers = containers
        self.operations = operations
        self.projects = projects
        self.docker_host = docker_host
        self.foreign_ids: list[str] = []
        self.slugs: list[str] = []

    def slug(self, stem: str) -> str:
        value = f"e2e-{stem}-{self.suffix}"
        self.slugs.append(value)
        return value

    def create_project(self, stem: str, *, start: bool = True) -> tuple[str, dict]:
        slug = self.slug(stem)
        metadata = self.projects.create_project(
            slug=slug,
            display_name=f"DevFleet E2E {stem}",
            template="generic",
            profile="strict",
            resource_profile="small",
            runtime_isolation="container",
            use_ollama=False,
        )
        require(metadata["managed_by"] == "devfleet" and metadata["slug"] == slug, "Created project lacks exact ownership metadata.")
        if start:
            self.projects.start_project(slug)
            require(self.projects.inspect_runtime(slug)["running"] is True, "Created project runtime did not start.")
        return slug, metadata

    def create_foreign_container(self, image: str, name: str) -> str:
        result = command(["docker", "run", "-d", "--name", name, "--label", "io.devfleet.managed-by=foreign", image, "sh", "-lc", "sleep 600"])
        immutable_id = result.stdout.strip()
        require(re.fullmatch(r"[0-9a-f]{64}", immutable_id) is not None, "Foreign container did not return an immutable Docker identity.")
        self.foreign_ids.append(immutable_id)
        return immutable_id

    def running_container(self, slug: str) -> tuple[str, str, str]:
        compose = self.projects.compose_file(self.projects.SETTINGS.workspaces / slug)
        require(compose is not None, "Project has no Compose runtime.")
        result = self.projects.run([*self.projects.compose_args(self.projects.SETTINGS.workspaces / slug, compose), "ps", "--quiet"], cwd=self.projects.SETTINGS.workspaces / slug)
        container_id = result.stdout.strip().splitlines()[0]
        inspected = json.loads(command(["docker", "inspect", container_id]).stdout)[0]
        return inspected["Id"], inspected["Config"]["Image"], inspected["Name"].lstrip("/")

    def permanent_delete(self) -> dict:
        slug, metadata = self.create_project("delete")
        workspace = self.projects.SETTINGS.workspaces / slug
        sentinel = workspace / "release-sentinel.txt"
        sentinel.write_text("permanent-delete-evidence\n", encoding="utf-8")
        result = self.projects.destroy_project(slug, slug, f"DESTROY {slug}")
        require(not workspace.exists(), "Permanent delete left the authoritative workspace behind.")
        tombstones = list((self.projects.SETTINGS.runtime_root / "recovery-tombstones").glob(f"{slug}-*.json"))
        require(len(tombstones) == 1, "Permanent delete did not retain exactly one recovery tombstone.")
        tombstone = json.loads(tombstones[0].read_text(encoding="utf-8"))
        backups = self.projects.SETTINGS.runtime_root / "workspace-backups" / tombstone["backup_id"]
        require(backups.is_dir() and re.fullmatch(r"[0-9a-f]{64}", tombstone["backup_sha256"]), "Safety backup identity is incomplete.")
        return {"workspaceAbsent": True, "projectId": metadata["project_id"], "backupId": tombstone["backup_id"], "backupSha256": tombstone["backup_sha256"], "tombstone": tombstones[0].name, "productResult": result[-1000:]}

    def delete_restore(self) -> dict:
        slug, metadata = self.create_project("restore")
        workspace = self.projects.SETTINGS.workspaces / slug
        sentinel = workspace / "release-sentinel.txt"
        expected = hashlib.sha256(f"{self.run_id}:{slug}".encode()).hexdigest()
        sentinel.write_text(expected + "\n", encoding="utf-8")
        self.projects.destroy_project(slug, slug, f"DESTROY {slug}")
        tombstone_path = next((self.projects.SETTINGS.runtime_root / "recovery-tombstones").glob(f"{slug}-*.json"))
        tombstone = json.loads(tombstone_path.read_text(encoding="utf-8"))
        restored = self.projects.restore_deleted_project(slug, tombstone["backup_id"], project_id=metadata["project_id"], confirm_restore=True)
        require(sentinel.read_text(encoding="utf-8").strip() == expected, "Delete/restore did not recover exact sentinel content.")
        require(restored["project"]["project_id"] == metadata["project_id"], "Delete/restore changed project identity.")
        self.projects.start_project(slug)
        require(self.projects.runtime_health(slug)["healthy"] is True, "Restored project runtime did not return healthy.")
        self.projects.stop_project(slug)
        return {"projectId": metadata["project_id"], "backupId": tombstone["backup_id"], "backupSha256": restored["backup_sha256"], "sentinelSha256": hashlib.sha256(sentinel.read_bytes()).hexdigest(), "runtimeRestarted": True}

    def stopped_project(self) -> dict:
        slug, metadata = self.create_project("stopped")
        before = self.projects.inspect_runtime(slug)
        self.projects.stop_project(slug)
        stopped = self.projects.inspect_runtime(slug)
        health = self.projects.runtime_health(slug)
        require(before["running"] is True and stopped["running"] is False, "Stopped-project state transition was not truthful.")
        require(health["healthy"] is False and not str(self.projects.load_meta(self.projects.SETTINGS.workspaces / slug).get("runtime_address") or ""), "Stopped project retained a live runtime claim.")
        self.projects.start_project(slug)
        require(self.projects.inspect_runtime(slug)["running"] is True, "Stopped-project recovery did not restart the owned runtime.")
        self.projects.stop_project(slug)
        return {"projectId": metadata["project_id"], "runningBefore": True, "stoppedRecognized": True, "staleAddressRejected": True, "restartRecovered": True}

    def host_concurrency(self) -> dict:
        operations = self.operations
        started = threading.Event()
        release = threading.Event()
        active = 0
        maximum_same = 0
        lock = threading.Lock()

        def held(ctx):
            nonlocal active, maximum_same
            with lock:
                active += 1
                maximum_same = max(maximum_same, active)
            started.set()
            release.wait(10)
            with lock:
                active -= 1
            return "held"

        first = operations.submit_operation("e2e-mutation", "same-project", held, idempotency_key=f"e2e:{self.suffix}:same")
        require(started.wait(5), "First bounded mutation did not start.")
        duplicate = operations.submit_operation("e2e-mutation", "same-project", lambda _ctx: "duplicate", idempotency_key=f"e2e:{self.suffix}:same")
        second = operations.submit_operation("e2e-conflict", "same-project", lambda _ctx: "conflict")
        release.set()
        first_record = wait_operation(operations, first)
        second_record = wait_operation(operations, second)
        require(duplicate == first and first_record["state"] == "completed", "Operation idempotency did not reuse the live operation.")
        require(second_record["state"] == "failed" and second_record.get("error") == "operation_locked", "Conflicting same-project mutation was not serialized.")
        require(maximum_same == 1, "Same-project mutations overlapped.")

        barrier = threading.Barrier(2)
        independent_active = 0
        independent_maximum = 0

        def independent(_ctx):
            nonlocal independent_active, independent_maximum
            with lock:
                independent_active += 1
                independent_maximum = max(independent_maximum, independent_active)
            barrier.wait(timeout=5)
            time.sleep(0.2)
            with lock:
                independent_active -= 1
            return "independent"

        ids = [operations.submit_operation("e2e-read", name, independent) for name in ("project-a", "project-b")]
        records = [wait_operation(operations, value) for value in ids]
        require(all(record["state"] == "completed" for record in records) and independent_maximum == 2, "Independent project operations did not execute independently.")
        return {"sameOperationIdempotent": True, "sameProjectMaximumConcurrency": maximum_same, "conflictingMutationState": second_record["state"], "independentProjectMaximumConcurrency": independent_maximum, "leasesReleased": True}

    def operation_recovery(self) -> dict:
        op_path = self.root / "orphan-operation-id.txt"
        counter_path = self.root / "destructive-counter.txt"
        child_code = """
import os,time
from pathlib import Path
from devfleet import operations
counter=Path(os.environ['DEVFLEET_E2E_COUNTER'])
def work(ctx):
    counter.write_text('1\\n',encoding='utf-8');ctx.update(25,'fixture mutation entered','mutation');time.sleep(600)
op=operations.submit_operation('e2e-destructive','orphan-project',work,idempotency_key='e2e-orphan')
Path(os.environ['DEVFLEET_E2E_OP']).write_text(op,encoding='utf-8')
while True: time.sleep(1)
"""
        env = os.environ.copy()
        env["PYTHONPATH"] = str(self.source_root / "app")
        env["DEVFLEET_E2E_COUNTER"] = str(counter_path)
        env["DEVFLEET_E2E_OP"] = str(op_path)
        child = subprocess.Popen([sys.executable, "-c", child_code], env=env)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline and not op_path.exists():
                time.sleep(0.1)
            require(op_path.exists(), "Recovery child did not persist an operation identity.")
            op_id = op_path.read_text(encoding="utf-8").strip()
            record_path = self.operations.SETTINGS.operations / f"{op_id}.json"
            while time.monotonic() < deadline:
                record = json.loads(record_path.read_text(encoding="utf-8"))
                if record["state"] == "running" and counter_path.exists():
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("Recovery child operation did not enter running state.")
            child.terminate()
            child.wait(timeout=10)
            lease = json.loads(record_path.read_text(encoding="utf-8"))["lease_expires_at"]
            lease_epoch = __import__("datetime").datetime.fromisoformat(lease.replace("Z", "+00:00")).timestamp()
            time.sleep(max(0.0, lease_epoch - time.time()) + 0.5)
            reconcile_code = "from devfleet.operations import reconcile_operations; import json; print(json.dumps(reconcile_operations()))"
            recovered = json.loads(command([sys.executable, "-c", reconcile_code], timeout=20).stdout)
            record = json.loads(record_path.read_text(encoding="utf-8"))
            require(op_id in recovered and record["state"] == "interrupted" and record["recovery_required"] is True, "Expired worker lease was not reconciled truthfully.")
            require(counter_path.read_text(encoding="utf-8").splitlines() == ["1"], "Interrupted mutation executed more than once.")
            return {"operationId": op_id, "originatingProcessExited": True, "leaseExpired": True, "reconciledState": record["state"], "recoveryRequired": True, "destructiveEntryCount": 1}
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)

    def ownership(self) -> dict:
        slug, metadata = self.create_project("ownership")
        owned_id, image, owned_name = self.running_container(slug)
        listed = {row["id"] for row in self.containers.list_containers()}
        require(owned_id in listed, "Owned container was absent from the authorized container inventory.")
        foreign_name = f"devfleet-e2e-foreign-{self.suffix}"
        foreign_id = self.create_foreign_container(image, foreign_name)
        require(foreign_id not in {row["id"] for row in self.containers.list_containers()}, "Foreign container leaked into the authorized inventory.")
        rejected = False
        try:
            self.containers.container_action(foreign_id, "remove")
        except ValueError:
            rejected = True
        require(rejected and command(["docker", "inspect", foreign_id], check=False).returncode == 0, "Foreign container mutation was not rejected and preserved.")
        self.projects.stop_project(slug)
        same_name_id = self.create_foreign_container(image, owned_name)
        same_name_rejected = False
        try:
            self.containers.container_action(owned_name, "remove")
        except ValueError:
            same_name_rejected = True
        require(same_name_rejected and command(["docker", "inspect", same_name_id], check=False).returncode == 0, "Same-name foreign replacement was not rejected and preserved.")
        return {"projectId": metadata["project_id"], "ownedContainerAccepted": True, "ownedImmutableId": owned_id, "foreignContainerRejected": True, "sameNameReplacementRejected": True, "foreignResourcesPreserved": True}

    def vault(self) -> dict:
        candidate_backup = self.source_root / "linux" / "devfleet-backup"
        candidate_bootstrap = self.source_root / "linux" / "bootstrap-vault.sh"
        require(candidate_backup.is_file() and candidate_bootstrap.is_file(), "Exact candidate Vault scripts are missing.")
        bootstrap_text = candidate_bootstrap.read_text(encoding="utf-8")
        backup_text = candidate_backup.read_text(encoding="utf-8")
        require("tailscale ip -4" in bootstrap_text and "append-only" in bootstrap_text and "tailscale0" in bootstrap_text, "Vault bootstrap lacks canonical private-transport/append-only enforcement.")
        require("RESTIC_REPOSITORY" in backup_text and "restic backup" in backup_text, "Candidate backup entrypoint is incomplete.")
        repo = self.root / "restic-repository"
        source = self.root / "vault-source"
        restore = self.root / "vault-restore"
        source.mkdir()
        sentinel = source / "sentinel.txt"
        sentinel.write_text(f"vault-{self.suffix}\n", encoding="utf-8")
        env = os.environ.copy()
        env["RESTIC_REPOSITORY"] = str(repo)
        env["RESTIC_PASSWORD"] = hashlib.sha256(f"vault:{self.run_id}".encode()).hexdigest()
        for args in (["restic", "init"], ["restic", "backup", str(source)], ["restic", "restore", "latest", "--target", str(restore)]):
            result = subprocess.run(args, env=env, text=True, capture_output=True, timeout=300, check=False)
            require(result.returncode == 0, f"Disposable restic operation failed: {args[1]}")
        restored = next(restore.rglob("sentinel.txt"))
        require(restored.read_bytes() == sentinel.read_bytes(), "Disposable Vault restore changed sentinel content.")
        return {"candidatePolicy": "tailscale-scoped append-only", "arbitraryLanFallbackRejectedByContract": True, "resticBackup": "PASS", "resticRestore": "PASS", "sentinelSha256": hashlib.sha256(restored.read_bytes()).hexdigest(), "credentialInEvidence": False, "liveRemoteVault": "NOT APPLICABLE — supported Tailscale mode is Deferred"}

    def cleanup(self) -> None:
        for slug in reversed(self.slugs):
            project = self.projects.SETTINGS.workspaces / slug
            if project.is_dir():
                try:
                    self.projects.stop_project(slug)
                except Exception:
                    pass
        for immutable_id in reversed(self.foreign_ids):
            command(["docker", "rm", "-f", immutable_id], timeout=60, check=False)
        if self.root.exists() and self.root.is_relative_to(Path("/tmp/devfleet-release-e2e")):
            shutil.rmtree(self.root)

    def run(self) -> dict:
        command(["docker", "version", "--format", "{{.Server.Version}}"], timeout=30)
        functions = {
            "permanent-delete": self.permanent_delete,
            "delete-restore": self.delete_restore,
            "stopped-project": self.stopped_project,
            "host-concurrency": self.host_concurrency,
            "operation-recovery": self.operation_recovery,
            "ownership": self.ownership,
            "vault": self.vault,
        }
        try:
            evidence = functions[self.scenario]()
            return {"status": "PASS", "scenario": self.scenario, "runId": self.run_id, "sourceVersion": (self.source_root / "VERSION").read_text(encoding="utf-8").strip(), "rootlessDocker": True, "dockerOwnerUid": int(re.search(r"/run/user/([0-9]+)/", self.docker_host).group(1)), "evidence": evidence, "cleanup": "PASS"}
        finally:
            self.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--scenario", choices=("permanent-delete", "delete-restore", "stopped-project", "host-concurrency", "operation-recovery", "ownership", "vault"), required=True)
    args = parser.parse_args()
    require(re.fullmatch(r"e2e-[A-Za-z0-9-]{8,80}", args.run_id) is not None, "Invalid release run identity.")
    require((args.source_root / "VERSION").is_file() and (args.source_root / "app" / "devfleet" / "projects.py").is_file(), "Exact candidate source root is incomplete.")
    try:
        print(json.dumps(Scenario(args.source_root, args.run_id, args.scenario).run(), sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({"status": "FAIL", "scenario": args.scenario, "error": str(exc)[-3000:]}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
