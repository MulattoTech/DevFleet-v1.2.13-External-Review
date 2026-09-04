"""First-class project runtime/provider boundary.

The dashboard and project model express intent. Providers own mechanics. The
VM provider talks only to the authenticated host-agent client; no Multipass
command is reachable from a dashboard route.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from .host_control import (
    destroy_project_vm,
    ensure_project_vm,
    get_host_capacity,
    get_provider_status,
    runtime_project_vm,
    stop_project_vm,
    export_project_workspace,
    export_project_workspace_to_source,
    restore_previous_source_workspace,
    project_vm_operation,
    list_project_vm_backups,
    inspect_project_vm_backup,
    restore_project_vm_backup,
    refresh_project_vm_connection_state,
    host_control_request,
)


@dataclass(frozen=True)
class RuntimeProvider:
    name: str
    runtime_type: str
    description: str
    gpu_enabled: bool = False

    @property
    def is_vm(self) -> bool:
        return self.runtime_type == "vm"


class ProjectRuntimeProvider(Protocol):
    provider: RuntimeProvider

    def create(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]: ...
    def start(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]: ...
    def stop(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]: ...
    def restart(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]: ...
    def inspect(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]: ...
    def health(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]: ...
    def backup(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]: ...
    def quarantine(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]: ...
    def restore(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]: ...
    def destroy(self, slug: str, metadata: dict[str, Any], **kwargs: Any) -> dict[str, Any]: ...
    def reconcile(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]: ...
    def refresh(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]: ...
    def command(self, slug: str, metadata: dict[str, Any], operation: str, *, command_key: str = "", tail: int = 150) -> dict[str, Any]: ...
    def logs(self, slug: str, metadata: dict[str, Any], *, tail: int = 150) -> dict[str, Any]: ...
    def export(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]: ...


CONTAINER_PROVIDER = RuntimeProvider("docker-compose", "container", "Dedicated project containers on the current DevFleet VM.")
VM_PROVIDER = RuntimeProvider("multipass-host-agent", "vm", "Dedicated project VM managed by the authenticated Windows host agent; GPU access is disabled.")


def provider_for(metadata: dict[str, Any]) -> RuntimeProvider:
    recorded = str(metadata.get("runtime_provider") or "").lower()
    isolation = str(metadata.get("runtime_isolation") or metadata.get("runtime_type") or "container").lower()
    if recorded in {VM_PROVIDER.name, "multipass", "vm"} or isolation == "vm":
        return VM_PROVIDER
    return CONTAINER_PROVIDER


def runtime_metadata(provider: RuntimeProvider, *, status: str, **values: Any) -> dict[str, Any]:
    data = {
        "runtime_type": provider.runtime_type,
        "runtime_provider": provider.name,
        "runtime_status": status,
        "gpu_enabled": False,
    }
    data.update({key: value for key, value in values.items() if value is not None})
    return data


class MultipassRuntimeProvider:
    provider = VM_PROVIDER

    def create(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]:
        return ensure_project_vm(slug, metadata.get("resource_limits") or {}, project_id=str(metadata.get("project_id") or ""), git_url=str(metadata.get("git_url") or ""))

    def start(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]:
        return runtime_project_vm(slug, "start", runtime_id=str(metadata.get("runtime_id") or ""), project_id=str(metadata.get("project_id") or ""))

    def stop(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]:
        return stop_project_vm(slug, runtime_id=str(metadata.get("runtime_id") or ""), project_id=str(metadata.get("project_id") or ""))

    def restart(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]:
        return runtime_project_vm(slug, "restart", runtime_id=str(metadata.get("runtime_id") or ""), project_id=str(metadata.get("project_id") or ""))

    def inspect(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]:
        return runtime_project_vm(slug, "inspect", runtime_id=str(metadata.get("runtime_id") or ""), project_id=str(metadata.get("project_id") or ""))

    def health(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]:
        return runtime_project_vm(slug, "health", runtime_id=str(metadata.get("runtime_id") or ""), project_id=str(metadata.get("project_id") or ""))

    def backup(self, slug: str, metadata: dict[str, Any], *, consistency_level: str = "live-best-effort", destructive: bool = False) -> dict[str, Any]:
        return host_control_request("backup", {"slug": slug, "project_id": str(metadata.get("project_id") or ""), "consistency_level": consistency_level, "destructive": bool(destructive)}, runtime_id=str(metadata.get("runtime_id") or ""))

    def quarantine(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]:
        return runtime_project_vm(slug, "quarantine", runtime_id=str(metadata.get("runtime_id") or ""), project_id=str(metadata.get("project_id") or ""))

    def restore(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]:
        return runtime_project_vm(slug, "restore", runtime_id=str(metadata.get("runtime_id") or ""), project_id=str(metadata.get("project_id") or ""))

    def destroy(self, slug: str, metadata: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        return destroy_project_vm(slug, str(kwargs.get("confirm_slug") or ""), str(kwargs.get("confirm_phrase") or ""), backup_verified=bool(kwargs.get("backup_verified")), backup_id=str(kwargs.get("backup_id") or ""), backup_sha256=str(kwargs.get("backup_sha256") or ""), cleanup_only=bool(kwargs.get("cleanup_only")), runtime_id=str(metadata.get("runtime_id") or ""), project_id=str(metadata.get("project_id") or ""))

    def reconcile(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]:
        return self.inspect(slug, metadata)

    def refresh(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]:
        return refresh_project_vm_connection_state(slug, str(metadata.get("runtime_id") or ""), project_id=str(metadata.get("project_id") or ""))

    def command(self, slug: str, metadata: dict[str, Any], operation: str, *, command_key: str = "", tail: int = 150) -> dict[str, Any]:
        return project_vm_operation(slug, operation, runtime_id=str(metadata.get("runtime_id") or ""), project_id=str(metadata.get("project_id") or ""), command_key=command_key, tail=tail)

    def logs(self, slug: str, metadata: dict[str, Any], *, tail: int = 150) -> dict[str, Any]:
        return self.command(slug, metadata, "project-logs", tail=tail)

    def export(self, slug: str, metadata: dict[str, Any]) -> dict[str, Any]:
        return export_project_workspace(slug, str(metadata.get("runtime_id") or ""), project_id=str(metadata.get("project_id") or ""))

    def list_backups(self, slug: str, metadata: dict[str, Any]) -> list[dict[str, Any]]:
        return list_project_vm_backups(slug, runtime_id=str(metadata.get("runtime_id") or ""), project_id=str(metadata.get("project_id") or ""))

    def inspect_backup(self, slug: str, metadata: dict[str, Any], backup_id: str) -> dict[str, Any]:
        return inspect_project_vm_backup(slug, backup_id, runtime_id=str(metadata.get("runtime_id") or ""), project_id=str(metadata.get("project_id") or ""))

    def restore_backup(self, slug: str, metadata: dict[str, Any], backup_id: str, *, confirm_restore: bool = False) -> dict[str, Any]:
        return restore_project_vm_backup(slug, backup_id, confirm_restore=confirm_restore, runtime_id=str(metadata.get("runtime_id") or ""), project_id=str(metadata.get("project_id") or ""))

    def export_to_source(self, slug: str, metadata: dict[str, Any], *, source_vm: str, replace_source: bool = False) -> dict[str, Any]:
        return export_project_workspace_to_source(slug, str(metadata.get("runtime_id") or ""), source_vm=source_vm, project_id=str(metadata.get("project_id") or ""), replace_source=replace_source)

    def restore_previous_source(self, slug: str, metadata: dict[str, Any], *, source_vm: str, previous_workspace_path: str) -> dict[str, Any]:
        return restore_previous_source_workspace(slug, str(metadata.get("runtime_id") or ""), source_vm=source_vm, project_id=str(metadata.get("project_id") or ""), previous_workspace_path=previous_workspace_path)


VM_RUNTIME = MultipassRuntimeProvider()


class VmRuntimeOperations:
    """Compatibility facade for existing project lifecycle code."""

    @staticmethod
    def ensure(slug: str, metadata: dict[str, Any]) -> dict[str, Any]:
        return VM_RUNTIME.create(slug, metadata)

    @staticmethod
    def start(slug: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        return VM_RUNTIME.start(slug, metadata or {})

    @staticmethod
    def stop(slug: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        return VM_RUNTIME.stop(slug, metadata or {})

    @staticmethod
    def restart(slug: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        return VM_RUNTIME.restart(slug, metadata or {})

    @staticmethod
    def inspect(slug: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        return VM_RUNTIME.inspect(slug, metadata or {})

    @staticmethod
    def refresh(slug: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        return VM_RUNTIME.refresh(slug, metadata or {})

    @staticmethod
    def health(slug: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        return VM_RUNTIME.health(slug, metadata or {})

    @staticmethod
    def backup(slug: str, metadata: dict[str, Any] | None = None, *, consistency_level: str = "live-best-effort", destructive: bool = False) -> dict[str, Any]:
        return VM_RUNTIME.backup(slug, metadata or {}, consistency_level=consistency_level, destructive=destructive)

    @staticmethod
    def quarantine(slug: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        return VM_RUNTIME.quarantine(slug, metadata or {})

    @staticmethod
    def restore(slug: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
        return VM_RUNTIME.restore(slug, metadata or {})

    @staticmethod
    def command(slug: str, metadata: dict[str, Any] | None, operation: str, *, command_key: str = "", tail: int = 150) -> dict[str, Any]:
        return VM_RUNTIME.command(slug, metadata or {}, operation, command_key=command_key, tail=tail)

    @staticmethod
    def destroy(slug: str, metadata: dict[str, Any], **kwargs: Any) -> dict[str, Any]:
        return VM_RUNTIME.destroy(slug, metadata, **kwargs)


def host_capacity() -> dict[str, Any]:
    return get_host_capacity()


def provider_status() -> dict[str, Any]:
    return get_provider_status()
