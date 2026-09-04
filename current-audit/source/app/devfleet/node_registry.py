"""Durable Primary/Surrogate node identity registry without leader election."""
from __future__ import annotations

import json
import uuid
from pathlib import Path
from typing import Any, Iterable

from .core import SETTINGS, atomic_json, now_iso

VALID_ROLES = {"primary", "surrogate", "server"}


def _new_id() -> str:
    return str(uuid.uuid4())


class NodeRegistry:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or SETTINGS.runtime_root / "node-registry.json"

    def _empty(self) -> dict[str, Any]:
        return {"schema_version": 1, "deployment_id": "", "nodes": []}

    def load(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return self._empty()
        if not isinstance(data, dict) or not isinstance(data.get("nodes", []), list):
            raise ValueError("Node registry is invalid; refusing to infer identities.")
        data.setdefault("schema_version", 1)
        data.setdefault("deployment_id", "")
        return data

    def _save(self, data: dict[str, Any]) -> None:
        if not data.get("deployment_id"):
            raise ValueError("A deployment identity is required.")
        atomic_json(self.path, data)

    def ensure_local(self, *, node_name: str, node_role: str, friendly_name: str = "", deployment_id: str | None = None, coordinator_node_id: str | None = None, capabilities: Iterable[str] = ()) -> dict[str, Any]:
        role = str(node_role or "").strip().lower()
        if role not in VALID_ROLES:
            raise ValueError(f"Unsupported node role: {node_role}")
        data = self.load()
        requested_deployment = str(deployment_id or data.get("deployment_id") or "").strip()
        if not requested_deployment:
            requested_deployment = _new_id()
        if data.get("deployment_id") and data["deployment_id"] != requested_deployment:
            raise ValueError("Deployment identity mismatch; refusing to create a second deployment.")
        data["deployment_id"] = requested_deployment
        name = str(node_name or "").strip()
        if not name:
            raise ValueError("Node name is required.")
        existing = next((n for n in data["nodes"] if isinstance(n, dict) and n.get("node_name") == name), None)
        if existing is not None:
            if existing.get("node_role") != role or existing.get("deployment_id") != requested_deployment:
                raise ValueError("Existing node identity conflicts with the requested role or deployment.")
            existing.update({"friendly_name": friendly_name or existing.get("friendly_name") or name, "capabilities": sorted({str(x) for x in capabilities} | set(existing.get("capabilities") or [])), "coordinator_node_id": coordinator_node_id or existing.get("coordinator_node_id"), "last_seen": now_iso(), "connectivity": "online"})
            self._save(data)
            return dict(existing)
        if role == "surrogate" and not coordinator_node_id:
            raise ValueError("A Surrogate requires an explicit coordinator_node_id.")
        node = {"deployment_id": requested_deployment, "node_id": _new_id(), "node_name": name, "friendly_name": friendly_name or name, "node_role": role, "capabilities": sorted({str(x) for x in capabilities}), "coordinator_node_id": coordinator_node_id if role == "surrogate" else None, "protocol_version": 1, "devfleet_version": "", "health": "unknown", "connectivity": "online", "last_seen": now_iso(), "failover_priority": 100, "compute_capacity": {}, "vault_capability": False, "storage_capacity": {}, "tailscale": {"node": "", "ipv4": "", "ipv6": ""}, "registration_state": "registered"}
        data["nodes"].append(node)
        self._save(data)
        return dict(node)

    def register(self, node: dict[str, Any]) -> dict[str, Any]:
        required = ("deployment_id", "node_id", "node_name", "node_role")
        if any(not str(node.get(key) or "").strip() for key in required):
            raise ValueError("Node registration requires deployment, node, name, and role identities.")
        role = str(node["node_role"]).lower()
        if role not in VALID_ROLES:
            raise ValueError("Unsupported node role.")
        data = self.load()
        if data.get("deployment_id") and data["deployment_id"] != node["deployment_id"]:
            raise ValueError("Node belongs to a different deployment.")
        data["deployment_id"] = node["deployment_id"]
        existing = next((n for n in data["nodes"] if n.get("node_id") == node["node_id"]), None)
        if existing is not None:
            if any(existing.get(key) != node.get(key) for key in ("node_name", "node_role", "deployment_id")):
                raise ValueError("Duplicate node ID has conflicting identity.")
            existing.update(node)
            existing["last_seen"] = now_iso()
            self._save(data)
            return dict(existing)
        data["nodes"].append(dict(node))
        self._save(data)
        return dict(node)

    def list_nodes(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self.load()["nodes"] if isinstance(item, dict)]
