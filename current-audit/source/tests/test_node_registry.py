from __future__ import annotations

import pytest

from devfleet.node_registry import NodeRegistry


def test_primary_and_multiple_surrogates_share_deployment_but_keep_unique_ids(tmp_path):
    registry = NodeRegistry(tmp_path / "nodes.json")
    primary = registry.ensure_local(node_name="primary", node_role="primary", capabilities=("primary-control",))
    first = registry.ensure_local(node_name="surface-a", node_role="surrogate", deployment_id=primary["deployment_id"], coordinator_node_id=primary["node_id"], capabilities=("failover", "vault"))
    second = registry.ensure_local(node_name="surface-b", node_role="surrogate", deployment_id=primary["deployment_id"], coordinator_node_id=primary["node_id"], capabilities=("compute",))
    assert primary["deployment_id"] == first["deployment_id"] == second["deployment_id"]
    assert len({primary["node_id"], first["node_id"], second["node_id"]}) == 3
    assert first["node_role"] == second["node_role"] == "surrogate"


def test_surrogate_requires_coordinator_and_does_not_create_second_deployment(tmp_path):
    registry = NodeRegistry(tmp_path / "nodes.json")
    with pytest.raises(ValueError, match="coordinator"):
        registry.ensure_local(node_name="surface", node_role="surrogate")
    primary = registry.ensure_local(node_name="primary", node_role="primary")
    with pytest.raises(ValueError, match="Deployment identity mismatch"):
        registry.ensure_local(node_name="surface", node_role="surrogate", deployment_id="different", coordinator_node_id=primary["node_id"])


def test_duplicate_registration_is_idempotent_and_conflict_fails_closed(tmp_path):
    registry = NodeRegistry(tmp_path / "nodes.json")
    primary = registry.ensure_local(node_name="primary", node_role="primary")
    again = registry.register(primary)
    assert again["node_id"] == primary["node_id"]
    with pytest.raises(ValueError, match="conflicting identity"):
        registry.register({**primary, "node_role": "surrogate"})
