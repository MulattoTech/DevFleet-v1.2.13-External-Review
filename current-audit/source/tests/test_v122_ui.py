from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "app/templates/index.html").read_text(encoding="utf-8")
JS = (ROOT / "app/static/app.js").read_text(encoding="utf-8")
CSS = (ROOT / "app/static/style.css").read_text(encoding="utf-8")


def test_environment_wizard_has_reviewable_custom_resource_and_pid_controls():
    for field in ("custom_cpus", "custom_ram_gb", "custom_disk_gb", "pid_mode", "pid_limit"):
        assert f'name="{field}"' in HTML
    assert 'data-environment-wizard' in HTML
    assert 'data-review-summary' in HTML and 'Review before provisioning' in HTML
    assert 'initEnvironmentWizard' in JS


def test_workspace_display_uses_provider_metadata_and_not_a_global_codexdevvm_target():
    assert 'provider_label(p)' in HTML
    assert 'workspace_target(p)' in HTML
    assert 'data-provider' in HTML and 'data-workspace-target' in HTML
    assert 'Open workspace' in HTML
    assert 'ssh CodexDevVM' not in HTML


def test_project_action_sections_are_reachable():
    for tab in ('logs', 'backups', 'safety', 'isolate', 'settings'):
        assert f'?tab={tab}' in HTML
    assert 'Advanced' in HTML and 'confirm_quarantine' in HTML


def test_operation_progress_uses_same_origin_session_endpoint_with_fallback():
    assert 'data-operation-id' in HTML
    assert 'initOperationProgress' in JS
    assert 'fetch(`/operations/${encodeURIComponent(id)}`' in JS
    assert 'credentials: \'same-origin\'' in JS
    assert 'The UI endpoint is optional' in JS
    assert 'X-DevFleet-Token' not in JS
    assert '/ui/projects/${encodeURIComponent(slug)}/logs' in JS
    assert 'Refresh / API' not in HTML


def test_ui_styles_cover_review_and_custom_controls():
    assert '.custom-resource-controls' in CSS
    assert '.wizard-review' in CSS
