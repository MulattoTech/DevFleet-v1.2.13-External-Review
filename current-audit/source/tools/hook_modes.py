"""Single source of truth for executable template hook closure and modes."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
import sys

COMMAND_FIELDS = ("bootstrap_command", "health_command", "test_command", "codexpro_command")
LOCAL_HOOK_RE = re.compile(r"(?<![A-Za-z0-9_./-])(?:\./)?(?P<path>\.devfleet/[A-Za-z0-9._-]+\.sh)(?![A-Za-z0-9_./-])")
ABSOLUTE_HOOK_RE = re.compile(r"(?<![A-Za-z0-9_./-])/(?P<path>(?:[^\s\"']+/)*\.devfleet/[A-Za-z0-9._-]+\.sh)")
LOCALISH_HOOK_RE = re.compile(r"(?<![A-Za-z0-9_])(?P<path>(?:\./)?\.devfleet/[^\s\"'`()]+\.sh)")


@dataclass(frozen=True)
class HookClosure:
    """The complete, validated local executable-script closure for a template."""

    direct: frozenset[str]
    transitive: frozenset[str]

    @property
    def executable(self) -> frozenset[str]:
        return self.direct | self.transitive


def _local_references(text: str, *, origin: Path) -> set[str]:
    """Extract only local .devfleet script references and reject unsafe lookalikes."""
    absolute = ABSOLUTE_HOOK_RE.search(text)
    if absolute:
        raise ValueError(f"absolute external hook reference in {origin}: {absolute.group('path')}")
    for candidate in LOCALISH_HOOK_RE.finditer(text):
        path = candidate.group("path")
        if ".." in Path(path).parts or "/" in path.removeprefix("./.devfleet/"):
            raise ValueError(f"unsafe local hook reference in {origin}: {path}")
    return {match.group("path") for match in LOCAL_HOOK_RE.finditer(text)}


def _resolve_local(root: Path, template_dir: Path, relative: str, *, origin: Path) -> tuple[str, Path]:
    candidate = (template_dir / relative).resolve(strict=False)
    template_root = template_dir.resolve()
    try:
        candidate.relative_to(template_root)
    except ValueError as exc:
        raise ValueError(f"hook reference escapes template root in {origin}: {relative}") from exc
    if candidate.parent != (template_dir / ".devfleet").resolve():
        raise ValueError(f"hook reference is not a local .devfleet script in {origin}: {relative}")
    package_relative = candidate.relative_to(root.resolve()).as_posix()
    return package_relative, candidate


def executable_template_hook_closure(root: Path) -> dict[str, HookClosure]:
    """Discover and validate metadata plus transitive local-script references."""
    result: dict[str, HookClosure] = {}
    for metadata in sorted((root / "templates").glob("*/.devfleet/template.json")):
        data = json.loads(metadata.read_text(encoding="utf-8"))
        template_dir = metadata.parent.parent
        direct: set[str] = set()
        pending: list[tuple[str, Path]] = []
        for field in COMMAND_FIELDS:
            command = data.get(field)
            if not isinstance(command, str):
                continue
            for reference in _local_references(command, origin=metadata):
                package_relative, candidate = _resolve_local(root, template_dir, reference, origin=metadata)
                direct.add(package_relative)
                pending.append((package_relative, candidate))

        all_hooks = set(direct)
        while pending:
            package_relative, script = pending.pop()
            if not script.is_file() or script.is_symlink():
                raise ValueError(f"referenced hook is not a regular file: {package_relative}")
            for reference in _local_references(script.read_text(encoding="utf-8"), origin=script):
                child_relative, child = _resolve_local(root, template_dir, reference, origin=script)
                if child_relative not in all_hooks:
                    all_hooks.add(child_relative)
                    pending.append((child_relative, child))
        missing = [rel for rel in sorted(all_hooks) if not (root / rel).is_file()]
        if missing:
            raise ValueError(f"referenced hook does not exist: {missing[0]}")
        direct_set = frozenset(direct)
        result[template_dir.name] = HookClosure(direct_set, frozenset(all_hooks - direct_set))
    return result


def executable_template_hooks(root: Path) -> set[str]:
    """Return package-relative paths in the complete executable hook closure."""
    return set().union(*(closure.executable for closure in executable_template_hook_closure(root).values()))


def hook_mode_manifest(root: Path) -> dict[str, object]:
    closures = executable_template_hook_closure(root)
    hooks = sorted(set().union(*(closure.executable for closure in closures.values())))
    all_scripts = sorted(
        p.relative_to(root).as_posix()
        for p in (root / "templates").glob("*/.devfleet/*.sh")
        if p.is_file()
    )
    return {
        "executable_by_contract": hooks,
        "count": len(hooks),
        "classification": {
            rel: "executable-by-contract" if rel in hooks else "non-executable-source/helper"
            for rel in all_scripts
        },
        "templates": {
            name: {"direct": sorted(c.direct), "transitive": sorted(c.transitive)}
            for name, c in sorted(closures.items())
        },
    }


def is_executable_template_hook(root: Path, path: Path) -> bool:
    return path.relative_to(root).as_posix() in executable_template_hooks(root)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: python hook_modes.py <source-root>")
    print(json.dumps(hook_mode_manifest(Path(sys.argv[1]).resolve()), sort_keys=True))
