"""Reproducible DevFleet TAR and portable bundle builder."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import re
import stat
import tarfile
import zipfile
from pathlib import Path

from hook_modes import executable_template_hooks, hook_mode_manifest

TRANSIENT = {".git", ".pytest_cache", ".test-runtime", "__pycache__", "runtime-migrations"}


def is_transient_part(part: str) -> bool:
    return part in TRANSIENT or part.startswith(".venv")


def files(root: Path) -> list[Path]:
    candidates = (
        p
        for p in root.rglob("*")
        if p.is_file()
        and not any(is_transient_part(part) for part in p.relative_to(root).parts)
    )
    return sorted(
        candidates,
        key=lambda path: path.relative_to(root).as_posix().encode("utf-8"),
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_checksums(root: Path) -> None:
    manifest = root / "CHECKSUMS.sha256"
    lines = [f"{sha256(path)}  {path.relative_to(root).as_posix()}" for path in files(root) if path != manifest]
    # Keep the tracked manifest byte-identical to a Git archive on Windows;
    # newline translation here would make a frozen commit unreproducible.
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def build_tar(root: Path, output: Path) -> set[str]:
    hooks = executable_template_hooks(root)
    with output.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed, tarfile.open(fileobj=compressed, mode="w") as archive:
        for path in files(root):
            rel = path.relative_to(root).as_posix()
            info = archive.gettarinfo(str(path), arcname=rel)
            info.mode = 0o755 if rel in hooks else 0o644
            info.mtime = 0; info.uid = 0; info.gid = 0; info.uname = "root"; info.gname = "root"
            with path.open("rb") as stream:
                archive.addfile(info, stream)
    return hooks


def portable_metadata(entries: list[tuple[str, bytes]], version: str, nested_tar: Path, root: Path) -> list[tuple[str, bytes]]:
    nested_tar_name = nested_tar.name
    current_source = [("source/" + path.relative_to(root).as_posix(), path.read_bytes()) for path in files(root)]
    source_names = [name for name, _ in current_source]
    source_hashes = [{"path": name, "sha256": sha256_bytes(data)} for name, data in current_source]
    manifest = {"version": version, "file_count": len(source_names), "files": source_hashes}
    canonical_docs = {
        "README.md": (
            f"# DevFleet Safe Remote Development v{version}\n\n"
            f"This is the clean-room v{version} portable bundle. The TAR is the authoritative POSIX-mode artifact.\n\n"
            f"Verify `CHECKSUMS.sha256`, then run `python source/tools/verify_package.py --archive {nested_tar_name}` from the extracted bundle root.\n"
        ).encode(),
        "CLEAN-ROOM-VERIFICATION.md": (
            f"# DevFleet {version} clean-room verification\n\n"
            "Extract this ZIP into a fresh directory. From the extracted bundle root, run:\n\n"
            f"`python source/tools/verify_package.py --archive {nested_tar_name}`\n\n"
            "The command must complete successfully before the portable package is accepted.\n"
        ).encode(),
        "DIRECTORY-LAYOUT.md": (
            f"# DevFleet {version} portable layout\n\n"
            f"`source/` contains the complete canonical source. `{nested_tar_name}` preserves the release source and trusted POSIX hook modes.\n"
        ).encode(),
    }
    rebuilt: list[tuple[str, bytes]] = []
    for name, data in entries:
        if name.startswith("devfleet-v1.2.") and name.endswith(".tar.gz"):
            continue
        if name.startswith("source/"):
            continue
        if name in {"portable-codebase-manifest.json", "portable-codebase-sha256.txt", "source-tree-manifest.json", "source-tree-sha256.txt"}:
            continue
        if name in canonical_docs:
            continue
        rebuilt.append((name, data))
    rebuilt.extend(canonical_docs.items())
    rebuilt.append((nested_tar_name, nested_tar.read_bytes()))
    rebuilt.extend(current_source)
    rebuilt.append(("portable-codebase-manifest.json", json.dumps(manifest, indent=2).encode()))
    rebuilt.append(("source-tree-manifest.json", json.dumps({"version": version, "file_count": len(source_names), "files": source_hashes}, indent=2).encode()))
    rebuilt.append(("source-tree-sha256.txt", ("\n".join(f"{item['sha256']}  {item['path']}" for item in source_hashes) + "\n").encode()))
    rebuilt.append(("portable-codebase-sha256.txt", ("\n".join(f"{sha256_bytes(data)}  {name}" for name, data in sorted(rebuilt, key=lambda item: item[0].encode("utf-8")) if name not in {"portable-codebase-sha256.txt"}) + "\n").encode()))
    _assert_portable_instruction_identity(rebuilt, version, nested_tar_name)
    return rebuilt


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _assert_portable_instruction_identity(entries: list[tuple[str, bytes]], version: str, nested_tar_name: str) -> None:
    instruction_names = {"README.md", "CLEAN-ROOM-VERIFICATION.md", "DIRECTORY-LAYOUT.md"}
    stale_version = re.compile(r"(?:DevFleet\s+v|devfleet-v)(\d+\.\d+\.\d+)")
    for name, data in entries:
        if name not in instruction_names:
            continue
        text = data.decode("utf-8", errors="strict")
        for match in stale_version.finditer(text):
            context = text[max(0, match.start() - 80):match.end() + 80].lower()
            if match.group(1) != version and "historical" not in context:
                raise ValueError(f"Portable release instruction {name} contains an unapproved prior release identity.")
        if name == "CLEAN-ROOM-VERIFICATION.md" and nested_tar_name not in text:
            raise ValueError(f"Portable clean-room instructions do not name {nested_tar_name}.")


def main() -> None:
    global args, root
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--old-portable", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    root = args.source.resolve()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (root / "CHECKSUMS.sha256").unlink(missing_ok=True)
    write_checksums(root)
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    tar = args.output_dir / f"devfleet-v{version}.tar.gz"
    hooks = build_tar(root, tar)
    with zipfile.ZipFile(args.old_portable) as source_zip:
        entries = [(item.filename, source_zip.read(item.filename)) for item in source_zip.infolist() if not item.is_dir()]
    portable = args.output_dir / f"DevFleet-v{version}-Portable-Codebase-Verified-r1.zip"
    rebuilt = portable_metadata(entries, version, tar, root)
    with zipfile.ZipFile(portable, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as out:
        for name, data in sorted(rebuilt, key=lambda item: item[0].encode("utf-8")):
            info = zipfile.ZipInfo(name)
            mode = 0o755 if name.removeprefix("source/") in hooks else 0o644
            info.create_system = 3  # Unix origin; required for standard unzip mode restoration.
            info.external_attr = (stat.S_IFREG | mode) << 16
            out.writestr(info, data)
    manifest = hook_mode_manifest(root); manifest.update({"version": version, "mode": "0755"})
    (args.output_dir / "hook-mode-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"tar": str(tar), "portable": str(portable), "hook_count": len(hooks), "tar_sha256": sha256(tar), "portable_sha256": sha256(portable)}, indent=2))


if __name__ == "__main__":
    main()
