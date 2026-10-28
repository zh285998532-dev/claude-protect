#!/usr/bin/env python3
"""Build a VSIX with Microsoft's vsce, plus a portable source distribution."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--vsce", default="vsce", help="path to an already installed Microsoft @vscode/vsce")
    args = parser.parse_args()
    version = json.loads((ROOT / "extension/package.json").read_text())["version"]
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    shutil.copyfile(ROOT / "LICENSE", ROOT / "extension/LICENSE")
    shutil.copyfile(ROOT / "NOTICE.md", ROOT / "extension/NOTICE.md")
    guide = (ROOT / "README.md").read_text()
    (ROOT / "extension/readme.md").write_text(guide)
    for file in (ROOT / "docs").glob("*.md"):
        target = ROOT / "extension/docs" / file.name
        target.parent.mkdir(exist_ok=True)
        shutil.copyfile(file, target)
    vsix = dist / f"claude-protect-{version}.vsix"
    subprocess.run([args.vsce, "package", "--allow-missing-repository", "--no-rewrite-relative-links", "--out", str(vsix)],
                   cwd=ROOT / "extension", check=True)
    archive = dist / f"claude-protect-{version}-ubuntu.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        for file in sorted(ROOT.rglob("*")):
            relative = file.relative_to(ROOT)
            if not file.is_file() or any(part in ("__pycache__", ".git", "node_modules", ".venv") for part in relative.parts):
                continue
            # GUI reports and arbitrary workspace files are not release inputs.
            allowed_roots = {"bin", "lib", "scripts", "tests", "docs", "extension", ".github", "dist"}
            allowed_files = {"README.md", "LICENSE", "NOTICE.md", "requirements-gui.txt", ".gitignore"}
            if relative.parts[0] not in allowed_roots and str(relative) not in allowed_files:
                continue
            if file.name.startswith("claude-protect-report") or file.suffix == ".log":
                continue
            if relative.parts[0] == "dist" and file != vsix:
                continue
            output.add(file, arcname=str(Path(f"claude-protect-{version}") / relative), recursive=False)
    checksum = dist / "SHA256SUMS"
    checksum.write_text("".join(f"{hashlib.sha256(file.read_bytes()).hexdigest()}  {file.name}\n" for file in (vsix, archive)))
    print(f"Built {vsix.name}, {archive.name}, SHA256SUMS")


if __name__ == "__main__":
    main()
