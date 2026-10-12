"""Verify the finite public source inventory; no credentials or network access."""
import hashlib
import json
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "PUBLIC_EXPORT_MANIFEST.json"
GENERATED_DIRS = {".git", ".cache", ".tools", "bin", "work", "__pycache__"}
GENERATED_PREFIXES = ("experiments/raw/", "experiments/reports/", "formal/proof_logs/", "formal/source_snapshots/")
GENERATED_FILES = {"experiments/MANIFEST.json", "experiments/manifests/go-toolchain.json", "docs/RESEARCH_RESULTS.md"}


def generated(path):
    return bool(set(Path(path).parts) & GENERATED_DIRS) or path.startswith(GENERATED_PREFIXES) or path in GENERATED_FILES or path.endswith('.pyc')


def verify():
    record = json.loads((ROOT / MANIFEST).read_text())
    if record.get("source_commit") != "c9fd0579b280dad65c41d6f631c6225b654fd834":
        raise ValueError("Unexpected original source identity")
    entries = record.get("files")
    if not isinstance(entries, list) or not entries:
        raise ValueError("Empty public inventory")
    paths = [entry["path"] for entry in entries]
    if len(paths) != len(set(paths)) or MANIFEST in paths:
        raise ValueError("Duplicate or self-referential inventory")
    forbidden = [
        re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{20,255}|github_pat_[A-Za-z0-9_]{30,255})\b"),
        re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----"),
        re.compile(rb"(?:/Users/|/home/)[A-Za-z0-9_.-]+"),
        re.compile(rb"(?i)\b(?:netAmount|grossAmount|payment_method|billingAddress|accountNumber)\b"),
    ]
    for entry in entries:
        name = entry["path"]
        if entry.get("disposition") not in {"unchanged", "modified", "new"}:
            raise ValueError("Invalid source provenance disposition")
        if entry["disposition"] == "unchanged" and entry.get("source_sha256") != entry["sha256"]:
            raise ValueError("Unchanged-source provenance does not match")
        relative = Path(name)
        if relative.is_absolute() or ".." in relative.parts or generated(name):
            raise ValueError("Invalid source inventory path")
        path = ROOT / relative
        if path.is_symlink() or not path.is_file() or any((ROOT / parent).is_symlink() for parent in relative.parents):
            raise ValueError("Missing or unsafe inventory file: " + name)
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("Public source hash differs: " + name)
        if name != "scripts/verify_public_export.py" and any(pattern.search(data) for pattern in forbidden):
            raise ValueError("Public-text hygiene finding: " + name)
    actual = {str(path.relative_to(ROOT)) for path in ROOT.rglob('*')
              if path.is_file() and not generated(str(path.relative_to(ROOT)))}
    expected = set(paths) | {MANIFEST}
    if actual != expected:
        raise ValueError("Unlisted/missing public source files: " + repr(sorted(actual ^ expected)))
    if (ROOT / ".git").exists():
        tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split('\0')
        tracked = set(filter(None, tracked))
        if tracked != expected:
            raise ValueError("Git tracked inventory differs: " + repr(sorted(tracked ^ expected)))
    print(json.dumps({"status": "PASS", "source_files": len(paths), "original_commit": record["source_commit"],
                      "scope": "curated public source; not the complete original study archive"}, sort_keys=True))


if __name__ == "__main__":
    verify()
