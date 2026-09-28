# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Automated security review (WP-044): dependency audit, secret scan, unsafe-pattern scan,
parser fuzzing and protocol-invariant tests.

Usage: uv run python scripts/security_review.py [--offline] [--fuzz-iterations N] [--json OUT]

Every finding is either fixed or listed in ``ALLOWLIST`` with a justification.
The manual threat-model review before v1.0 is tracked in docs/THREAT_MODEL.md.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SECRET_PATTERNS = {
    "pem_private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    "aws_access_key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "slack_token": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    "generic_assignment": re.compile(
        r"(?i)\b(api[_-]?key|secret[_-]?key|password|passwd|token)\s*[:=]\s*['\"][^'\"\s]{12,}['\"]"
    ),
}

UNSAFE_PATTERNS = {
    "tls_verification_disabled": re.compile(
        r"verify\s*=\s*False|CERT_NONE|_create_unverified_context"
    ),
    "shell_true": re.compile(r"shell\s*=\s*True"),
    "pickle_load": re.compile(r"\bpickle\.loads?\("),
    "yaml_unsafe_load": re.compile(r"\byaml\.load\((?![^)]*SafeLoader)"),
    "eval_exec": re.compile(r"(?<![\w.])(?:eval|exec)\("),
    "torch_load_unrestricted": re.compile(r"torch\.load\([^)]*weights_only\s*=\s*False"),
    "bind_all_interfaces": re.compile(r"['\"]0\.0\.0\.0['\"]"),
    "assert_in_src": re.compile(r"^\s*assert\s", re.MULTILINE),
}

#: (pattern, path) -> justification. Anything else is a finding.
ALLOWLIST = {
    ("torch_load_unrestricted", "src/esp/training/harness.py"): (
        "loads only checkpoints this harness wrote itself (optimizer and RNG state need pickling); "
        "never used for downloaded checkpoints"
    ),
    ("tls_verification_disabled", "scripts/security_review.py"): "the pattern definition itself",
    ("shell_true", "scripts/security_review.py"): "the pattern definition itself",
    ("pickle_load", "scripts/security_review.py"): "the pattern definition itself",
    ("yaml_unsafe_load", "scripts/security_review.py"): "the pattern definition itself",
    ("eval_exec", "scripts/security_review.py"): "the pattern definition itself",
    ("torch_load_unrestricted", "scripts/security_review.py"): "the pattern definition itself",
    ("bind_all_interfaces", "scripts/security_review.py"): "the pattern definition itself",
    ("assert_in_src", "scripts/security_review.py"): "the pattern definition itself",
}


def tracked_files() -> list[Path]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    return [ROOT / p for p in out.splitlines() if (ROOT / p).is_file()]


def scan(
    patterns: dict[str, re.Pattern[str]], files: list[Path], only_code: bool
) -> list[dict[str, str]]:
    findings = []
    for f in files:
        rel = str(f.relative_to(ROOT))
        if only_code and f.suffix not in {".py", ".rs", ".toml", ".yml", ".yaml", ".sh"}:
            continue
        if rel.startswith(("tests/fixtures/", "vectors/")):
            continue  # published test vectors contain deliberate test keys
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for name, pat in patterns.items():
            if name == "assert_in_src" and not rel.startswith("src/"):
                continue
            for m in pat.finditer(text):
                if (name, rel) in ALLOWLIST:
                    continue
                line = text.count("\n", 0, m.start()) + 1
                findings.append({"check": name, "file": rel, "line": str(line)})
    return findings


def run(cmd: list[str], env: dict[str, str] | None = None, cwd: Path = ROOT) -> tuple[int, str]:
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False, env=env)
    return p.returncode, (p.stdout + p.stderr)[-4000:]


def dependency_audit(offline: bool) -> dict[str, object]:
    if offline:
        return {"status": "skipped (offline)"}
    rc, req = run(["uv", "export", "--frozen", "--no-hashes", "--all-groups", "--no-emit-project"])
    if rc != 0:
        return {"status": "error", "detail": req}
    req_file = ROOT / ".security-requirements.txt"
    # local builds such as torch==2.x+cpu are audited under their public version
    req = re.sub(r"^([A-Za-z0-9_.\-]+==[^+\s]+)\+[A-Za-z0-9.]+", r"\1", req, flags=re.MULTILINE)
    req_file.write_text(req, encoding="utf-8")
    try:
        rc, out = run(
            [
                sys.executable,
                "-m",
                "pip_audit",
                "-r",
                str(req_file),
                "--progress-spinner",
                "off",
                "--disable-pip",
                "--no-deps",
            ]
        )
    finally:
        req_file.unlink(missing_ok=True)
    result: dict[str, object] = {"python": {"rc": rc, "output": out}}
    deny = shutil.which("cargo-deny") or str(Path.home() / ".cargo" / "bin" / "cargo-deny")
    if Path(deny).exists():
        cargo_bin = Path.home() / ".cargo" / "bin"
        cargo_env = os.environ | {"PATH": f"{cargo_bin}:{os.environ.get('PATH', '')}"}
        rc2, out2 = run([deny, "check", "advisories"], env=cargo_env, cwd=ROOT / "rust" / "esp-rs")
        result["rust"] = {"rc": rc2, "output": out2}
    result["status"] = (
        "ok" if all(v["rc"] == 0 for k, v in result.items() if isinstance(v, dict)) else "findings"
    )  # type: ignore[index]
    return result


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--offline", action="store_true")
    ap.add_argument("--fuzz-iterations", type=int, default=100_000)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args(argv)
    files = tracked_files()
    report: dict[str, object] = {
        "secrets": scan(SECRET_PATTERNS, files, only_code=False),
        "unsafe_patterns": scan(UNSAFE_PATTERNS, files, only_code=True),
        "allowlisted": [
            {"check": c, "file": f, "why": w}
            for (c, f), w in ALLOWLIST.items()
            if f != "scripts/security_review.py"
        ],
        "dependency_audit": dependency_audit(args.offline),
    }
    env = os.environ | {"ESP_FUZZ_ITERATIONS": str(args.fuzz_iterations)}
    rc_fuzz, out_fuzz = run([sys.executable, "-m", "pytest", "-q", "tests/fuzz"], env=env)
    rc_inv, out_inv = run([sys.executable, "-m", "pytest", "-q", "-m", "security"])
    report["parser_fuzz"] = {
        "rc": rc_fuzz,
        "iterations": args.fuzz_iterations,
        "tail": out_fuzz[-300:],
    }
    report["protocol_invariants"] = {"rc": rc_inv, "tail": out_inv[-300:]}
    audit = report["dependency_audit"]
    ok = (
        not report["secrets"]
        and not report["unsafe_patterns"]
        and rc_fuzz == 0
        and rc_inv == 0
        and isinstance(audit, dict)
        and audit.get("status") in {"ok", "skipped (offline)"}
    )
    report["passed"] = ok
    text = json.dumps(report, indent=2)
    if args.json:
        args.json.write_text(text + "\n", encoding="utf-8")
    print(text)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
