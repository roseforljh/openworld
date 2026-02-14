from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

SKIP_DIR_NAMES = {
    ".git",
    ".gradle",
    ".idea",
    ".vscode",
    "target",
    "build",
    "node_modules",
}

FORBIDDEN_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bsing-box\b", re.IGNORECASE), "Use OpenWorldCore terminology"),
    (re.compile(r"\bsingbox\b", re.IGNORECASE), "Use OpenWorldCore terminology"),
    (re.compile(r"\blibbox\b", re.IGNORECASE), "Use OpenWorldCore terminology"),
    (re.compile(r"\bCoreBridge\b"), "Use real symbol names (e.g., SingBoxCore/Libbox bridge)") ,
    (re.compile(r"\bRemoteClient\b"), "Use OpenWorldRemote"),
    (re.compile(r"\bIpcService\b"), "Use OpenWorldIpcService"),
    (re.compile(r"\bIpcHub\b"), "Use OpenWorldIpcHub"),
    (re.compile(r"kunbox://import\?url=", re.IGNORECASE), "Use kunbox://install-config?url="),
    (re.compile(r"#kunbox-for-android", re.IGNORECASE), "Use #openworld-for-android"),
    (re.compile(r"\bSingBoxService\b"), "Use OpenWorldService"),
    (re.compile(r"\bSingBoxIpcService\b"), "Use OpenWorldIpcService"),
    (re.compile(r"\bSingBoxIpcHub\b"), "Use OpenWorldIpcHub"),
    (re.compile(r"\bSingBoxRemote\b"), "Use OpenWorldRemote"),
]


def should_skip(path: Path) -> bool:
    parts = set(path.parts)
    if parts & SKIP_DIR_NAMES:
        return True
    return ".agent" in parts


def scan_markdown() -> list[str]:
    violations: list[str] = []
    for md in ROOT.rglob("*.md"):
        if should_skip(md):
            continue
        rel = md.relative_to(ROOT)
        text = md.read_text(encoding="utf-8", errors="ignore")
        for line_no, line in enumerate(text.splitlines(), start=1):
            lower_line = line.lower()
            allow_singbox_compat = (
                "sing-box json (compatible)" in lower_line
                or "sing-box json（兼容）" in lower_line
                or "compatible with sing-box json" in lower_line
            )
            for pattern, suggestion in FORBIDDEN_PATTERNS:
                if allow_singbox_compat and pattern.pattern == r"\bsing-box\b":
                    continue
                if pattern.search(line):
                    violations.append(
                        f"{rel}:{line_no}: forbidden term '{pattern.pattern}' -> {suggestion}\n"
                        f"    {line.strip()}"
                    )
    return violations


def main() -> int:
    violations = scan_markdown()
    if violations:
        print("Documentation terminology check failed.\n")
        print("\n".join(violations))
        return 1

    print("Documentation terminology check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
