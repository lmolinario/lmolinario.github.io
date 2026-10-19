#!/usr/bin/env python3
"""Check the inline application JavaScript with Node's syntax checker."""
from pathlib import Path
import re
import subprocess
import sys
import tempfile

root = Path(__file__).resolve().parents[1]
paths = [
    root / "tools/domain-risk-scan/index.html",
    root / "tools/domain-risk-scan/templates/index.html",
]
script = re.compile(r"<script\b([^>]*)>([\s\S]*?)</script>", re.IGNORECASE)
for path in paths:
    html = path.read_text(encoding="utf-8")
    matched = [
        match.group(2)
        for match in script.finditer(html)
        if not re.search(r'\btype=["\']application/ld\+json', match.group(1), re.I)
        and "src=" not in match.group(1)
        and match.group(2).strip()
    ]
    if not matched:
        sys.exit(f"No JavaScript found: {path}")
    for i, code in enumerate(matched):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js", encoding="utf-8") as temp:
            temp.write(code)
            temp.flush()
            subprocess.run(["node", "--check", temp.name], check=True)
    print(f"Valid inline JS: {path.relative_to(root)} ({len(matched)} scripts)")
