#!/usr/bin/env python3
"""Keep static portfolio navigation and footer in sync without requiring a JS runtime.

The homepage is the authoritative markup for these shared fragments.
Run --write after changing the homepage shell; CI uses --check.
Application-specific UI (Supplier Risk Screening / operational radar) is excluded.
"""
import argparse
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PAGES = [
    "index.html",
    "about/index.html",
    "research/index.html",
    "publications/index.html",
    "projects/index.html",
    "projects/evidence-first/index.html",
    "media/index.html",
    "contact/index.html",
    "tools/index.html",
    "opengovsec/index.html",
    "tools/domain-risk-scan/index.html",
    "tools/domain-risk-scan/templates/index.html",
    "tools/osint-threat-radar/index.html",
    "privacy/index.html",
    "cookies/index.html",
    "legal/index.html",
    "blog/index.html",
    "ai-forensics/index.html",
]
HEADER = re.compile(r"<header\b[\s\S]*?</header>", re.I)
FOOTER = re.compile(r"<footer\b[\s\S]*?</footer>", re.I)


def extract(pattern: re.Pattern, content: str) -> str:
    match = pattern.search(content)
    if match is None:
        raise ValueError(f"Expected fragment not found: {pattern.pattern}")
    return match.group()


def route_from_path(name: str) -> str:
    route = "/" + name.removesuffix("index.html")
    return route if route.endswith("/") else route + "/"


def main() -> int:
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true")
    group.add_argument("--write", action="store_true")
    args = parser.parse_args()
    homepage = (ROOT / "index.html").read_text(encoding="utf-8")
    header = extract(HEADER, homepage)
    footer = extract(FOOTER, homepage)
    errors = 0

    for path in PAGES:
        file = ROOT / path
        html = file.read_text(encoding="utf-8")
        current_header = header
        route = route_from_path(path)
        if route.startswith("/tools/") and route != "/tools/":
            route = "/tools/"
        if route != "/":
            needle = f'<a href="{route}">'
            if needle in header:
                current_header = header.replace(
                    needle, f'<a href="{route}" aria-current="page">', 1
                )
        replacement = HEADER.sub(lambda _: current_header, html, count=1)
        replacement = FOOTER.sub(lambda _: footer, replacement, count=1)
        if replacement != html:
            if args.write:
                file.write_text(replacement, encoding="utf-8")
                print("Updated:", path)
            else:
                print("Out of sync:", path)
                errors += 1
    if errors:
        print(f"{errors} out-of-sync pages. Run python scripts/sync_site_shell.py --write")
    else:
        print(f"Shared shell verified: {len(PAGES)} pages")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
