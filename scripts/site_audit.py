#!/usr/bin/env python3
"""Deterministic build-time checks for the public static website.

No external HTTP requests: runs on each GitHub pull request and main push.
"""
from __future__ import annotations

import json
from datetime import date
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree import ElementTree

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://lmolinario.github.io"
PUBLIC_PAGES = [
    "/", "/about/", "/research/", "/publications/", "/projects/",
    "/projects/evidence-first/", "/media/", "/opengovsec/",
    "/tools/", "/tools/osint-threat-radar/", "/tools/domain-risk-scan/",
    "/tools/supplier-risk-screening/", "/privacy/", "/cookies/",
    "/legal/", "/contact/",
]


class Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.meta = {}
        self.links = []
        self.title = False
        self.h1 = 0
        self.images_missing_alt = 0
        self.script_type = None
        self.structured_data = []
        self._buf = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "meta":
            key = a.get("name") or a.get("property")
            if key:
                self.meta[key.lower()] = a.get("content", "")
        if tag == "link" and a.get("rel") == "canonical":
            self.meta["canonical"] = a.get("href", "")
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        if tag == "h1":
            self.h1 += 1
        if tag == "img" and "alt" not in a:
            self.images_missing_alt += 1
        if tag == "script":
            self.script_type = a.get("type")
            self._buf = []

    def handle_data(self, data):
        if self.script_type == "application/ld+json":
            self._buf.append(data)

    def handle_endtag(self, tag):
        if tag == "script" and self.script_type == "application/ld+json":
            self.structured_data.append("".join(self._buf))
        if tag == "script":
            self.script_type = None


def html_path(url_path: str) -> Path:
    path = url_path.lstrip("/")
    return ROOT / (path + "index.html" if url_path.endswith("/") else path)


def audit() -> list[str]:
    errors = []
    sitemap = ROOT / "sitemap.xml"
    root = ElementTree.parse(sitemap).getroot()
    ns = {"s": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    entries = {}
    for item in root.findall("s:url", ns):
        url = (item.findtext("s:loc", default="", namespaces=ns)).strip()
        modified = item.findtext("s:lastmod", default="", namespaces=ns)
        entries[url] = modified
        if modified:
            try:
                value = date.fromisoformat(modified)
                if value > date.today():
                    errors.append(f"future lastmod: {url}")
            except ValueError:
                errors.append(f"invalid lastmod: {url}")

    expected_urls = {ORIGIN + p for p in PUBLIC_PAGES}
    if set(entries) != expected_urls:
        errors.append(f"sitemap mismatch: missing={sorted(expected_urls-set(entries))}, extra={sorted(set(entries)-expected_urls)}")

    titles = {}
    for route in PUBLIC_PAGES:
        filepath = html_path(route)
        if not filepath.exists():
            errors.append(f"missing page: {route}")
            continue
        html = filepath.read_text(encoding="utf-8")
        page = Page()
        page.feed(html)
        if page.meta.get("canonical") != ORIGIN + route:
            errors.append(f"canonical mismatch: {route}")
        if "noindex" in page.meta.get("robots", "").lower():
            errors.append(f"public page marked noindex: {route}")
        if not page.meta.get("description"):
            errors.append(f"missing description: {route}")
        if page.h1 != 1:
            errors.append(f"expected exactly one H1: {route} (found {page.h1})")
        if page.images_missing_alt:
            errors.append(f"missing image alt: {route}")
        if not page.meta.get("canonical"):
            errors.append(f"missing canonical: {route}")
        for fragment in page.structured_data:
            try:
                json.loads(fragment)
            except ValueError:
                errors.append(f"invalid JSON-LD: {route}")
        for link in page.links:
            parsed = urlsplit(link)
            if parsed.scheme or parsed.netloc or not link.startswith("/"):
                continue
            # Root-relative links to the publicly served static file tree.
            linked_file = html_path(parsed.path)
            if not linked_file.is_file():
                errors.append(f"broken internal link {route}: {link}")
        # Titles are intentionally unique; duplicates hurt information architecture.
        import re
        title_match = re.search(r"<title[^>]*>(.*?)</title>", html, re.I | re.S)
        title = title_match.group(1).strip() if title_match else ""
        if not title:
            errors.append(f"missing title: {route}")
        elif title in titles:
            errors.append(f"duplicate title: {route} and {titles[title]}")
        titles[title] = route

    robots = (ROOT / "robots.txt").read_text(encoding="utf-8")
    if ORIGIN + "/sitemap.xml" not in robots:
        errors.append("robots.txt does not advertise sitemap")
    return errors


if __name__ == "__main__":
    problems = audit()
    for problem in problems:
        print("ERROR:", problem)
    print(f"Static site audit: {len(PUBLIC_PAGES)} indexable URLs; {len(problems)} problems.")
    raise SystemExit(1 if problems else 0)
