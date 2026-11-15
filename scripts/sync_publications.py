#!/usr/bin/env python3
"""Synchronize verified Red Hot Cyber publications with the static portfolio.

The JSON catalogue is authoritative. Discovery from the publisher is conservative:
unknown URLs are added only after title, publication date and author verification.
No claim is made that publisher HTML or availability will remain stable.
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
CATALOGUE = ROOT / "data/publications.json"
HOME = ROOT / "index.html"
PUBLICATIONS = ROOT / "publications/index.html"
SITEMAP = ROOT / "sitemap.xml"
DOMAIN = "www.redhotcyber.com"
AUTHOR = "Lello Molinario"
PAGE_RE = re.compile(
    r'(?:<article class="card" data-article-topic="(?:ai|forensics)">[\s\S]*?</article>)+'
)
HOME_RE = re.compile(
    r'(<div class="article-list" id="article-list">)[\s\S]*?(</div>)'
)


def safe_text(value: str) -> str:
    return html.escape(value, quote=True)


def load() -> tuple[dict, list[dict]]:
    data = json.loads(CATALOGUE.read_text(encoding="utf-8"))
    rows = data["articles"]
    ids, urls = set(), set()
    for row in rows:
        url = urlsplit(row["url"])
        if url.scheme != "https" or url.hostname != DOMAIN or not url.path.startswith("/post/"):
            raise ValueError(f"Unsupported publisher URL: {row['url']}")
        dt.date.fromisoformat(row["date"])
        if row["id"] in ids or row["url"] in urls:
            raise ValueError("Duplicate publication ID or URL")
        if row["topic"] not in ("forensics", "ai"):
            raise ValueError("Unsupported article category")
        if not row["title"].strip() or not row["description"].strip():
            raise ValueError("Article missing title or description")
        ids.add(row["id"])
        urls.add(row["url"])
    rows.sort(key=lambda a: (a["date"], a["id"]), reverse=True)
    return data, rows


def display_date(iso_date: str) -> str:
    d = dt.date.fromisoformat(iso_date)
    return f"{d.day} {d.strftime('%B %Y')}"


def publication_card(row: dict) -> str:
    tags = "".join(f'<span class="pill">{safe_text(tag)}</span>' for tag in row["tags"][:5])
    return (
        f'<article class="card" data-article-topic="{row["topic"]}">'
        f'<span class="status live">Published · Red Hot Cyber · {display_date(row["date"])}</span>'
        f'<h3 lang="it">{safe_text(row["title"])}</h3>'
        f'<p>{safe_text(row["description"])}</p>'
        f'<div class="pill-row">{tags}</div>'
        f'<div class="actions"><a class="btn primary" href="{safe_text(row["url"])}"'
        ' target="_blank" rel="noopener noreferrer">Read on Red Hot Cyber →</a></div>'
        '</article>'
    )


def home_card(row: dict, n: int) -> str:
    subject = "AI reliability" if row["topic"] == "ai" else "Digital evidence"
    return (
        f'<a class="article" data-topic="{row["topic"]}" href="{safe_text(row["url"])}"'
        ' target="_blank" rel="noopener noreferrer">'
        f'<span class="article-number">{n:02d}</span>'
        f'<h3 lang="it">{safe_text(row["title"])}</h3>'
        f'<span class="article-type">{subject} · Red Hot Cyber</span>'
        '<span class="article-arrow" aria-hidden="true">↗</span></a>'
    )


def update_structured_data(page: str, rows: list[dict]) -> str:
    script_re = re.compile(r'(<script type="application/ld\+json">)([\s\S]*?)(</script>)')
    found = script_re.search(page)
    if not found:
        raise ValueError("Publications JSON-LD not found")
    data = json.loads(found.group(2))
    graph = data["@graph"]
    collection = next(x for x in graph if x["@type"] == "CollectionPage")
    collection["hasPart"] = [
        {"@id": f"https://lmolinario.github.io/publications/#{row['id']}"}
        for row in rows
    ]
    collection["dateModified"] = max(
        collection.get("dateModified", "2000-01-01"), rows[0]["date"]
    )
    graph[:] = [x for x in graph if x.get("@type") != "Article"]
    for row in rows:
        graph.append({
            "@type": "Article",
            "@id": f"https://lmolinario.github.io/publications/#{row['id']}",
            "headline": row["title"],
            "datePublished": row["date"],
            "inLanguage": "it",
            "author": {"@id": "https://lmolinario.github.io/#person"},
            "publisher": {"@type": "Organization", "name": "Red Hot Cyber", "url": "https://www.redhotcyber.com/"},
            "url": row["url"],
            "mainEntityOfPage": row["url"],
            "description": row["description"],
            "about": row.get("about", row["tags"]),
        })
    encoded = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
    return page[:found.start(2)] + encoded + page[found.end(2):]


def render(data: dict, rows: list[dict]) -> set[Path]:
    pub = PUBLICATIONS.read_text(encoding="utf-8")
    match = PAGE_RE.search(pub)
    if not match:
        raise ValueError("Publications article marker missing")
    pub = pub[:match.start()] + "".join(publication_card(a) for a in rows) + pub[match.end():]
    pub = update_structured_data(pub, rows)
    home = HOME.read_text(encoding="utf-8")
    featured = rows[:5]
    if not HOME_RE.search(home):
        raise ValueError("Homepage article list missing")
    home = HOME_RE.sub(
        lambda m: m.group(1) + "".join(home_card(a, i) for i, a in enumerate(featured, 1)) + m.group(2),
        home, count=1,
    )
    home = re.sub(r'All \d+ technical articles', f'All {len(rows)} technical articles', home)
    home = re.sub(r'\d+ technical articles ↗</strong>', f'{len(rows)} technical articles ↗</strong>', home)
    home = re.sub(r'Showing \d+ selected articles', f'Showing {len(featured)} selected articles', home)
    changes = {}
    for file, content in ((HOME, home), (PUBLICATIONS, pub)):
        if file.read_text(encoding="utf-8") != content:
            changes[file] = content
    if changes:
        xml = SITEMAP.read_text(encoding="utf-8")
        today = dt.date.today().isoformat()
        for url_path in ("/", "/publications/"):
            addr = "https://lmolinario.github.io" + url_path
            pattern = re.compile(
                r'(<loc>' + re.escape(addr) + r'</loc>\s*<lastmod>)[^<]+(</lastmod>)'
            )
            xml, found = pattern.subn(lambda m: m.group(1) + today + m.group(2), xml)
            if found != 1:
                raise ValueError("Missing canonical sitemap URL: " + addr)
        if SITEMAP.read_text(encoding="utf-8") != xml:
            changes[SITEMAP] = xml
    for file, content in changes.items():
        file.write_text(content, encoding="utf-8")
        print("Updated:", file.relative_to(ROOT))
    return set(changes)


class Document(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.meta: dict[str, str] = {}
        self.h1_parts: list[str] = []
        self.in_h1 = False
        self.body_parts: list[str] = []
        self.in_schema = False
        self.schema_parts: list[str] = []
        self.schemas: list[dict] = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and attrs.get("href"):
            self.links.append(attrs["href"])
        if tag == "meta":
            k = attrs.get("property") or attrs.get("name")
            if k:
                self.meta[k.lower()] = attrs.get("content", "")
        if tag == "h1":
            self.in_h1 = True
        if tag == "script" and attrs.get("type") == "application/ld+json":
            self.in_schema = True
            self.schema_parts = []

    def handle_data(self, data):
        if self.in_h1:
            self.h1_parts.append(data)
        if self.in_schema:
            self.schema_parts.append(data)
        else:
            self.body_parts.append(data)

    def handle_endtag(self, tag):
        if tag == "h1":
            self.in_h1 = False
        if tag == "script" and self.in_schema:
            try:
                self.schemas.append(json.loads("".join(self.schema_parts)))
            except ValueError:
                pass
            self.in_schema = False


def fetch(url: str) -> str:
    req = Request(url, headers={
        "User-Agent": "LelloMolinarioPublicationMonitor/1.0 (+https://lmolinario.github.io/)",
        "Accept": "text/html",
    })
    with urlopen(req, timeout=18) as response:
        if response.status != 200:
            raise ValueError("Unexpected HTTP status")
        payload = response.read(1_500_000)
        if not payload:
            raise ValueError("Empty publisher response")
        return payload.decode("utf-8", errors="replace")


def has_verified_author(document: Document) -> bool:
    if document.meta.get("author", "").strip().casefold() == AUTHOR.casefold():
        return True
    for schema in document.schemas:
        if re.search(r'"author"\s*:\s*\{[^{}]{0,700}"name"\s*:\s*"Lello Molinario"',
                     json.dumps(schema, ensure_ascii=False), flags=re.I):
            return True
    text = re.sub(r'\s+', ' ', ' '.join(document.body_parts))
    return bool(re.search(r'\bAutore\s+Lello Molinario\b', text, flags=re.I))


def discover(data: dict, rows: list[dict]) -> bool:
    try:
        content = fetch(data["source_author_url"])
    except (HTTPError, URLError, TimeoutError, ValueError) as exc:
        print("Publisher discovery unavailable; catalogue preserved:", exc, file=sys.stderr)
        return False
    listing = Document()
    listing.feed(content)
    seen = {row["url"].rstrip("/") for row in rows}
    urls = []
    for href in listing.links:
        uri = urljoin(data["source_author_url"], href)
        parsed = urlsplit(uri)
        clean = f"https://{DOMAIN}{parsed.path}"
        if parsed.hostname != DOMAIN or not parsed.path.startswith("/post/"):
            continue
        if parsed.path.startswith(("/post/author/", "/post/category/")):
            continue
        if clean.rstrip("/") not in seen and clean not in urls:
            urls.append(clean)
    count = 0
    for url in urls[:25]:
        try:
            article = Document()
            article.feed(fetch(url))
            if not has_verified_author(article):
                print("Skipped unverified byline:", url)
                continue
            title = re.sub(r'\s+', ' ', ''.join(article.h1_parts)).strip()
            date_raw = (
                article.meta.get("article:published_time")
                or article.meta.get("datepublished")
            )
            for item in article.schemas:
                serialized = json.dumps(item, ensure_ascii=False)
                match = re.search(r'"datePublished"\s*:\s*"([0-9]{4}-[0-9]{2}-[0-9]{2})', serialized)
                if not date_raw and match:
                    date_raw = match.group(1)
            description = (
                article.meta.get("description") or article.meta.get("og:description") or ""
            ).strip()
            if not date_raw or not re.match(r'^\d{4}-\d{2}-\d{2}', date_raw):
                print("Skipped: no verifiable publication date", url)
                continue
            day = dt.date.fromisoformat(date_raw[:10])
            if day > dt.date.today() or len(title) < 20 or len(description) < 40:
                print("Skipped: incomplete or future article metadata", url)
                continue
            slug = urlsplit(url).path.strip("/").split("/")[-1]
            topic = "ai" if re.search(r'\bAI\b|intelligenza artificiale|adversarial', title, re.I) else "forensics"
            rows.append({
                "id": "redhotcyber-" + slug,
                "title": title,
                "url": url if url.endswith("/") else url + "/",
                "date": day.isoformat(),
                "description": re.sub(r'\s+', ' ', description)[:460],
                "topic": topic,
                "tags": ["Digital Forensics", "AI Security" if topic == "ai" else "Digital Evidence"],
                "about": ["Digital Forensics", "AI Security" if topic == "ai" else "Digital Evidence"],
            })
            count += 1
            print("Verified new article:", day, title)
        except (HTTPError, URLError, TimeoutError, ValueError) as exc:
            print("Skipped inaccessible candidate:", url, str(exc), file=sys.stderr)
    if count:
        rows.sort(key=lambda a: (a["date"], a["id"]), reverse=True)
        CATALOGUE.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Publisher discovery: {count} new article(s), {len(rows)} total")
    return count > 0


def check(rows: list[dict]) -> None:
    pub = PUBLICATIONS.read_text(encoding="utf-8")
    home = HOME.read_text(encoding="utf-8")
    for row in rows:
        if row["url"] not in pub:
            raise ValueError("Publication missing from index: " + row["url"])
    schema = re.search(r'<script type="application/ld\+json">([\s\S]*?)</script>', pub)
    if not schema:
        raise ValueError("Missing publication JSON-LD")
    found = [x for x in json.loads(schema.group(1))["@graph"] if x.get("@type") == "Article"]
    if len(found) != len(rows):
        raise ValueError(f"Publication JSON-LD count mismatch: {len(found)} != {len(rows)}")
    if HOME_RE.search(home) is None or rows[0]["url"] not in home:
        raise ValueError("Homepage latest publication does not match catalogue")
    if not re.search(rf'All {len(rows)} technical articles', home):
        raise ValueError("Homepage article count does not match catalogue")
    print(f"Publication consistency verified: {len(rows)} records")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--discover", action="store_true", help="Check the official publisher archive")
    parser.add_argument("--write", action="store_true", help="Render updated static HTML/JSON-LD")
    parser.add_argument("--check", action="store_true", help="Validate publication links and schema")
    args = parser.parse_args()
    data, rows = load()
    if args.discover:
        discover(data, rows)
    if args.write:
        render(data, rows)
    if args.check or not (args.discover or args.write):
        check(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
