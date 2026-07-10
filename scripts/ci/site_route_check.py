#!/usr/bin/env python3
"""Validate TinyZKP static-site internal routes, assets, anchors, and sitemap URLs."""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
import json
from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
import re
from urllib.parse import unquote, urlparse


ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
SITEMAP = SITE / "sitemap.xml"
ROBOTS_TXT = SITE / "robots.txt"
WORKER = SITE / "_worker.js"
LOCAL_HOSTS = {"tinyzkp.com", "www.tinyzkp.com"}
SKIPPED_SCHEMES = {"http", "https", "mailto", "tel", "javascript", "data"}
REQUIRED_ROBOTS_SITEMAP = "Sitemap: https://tinyzkp.com/sitemap.xml"
ROUTE_ATTRS = {"href", "src", "action"}
URL_META_PROPERTIES = {"og:image", "og:url"}
URL_META_NAMES = {"twitter:image"}
IMPORT_RE = re.compile(r'import\s+\*\s+as\s+(\w+)\s+from\s+"\.\/functions\/api\/([^"]+)\.js";')
ROUTE_RE = re.compile(r'"(/api/[^"]+)":\s*(\w+)')
JS_ROUTE_RE = re.compile(
    r"(?:fetch|apiPost)\(\s*['\"]([^'\"]+)['\"]"
    r"|window\.location\.href\s*=\s*['\"]([^'\"]+)['\"]"
)

PUBLIC_HTML = {
    "index.html",
    "engine.html",
    "benchmarks.html",
    "plonky3.html",
    "security.html",
    "docs.html",
    "pricing.html",
    "status.html",
    "contact.html",
}
LEGAL_HTML = {"privacy.html", "terms.html", "requests.html"}
PERMANENTLY_REDIRECTED_ROUTES = {
    "/account",
    "/welcome",
    "/compute",
    "/receipts",
    "/try",
    "/verify",
    "/signup",
    "/pilot",
    "/platform-rollout",
    "/enterprise",
    "/evaluation",
    "/mcp",
    "/changelog",
}
GONE_ROUTE_PREFIXES = {
    "/agents",
    "/agent-",
    "/verifiable-agent-output",
    "/roi",
    "/calculator",
    "/fit",
    "/use-cases",
    "/compare",
    "/integrations",
    "/apps",
    "/badges",
    "/examples",
    "/limits",
    "/recipes",
    "/research",
    "/templates",
}
PUBLIC_EMAIL_RE = re.compile(
    r"(?:mailto:|[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})",
    re.IGNORECASE,
)
OBFUSCATED_EMAIL_MARKERS = ("__cf_email__", "/cdn-cgi/l/email-protection")
PUBLIC_TEXT_SUFFIXES = {".html", ".js", ".json", ".txt", ".xml"}


@dataclass(frozen=True)
class Link:
    source: Path
    line: int
    attr: str
    raw: str


@dataclass
class PageMetadata:
    h1_count: int = 0
    title_count: int = 0
    description_count: int = 0
    canonical_hrefs: list[str] | None = None
    robots_contents: list[str] | None = None

    def __post_init__(self) -> None:
        if self.canonical_hrefs is None:
            self.canonical_hrefs = []
        if self.robots_contents is None:
            self.robots_contents = []


@dataclass(frozen=True)
class SitemapURL:
    loc: str
    path: str
    canonical_url: str


class SiteLinkParser(HTMLParser):
    def __init__(self, source: Path) -> None:
        super().__init__(convert_charrefs=True)
        self.source = source
        self.links: list[Link] = []
        self.anchors: set[str] = set()
        self.metadata = PageMetadata()
        self._ld_json_source_line: int | None = None
        self._ld_json_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        attrs_dict = {key.lower(): value for key, value in attrs if value is not None}
        line, _ = self.getpos()
        if tag_lower == "h1":
            self.metadata.h1_count += 1
        if tag_lower == "title":
            self.metadata.title_count += 1
        if tag_lower == "meta" and attrs_dict.get("name", "").lower() == "description":
            self.metadata.description_count += 1
        if tag_lower == "meta" and attrs_dict.get("name", "").lower() == "robots":
            content = attrs_dict.get("content", "").strip()
            if content:
                self.metadata.robots_contents.append(content)
        if tag_lower == "link" and "canonical" in attrs_dict.get("rel", "").lower().split():
            href = attrs_dict.get("href", "").strip()
            if href:
                self.metadata.canonical_hrefs.append(href)
        if tag_lower == "meta":
            property_name = attrs_dict.get("property", "").lower()
            name = attrs_dict.get("name", "").lower()
            content = attrs_dict.get("content", "").strip()
            if content and (property_name in URL_META_PROPERTIES or name in URL_META_NAMES):
                self.links.append(Link(self.source, line, "meta-content", content))
        if tag_lower == "script" and attrs_dict.get("type", "").lower() == "application/ld+json":
            self._ld_json_source_line = line
            self._ld_json_chunks = []
        for attr, value in attrs:
            if value is None:
                continue
            if attr in ROUTE_ATTRS:
                self.links.append(Link(self.source, line, attr, value.strip()))
            if attr == "id" and value.strip():
                self.anchors.add(value.strip())
            if tag_lower == "a" and attr == "name" and value.strip():
                self.anchors.add(value.strip())

    def handle_data(self, data: str) -> None:
        if self._ld_json_source_line is not None:
            self._ld_json_chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() != "script" or self._ld_json_source_line is None:
            return
        text = "".join(self._ld_json_chunks).strip()
        line = self._ld_json_source_line
        self._ld_json_source_line = None
        self._ld_json_chunks = []
        if not text:
            return
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            self.links.append(Link(self.source, line, "json-ld", "__INVALID_JSON_LD__"))
            return
        for url in json_ld_urls(data):
            self.links.append(Link(self.source, line, "json-ld", url))


def json_ld_urls(value: object) -> list[str]:
    urls: list[str] = []
    if isinstance(value, dict):
        for item in value.values():
            urls.extend(json_ld_urls(item))
    elif isinstance(value, list):
        for item in value:
            urls.extend(json_ld_urls(item))
    elif isinstance(value, str) and value.startswith(("https://tinyzkp.com/", "https://www.tinyzkp.com/", "/")):
        urls.append(value)
    return urls


def route_for_html(path: Path) -> str:
    rel = path.relative_to(SITE).as_posix()
    if rel == "index.html":
        return "/"
    if rel.endswith("/index.html"):
        return f"/{rel[:-len('/index.html')]}"
    return f"/{rel[:-len('.html')]}"


def is_retired_html(path: Path) -> bool:
    route = route_for_html(path)
    return route in PERMANENTLY_REDIRECTED_ROUTES or any(
        route.startswith(prefix) for prefix in GONE_ROUTE_PREFIXES
    )


def parse_html_files() -> tuple[list[Link], dict[Path, set[str]], dict[Path, PageMetadata]]:
    links: list[Link] = []
    anchors: dict[Path, set[str]] = {}
    page_metadata: dict[Path, PageMetadata] = {}
    for path in sorted(SITE.rglob("*.html")):
        if is_retired_html(path):
            continue
        parser = SiteLinkParser(path)
        parser.feed(path.read_text(encoding="utf-8"))
        links.extend(parser.links)
        anchors[path] = parser.anchors
        page_metadata[path] = parser.metadata
    return links, anchors, page_metadata


def parse_literal_script_routes() -> list[Link]:
    links: list[Link] = []
    for path in sorted([*SITE.glob("*.html"), *SITE.glob("*.js")]):
        if path.suffix == ".html" and is_retired_html(path):
            continue
        text = path.read_text(encoding="utf-8")
        line_starts = [0]
        for match in re.finditer(r"\n", text):
            line_starts.append(match.end())
        for match in JS_ROUTE_RE.finditer(text):
            raw = next(group for group in match.groups() if group is not None)
            line = 1
            for index, start in enumerate(line_starts, start=1):
                if start > match.start():
                    break
                line = index
            links.append(Link(path, line, "js-route", raw.strip()))
    return links


def is_external(parsed) -> bool:
    if parsed.scheme not in {"http", "https"}:
        return False
    return parsed.netloc.lower() not in LOCAL_HOSTS


def normalize_link(raw: str, source: Path) -> tuple[str, str] | None:
    if not raw or raw.startswith("//"):
        return None
    parsed = urlparse(raw)
    if parsed.scheme in SKIPPED_SCHEMES and is_external(parsed):
        return None
    if parsed.scheme in {"mailto", "tel", "javascript", "data"}:
        return None
    if parsed.scheme in {"http", "https"} and is_external(parsed):
        return None
    if parsed.scheme and parsed.scheme not in {"http", "https"}:
        return None

    fragment = unquote(parsed.fragment)
    path = unquote(parsed.path)
    if not path and fragment:
        path = "/" + source.relative_to(SITE).as_posix()
    if not path:
        return None
    if not path.startswith("/"):
        base = "/" + source.relative_to(SITE).parent.as_posix().strip("/")
        path = f"{base}/{path}" if base != "/" else f"/{path}"
    return path, fragment


def worker_api_routes() -> tuple[dict[str, Path], list[str]]:
    failures: list[str] = []
    if not WORKER.is_file():
        return {}, ["site/_worker.js is missing"]

    worker_text = WORKER.read_text(encoding="utf-8")
    imports_by_var: dict[str, Path] = {}
    for var_name, module_name in IMPORT_RE.findall(worker_text):
        imports_by_var[var_name] = SITE / "functions" / "api" / f"{module_name}.js"

    routes: dict[str, Path] = {}
    for route_path, var_name in ROUTE_RE.findall(worker_text):
        module_path = imports_by_var.get(var_name)
        if module_path is None:
            failures.append(f"site/_worker.js: {route_path} maps to unimported module {var_name}")
            continue
        routes[route_path] = module_path

    public_functions = {
        path.stem: path
        for path in (SITE / "functions" / "api").glob("*.js")
        if not path.name.startswith("_")
    }
    routed_functions = {path.stem for path in routes.values()}
    imported_functions = {path.stem for path in imports_by_var.values()}

    for stem, path in sorted(public_functions.items()):
        expected_route = f"/api/{stem}"
        if stem not in imported_functions:
            failures.append(f"{display_path(path)} is not imported by site/_worker.js")
        if expected_route not in routes:
            failures.append(f"{display_path(path)} is not routed as {expected_route} in site/_worker.js")

    for route_path, path in sorted(routes.items()):
        if not path.is_file():
            failures.append(f"site/_worker.js: {route_path} points to missing {display_path(path)}")

    for var_name, path in sorted(imports_by_var.items()):
        if not path.is_file():
            failures.append(f"site/_worker.js imports missing module {var_name}: {display_path(path)}")
        if path.stem not in routed_functions and not path.name.startswith("_"):
            failures.append(f"site/_worker.js imports {display_path(path)} but does not route it")

    return routes, failures


def resolve_static_path(path: str, api_routes: dict[str, Path]) -> Path | None:
    if path.startswith("/api/"):
        return api_routes.get(path.rstrip("/"))

    if path == "/":
        return SITE / "index.html"

    candidate = SITE / path.lstrip("/")
    if candidate.is_file():
        return candidate
    if candidate.suffix:
        return None

    html_candidate = candidate.with_suffix(".html")
    if html_candidate.is_file():
        return html_candidate

    index_candidate = candidate / "index.html"
    if index_candidate.is_file():
        return index_candidate

    return None


def sitemap_paths() -> list[str]:
    records, _ = sitemap_url_records()
    return [record.path for record in records]


def sitemap_url_records() -> tuple[list[SitemapURL], list[str]]:
    if not SITEMAP.is_file():
        return [], ["site/sitemap.xml is missing"]
    tree = ET.parse(SITEMAP)
    namespace = {"sm": "http://www.sitemaps.org/schemas/sitemap/0.9"}
    records: list[SitemapURL] = []
    failures: list[str] = []
    for loc in tree.findall(".//sm:loc", namespace):
        if loc.text:
            record = sitemap_url_record(loc.text.strip())
            if record is None:
                failures.append(f"site/sitemap.xml: invalid TinyZKP URL {loc.text.strip()!r}")
            else:
                records.append(record)
    return records, failures


def sitemap_url_record(loc: str) -> SitemapURL | None:
    parsed = urlparse(loc)
    if parsed.scheme not in {"http", "https"} or parsed.netloc.lower() not in LOCAL_HOSTS:
        return None
    if parsed.query or parsed.fragment:
        return None
    path = parsed.path or "/"
    if not path.startswith("/"):
        return None
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    canonical_url = "https://tinyzkp.com" if path == "/" else f"https://tinyzkp.com{path}"
    return SitemapURL(loc=loc, path=path, canonical_url=canonical_url)


def expected_canonical_url(path: Path) -> str:
    rel = path.relative_to(SITE).as_posix()
    if rel == "index.html":
        return "https://tinyzkp.com"
    if rel.endswith("/index.html"):
        route = rel[: -len("/index.html")]
    elif rel.endswith(".html"):
        route = rel[: -len(".html")]
    else:
        route = rel
    return f"https://tinyzkp.com/{route}"


def robots_tokens(metadata: PageMetadata) -> set[str]:
    tokens: set[str] = set()
    for content in metadata.robots_contents or []:
        tokens.update(token for token in re.split(r"[\s,]+", content.lower()) if token)
    return tokens


def is_noindex(metadata: PageMetadata) -> bool:
    return "noindex" in robots_tokens(metadata)


def validate_robots_txt() -> list[str]:
    if not ROBOTS_TXT.is_file():
        return ["site/robots.txt is missing"]
    text = ROBOTS_TXT.read_text(encoding="utf-8")
    if REQUIRED_ROBOTS_SITEMAP not in text:
        return [f"site/robots.txt must declare {REQUIRED_ROBOTS_SITEMAP!r}"]
    return []


def validate_no_public_email() -> list[str]:
    """Require public web contact to use HTTPS/non-email channels only."""
    failures: list[str] = []
    for path in sorted(SITE.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in PUBLIC_TEXT_SUFFIXES:
            continue
        relative_parts = path.relative_to(SITE).parts
        if any(part.startswith(".") and part != ".well-known" for part in relative_parts):
            continue
        text = path.read_text(encoding="utf-8")
        for line_number, line in enumerate(text.splitlines(), start=1):
            match = PUBLIC_EMAIL_RE.search(line)
            if match:
                failures.append(
                    f"{display_path(path)}:{line_number}: public email contact is forbidden: {match.group(0)!r}"
                )
            for marker in OBFUSCATED_EMAIL_MARKERS:
                if marker in line.lower():
                    failures.append(
                        f"{display_path(path)}:{line_number}: obfuscated public email contact is forbidden: {marker!r}"
                    )

    security_txt = SITE / ".well-known" / "security.txt"
    if not security_txt.is_file():
        failures.append("site/.well-known/security.txt is missing")
        return failures
    lines = [line.strip() for line in security_txt.read_text(encoding="utf-8").splitlines()]
    contacts = [line.removeprefix("Contact:").strip() for line in lines if line.startswith("Contact:")]
    if not contacts:
        failures.append("site/.well-known/security.txt must contain an HTTPS Contact field")
    for contact in contacts:
        if not contact.startswith("https://"):
            failures.append("site/.well-known/security.txt Contact fields must use HTTPS")
    if not any(line.startswith("Expires:") for line in lines):
        failures.append("site/.well-known/security.txt must contain an Expires field")
    return failures


def display_path(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def main() -> int:
    links, anchors, page_metadata = parse_html_files()
    links.extend(parse_literal_script_routes())
    api_routes, route_table_failures = worker_api_routes()
    failures: list[str] = []
    failures.extend(route_table_failures)
    failures.extend(validate_robots_txt())
    failures.extend(validate_no_public_email())
    sitemap_records, sitemap_failures = sitemap_url_records()
    failures.extend(sitemap_failures)

    worker_text = WORKER.read_text(encoding="utf-8") if WORKER.is_file() else ""
    html_paths = sorted(SITE.rglob("*.html"))
    for path in html_paths:
        rel = path.relative_to(SITE).as_posix()
        route = route_for_html(path)
        if rel in PUBLIC_HTML or rel in LEGAL_HTML:
            if is_retired_html(path):
                failures.append(f"{display_path(path)} is both public and retired")
            continue
        if not is_retired_html(path):
            failures.append(f"{display_path(path)} is neither an allowed public page nor retired")
            continue
        if route in PERMANENTLY_REDIRECTED_ROUTES and f'["{route}",' not in worker_text:
            failures.append(f"{display_path(path)} lacks its required worker redirect")
        if route not in PERMANENTLY_REDIRECTED_ROUTES and not any(
            f'"{prefix}"' in worker_text for prefix in GONE_ROUTE_PREFIXES if route.startswith(prefix)
        ):
            failures.append(f"{display_path(path)} lacks its required worker 410 policy")
    sitemap_canonical_urls = [record.canonical_url for record in sitemap_records]
    sitemap_canonical_set = set(sitemap_canonical_urls)
    if len(sitemap_canonical_urls) != len(sitemap_canonical_set):
        failures.append("site/sitemap.xml must not contain duplicate canonical URLs")

    page_by_canonical: dict[str, Path] = {}
    for path, metadata in sorted(page_metadata.items()):
        if metadata.h1_count != 1:
            failures.append(f"{display_path(path)} must have exactly one primary <h1>; found {metadata.h1_count}")
        if metadata.title_count != 1:
            failures.append(f"{display_path(path)} must have exactly one <title>; found {metadata.title_count}")
        if metadata.description_count != 1:
            failures.append(
                f"{display_path(path)} must have exactly one meta description; found {metadata.description_count}"
            )
        if len(metadata.robots_contents or []) > 1:
            failures.append(
                f"{display_path(path)} must have no more than one meta robots tag; "
                f"found {len(metadata.robots_contents or [])}"
            )
        expected_canonical = expected_canonical_url(path)
        if metadata.canonical_hrefs != [expected_canonical]:
            failures.append(
                f"{display_path(path)} canonical must be {expected_canonical!r}; "
                f"found {metadata.canonical_hrefs}"
            )
        page_by_canonical[expected_canonical] = path
        if is_noindex(metadata):
            if expected_canonical in sitemap_canonical_set:
                failures.append(f"{display_path(path)} is noindex but appears in site/sitemap.xml")
        elif expected_canonical not in sitemap_canonical_set:
            failures.append(f"{display_path(path)} is indexable but missing from site/sitemap.xml")

    for record in sitemap_records:
        page = page_by_canonical.get(record.canonical_url)
        if page is None:
            failures.append(f"site/sitemap.xml: {record.loc!r} has no matching page canonical")
        elif is_noindex(page_metadata[page]):
            failures.append(f"site/sitemap.xml: {record.loc!r} points to noindex page {display_path(page)}")

    for link in links:
        normalized = normalize_link(link.raw, link.source)
        if link.attr == "json-ld" and link.raw == "__INVALID_JSON_LD__":
            failures.append(f"{display_path(link.source)}:{link.line}: invalid JSON-LD block")
            continue
        if normalized is None:
            continue
        path, fragment = normalized
        if link.attr == "json-ld":
            fragment = ""
        resolved = resolve_static_path(path, api_routes)
        if resolved is None:
            failures.append(
                f"{display_path(link.source)}:{link.line}: broken {link.attr} {link.raw!r}"
            )
            continue
        if fragment and resolved.suffix == ".html" and fragment not in anchors.get(resolved, set()):
            failures.append(
                f"{display_path(link.source)}:{link.line}: missing anchor "
                f"#{fragment} in {display_path(resolved)} for {link.raw!r}"
            )

    for record in sitemap_records:
        resolved = resolve_static_path(record.path, api_routes)
        if resolved is None or resolved.suffix != ".html":
            failures.append(f"site/sitemap.xml: unresolved URL path {record.path!r}")

    if failures:
        print("Static site route check failed:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    checked_routes = len(links) + len(sitemap_records)
    print(f"PASS static site route check ({checked_routes} links and sitemap entries)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
