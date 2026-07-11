import pathlib

import site_route_check as check


def test_expected_canonical_url_uses_extensionless_public_routes():
    assert check.expected_canonical_url(check.SITE / "index.html") == "https://tinyzkp.com"
    assert check.expected_canonical_url(check.SITE / "docs.html") == "https://tinyzkp.com/docs"
    assert (
        check.expected_canonical_url(check.SITE / "use-cases" / "mcp-zero-knowledge-proof.html")
        == "https://tinyzkp.com/use-cases/mcp-zero-knowledge-proof"
    )
    assert (
        check.expected_canonical_url(check.SITE / "use-cases" / "index.html")
        == "https://tinyzkp.com/use-cases"
    )


def test_site_link_parser_captures_metadata_and_routes():
    parser = check.SiteLinkParser(pathlib.Path("site/example.html"))
    parser.feed(
        """
        <html>
        <head>
          <title>Example</title>
          <meta name="description" content="Example page">
          <meta name="robots" content="noindex,follow">
          <meta property="og:image" content="https://tinyzkp.com/og-image.png">
          <meta name="twitter:image" content="/twitter-card.png">
          <link rel="canonical" href="https://tinyzkp.com/example">
        </head>
        <body>
          <h1>Example</h1>
          <a href="/docs#quickstart">Docs</a>
          <script src="/analytics.js"></script>
          <script type="application/ld+json">{"logo":"https://tinyzkp.com/og-image.png"}</script>
        </body>
        </html>
        """
    )

    assert parser.metadata.h1_count == 1
    assert parser.metadata.title_count == 1
    assert parser.metadata.description_count == 1
    assert parser.metadata.robots_contents == ["noindex,follow"]
    assert check.is_noindex(parser.metadata)
    assert parser.metadata.canonical_hrefs == ["https://tinyzkp.com/example"]
    assert parser.anchors == set()
    assert [link.raw for link in parser.links] == [
        "https://tinyzkp.com/og-image.png",
        "/twitter-card.png",
        "https://tinyzkp.com/example",
        "/docs#quickstart",
        "/analytics.js",
        "https://tinyzkp.com/og-image.png",
    ]


def test_site_link_parser_counts_duplicate_metadata():
    parser = check.SiteLinkParser(pathlib.Path("site/bad.html"))
    parser.feed(
        """
        <title>One</title><title>Two</title>
        <meta name="description" content="One">
        <meta name="description" content="Two">
        <link rel="canonical" href="https://tinyzkp.com/one">
        <link rel="canonical" href="https://tinyzkp.com/two">
        <h1>One</h1><h1>Two</h1>
        """
    )

    assert parser.metadata.h1_count == 2
    assert parser.metadata.title_count == 2
    assert parser.metadata.description_count == 2
    assert parser.metadata.canonical_hrefs == [
        "https://tinyzkp.com/one",
        "https://tinyzkp.com/two",
    ]


def test_sitemap_url_record_normalizes_root_and_extensionless_routes():
    assert check.sitemap_url_record("https://tinyzkp.com/") == check.SitemapURL(
        loc="https://tinyzkp.com/",
        path="/",
        canonical_url="https://tinyzkp.com",
    )
    assert check.sitemap_url_record("https://www.tinyzkp.com/docs") == check.SitemapURL(
        loc="https://www.tinyzkp.com/docs",
        path="/docs",
        canonical_url="https://tinyzkp.com/docs",
    )
    assert check.sitemap_url_record("https://tinyzkp.com/docs?ref=ad") is None
    assert check.sitemap_url_record("https://example.com/docs") is None


def test_json_ld_urls_extracts_only_local_urls():
    assert check.json_ld_urls(
        {
            "logo": "https://tinyzkp.com/og-image.png",
            "sameAs": ["https://example.com/external", "/docs"],
            "nested": {"url": "https://www.tinyzkp.com/security"},
        }
    ) == [
        "https://tinyzkp.com/og-image.png",
        "/docs",
        "https://www.tinyzkp.com/security",
    ]


def test_public_site_uses_no_listed_email_contact():
    assert check.validate_no_public_email() == []
    security_txt = (check.SITE / ".well-known" / "security.txt").read_text(encoding="utf-8")
    assert "Contact: https://" in security_txt
    assert "Expires:" in security_txt
    assert "mailto:" not in security_txt.lower()
