from pathlib import Path
import sys


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
import claim_containment_scan as claims  # noqa: E402


def write(root: Path, relative: str, text: str) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_rejects_unsupported_active_claims(tmp_path: Path) -> None:
    write(
        tmp_path,
        "site/index.html",
        "<p>The only production prover with O(sqrt T) memory and "
        "zero-knowledge privacy.</p>\n",
    )
    errors = claims.scan(tmp_path)
    assert any("square-root production behavior" in error for error in errors)
    assert any("zero-knowledge privacy" in error for error in errors)
    assert any("uniqueness" in error for error in errors)


def test_active_negation_is_allowed_but_not_a_fake_research_banner(
    tmp_path: Path,
) -> None:
    write(
        tmp_path,
        "site/security.html",
        "<p>TinyZKP does not claim zero-knowledge privacy.</p>\n",
    )
    write(
        tmp_path,
        "README.md",
        "> **Legacy research — not production evidence.**\n\n"
        "The shipping CLI guarantees O(sqrt T).\n",
    )
    errors = claims.scan(tmp_path)
    assert not any("site/security.html" in error for error in errors)
    assert any("README.md" in error for error in errors)


def test_clearly_labeled_legacy_document_is_quarantined(tmp_path: Path) -> None:
    write(
        tmp_path,
        "docs/whitepaper.md",
        "# Historical design\n\n"
        "> **Legacy research — not production evidence.** This is not a "
        "supported release contract.\n\n"
        "The old design targeted O(√T) and zero-knowledge.\n",
    )
    assert claims.scan(tmp_path) == []


def test_unlabeled_research_document_is_rejected(tmp_path: Path) -> None:
    write(
        tmp_path,
        "docs/design.md",
        "# Design\n\nThe shipping implementation is production-ready.\n",
    )
    errors = claims.scan(tmp_path)
    assert len(errors) == 2
