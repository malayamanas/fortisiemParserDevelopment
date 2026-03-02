# tests/integration/test_test_parser.py
from tests.integration.conftest import human_step

_APACHE_SAMPLE = (
    '192.168.0.1 - frank [10/Oct/2000:13:55:36 -0700] '
    '"GET /apache_pb.gif HTTP/1.0" 200 2326'
)


def test_test_parser_modal(page, no_pause, live_server):
    """
    Automated: paste Apache sample + Analyze + Generate.
    Human: optionally edits XML.
    Automated: opens Test modal, asserts single-parser results
    and '📝 Current Parser' row in library section.
    """
    # ── Automated: paste Apache log + Analyze ────────────────────────────
    page.locator("textarea").first.fill(_APACHE_SAMPLE)
    page.get_by_role("button", name="Analyze Samples →").click()
    page.wait_for_selector("text=Field Mappings", timeout=15_000)

    # ── Automated: Generate ───────────────────────────────────────────────
    page.get_by_role("button", name="Generate Parser →").click()
    page.wait_for_selector("text=Generated Parser XML", timeout=10_000)

    # ── HUMAN: optionally edit the XML ───────────────────────────────────
    human_step(
        page, "Edit XML (optional)",
        "The Generated Parser XML textarea is editable.\n"
        "Optionally adjust the XML, then press Resume.",
        no_pause=no_pause,
    )

    # ── Automated: click Test button ─────────────────────────────────────
    page.get_by_role("button", name="Test").click()
    page.wait_for_selector("text=Parser Test Results", timeout=10_000)

    # ── Assert: Test modal is open ────────────────────────────────────────
    assert page.is_visible("text=Parser Test Results"), "Test modal did not open"

    # ── Assert: single-parser results section visible ─────────────────────
    page.wait_for_selector("text=Current parser extraction", timeout=20_000)
    assert page.is_visible("text=Current parser extraction"), \
        "Single-parser extraction section not found"

    # ── Assert: library section visible with '📝 Current Parser' entry ───
    page.wait_for_selector("text=Also matched by library parsers", timeout=20_000)
    assert page.is_visible("text=Also matched by library parsers"), \
        "Library matches section not found"

    assert page.is_visible("text=📝 Current Parser"), \
        "'📝 Current Parser' row not found in library results"
