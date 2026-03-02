# tests/integration/test_analyze.py
from tests.integration.conftest import human_step


def test_analyze_samples(page, no_pause, live_server):
    """
    Human pastes real log samples → clicks Analyze → automated assertions
    verify Token Matrix + Field Mappings appear with EAT suggestions.
    """
    # ── HUMAN: paste log samples ──────────────────────────────────────────
    human_step(
        page, "Paste Log Samples",
        "In the 'Event Log Samples' section, clear the default\n"
        "text and paste one or more real raw log lines.\n"
        "Each textarea is one sample.",
        no_pause=no_pause,
    )

    # ── Automated: click Analyze ──────────────────────────────────────────
    page.get_by_role("button", name="Analyze Samples →").click()
    page.wait_for_selector("section.panel >> text=Token Matrix", timeout=15_000)

    # ── Assert Token Matrix visible ───────────────────────────────────────
    assert page.is_visible("text=Token Matrix"), "Token Matrix panel did not appear"

    # ── HUMAN: review Token Matrix ────────────────────────────────────────
    human_step(
        page, "Review Token Matrix",
        "Check that the column alignment looks correct for\n"
        "your log format. Each column should represent a\n"
        "consistent token position across samples.",
        no_pause=no_pause,
    )

    # ── Assert Field Mappings visible with ≥1 EAT suggestion ─────────────
    assert page.is_visible("text=Field Mappings"), "Field Mappings panel did not appear"
    rows = page.locator("table.mapping-table tbody tr").all()
    assert len(rows) >= 1, "Expected at least one field mapping row"

    # Confidence badges must be present (high / medium / low)
    badges = page.locator(".badge").all_text_contents()
    assert any(b in ("high", "medium", "low") for b in badges), \
        "Expected at least one confidence badge in Field Mappings"
