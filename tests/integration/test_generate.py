# tests/integration/test_generate.py
from tests.integration.conftest import human_step

# A safe KV-pair sample that always produces a parseable result
_KV_SAMPLE = (
    "Jul 23 10:05:15 2025 fw01 192.168.1.1 "
    "srcip=10.0.0.5 dstip=8.8.8.8 action=deny proto=tcp sport=54321 dport=443"
)


def test_generate_parser(page, no_pause, live_server):
    """
    Automated: paste KV sample + Analyze + Generate.
    Human: reviews and optionally edits XML.
    Automated: Validate asserts green badge.
    """
    # ── Automated: fill first sample textarea ────────────────────────────
    textarea = page.locator("textarea").first
    textarea.fill(_KV_SAMPLE)

    # ── Automated: Analyze ────────────────────────────────────────────────
    page.get_by_role("button", name="Analyze Samples →").click()
    page.wait_for_selector("text=Field Mappings", timeout=15_000)

    # ── Automated: Generate ───────────────────────────────────────────────
    page.get_by_role("button", name="Generate Parser →").click()
    page.wait_for_selector("text=Generated Parser XML", timeout=10_000)

    xml_area = page.locator("textarea.xml-preview")
    assert xml_area.is_visible(), "Generated XML textarea not visible"
    xml_content = xml_area.input_value()
    assert len(xml_content) > 50, "Generated XML appears empty"

    # ── HUMAN: review / edit XML ──────────────────────────────────────────
    human_step(
        page, "Review Generated XML",
        "The XML textarea is editable. Review the generated\n"
        "parser XML and make any adjustments you need.\n"
        "When done, press Resume.",
        no_pause=no_pause,
    )

    # ── Automated: Validate ───────────────────────────────────────────────
    page.get_by_role("button", name="Validate").click()
    page.wait_for_selector("text=Valid XML", timeout=5_000)
    assert page.is_visible("text=Valid XML"), "Expected 'Valid XML' badge after Validate"
