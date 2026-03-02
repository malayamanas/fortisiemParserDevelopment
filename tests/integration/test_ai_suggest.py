# tests/integration/test_ai_suggest.py
import json
import re
import shutil

import pytest
from tests.integration.conftest import human_step, claude_terminal_step

# A log line with ambiguous custom fields that will score low confidence
_AMBIGUOUS_SAMPLE = (
    "Jul 23 10:05:15 2025 edr01 10.0.0.1 "
    "threatCategory=ransomware riskScore=87 agentGuid=abc-123"
)


@pytest.mark.skipif(
    not shutil.which("claude"),
    reason="claude CLI not available",
)
def test_ai_suggest_eat(page, no_pause, live_server):
    """
    Automated: paste ambiguous log + Analyze → waits for ✨ AI button.
    Automated: clicks AI button + waits for suggestion.
    Human: reviews suggestion in browser.
    Automated: asserts EAT dropdown was updated.
    Human terminal: types a Claude prompt and test asserts valid JSON response.
    """
    # ── Automated: paste sample + Analyze ────────────────────────────────
    page.locator("textarea").first.fill(_AMBIGUOUS_SAMPLE)
    page.get_by_role("button", name="Analyze Samples →").click()
    page.wait_for_selector("text=Field Mappings", timeout=15_000)

    # ── Wait for ✨ AI button to appear on any low-confidence row ─────────
    ai_btn = page.locator("button", has_text="✨").first
    ai_btn.wait_for(state="visible", timeout=10_000)
    assert ai_btn.is_visible(), "✨ AI button not visible — no low-confidence field?"

    # Record the EAT select in the same row before clicking AI suggest
    row = ai_btn.locator("xpath=ancestor::tr[1]")
    eat_select = row.locator("select").first
    original_value = eat_select.input_value()

    # ── Automated: click ✨ AI button ─────────────────────────────────────
    ai_btn.click()

    # Wait for spinner to disappear (no button with text '...' remains)
    page.wait_for_function(
        "() => ![...document.querySelectorAll('button')]"
        ".some(b => b.textContent.trim() === '...')",
        timeout=30_000,
    )

    # ── HUMAN: review AI suggestion ───────────────────────────────────────
    human_step(
        page, "Review AI Suggestion",
        "The EAT dropdown for the low-confidence field should\n"
        "now show the AI's suggested mapping.\n"
        "Review whether the suggestion makes sense.",
        no_pause=no_pause,
    )

    # ── Assert: EAT dropdown is non-empty after AI suggest ────────────────
    new_value = eat_select.input_value()
    assert new_value != "", "EAT dropdown is empty after AI suggest"
    print(f"\n  AI suggest: '{original_value}' → '{new_value}'")

    # ── HUMAN terminal: Claude CLI prompt step ────────────────────────────
    response = claude_terminal_step(
        prompt_prefix=(
            f"The AI suggested EAT '{new_value}' for a field in log:\n"
            f"{_AMBIGUOUS_SAMPLE}\n\n"
            "Do you agree? Reply with JSON: "
            '{"agree": true/false, "reason": "one sentence"}'
        )
    )

    if response is not None:
        match = re.search(r'\{.*\}', response, re.DOTALL)
        assert match, f"Claude response did not contain JSON: {response}"
        payload = json.loads(match.group(0))
        assert "reason" in payload, "Claude response missing 'reason' key"
        assert len(payload["reason"]) > 5, "Claude reason is too short"
        print(f"  Claude agrees: {payload.get('agree')} — {payload.get('reason')}")
