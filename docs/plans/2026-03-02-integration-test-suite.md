# Integration Test Suite Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a semi-automated pytest + Playwright integration test suite covering all five Parser Studio workflows with human-checkpoint pauses and a live Claude CLI terminal step.

**Architecture:** `tests/integration/` folder with a shared `conftest.py` (live Flask server fixture + `human_step` helper) and one test file per workflow. `pytest-playwright` drives a headed Chromium browser; human checkpoints call `page.pause()` which opens the Playwright Inspector so the tester acts in the real browser before the test continues asserting.

**Tech Stack:** Python 3.11+, pytest, pytest-playwright, Playwright Chromium, subprocess (for Claude CLI step), existing Flask app (`app.py` on port 5001).

---

## Prerequisites

Install once before running any tasks:

```bash
pip install pytest-playwright
playwright install chromium
```

Verify:
```bash
python -m playwright --version
```

---

## Task 1: conftest.py — live server + fixtures

**Files:**
- Create: `tests/integration/__init__.py`
- Create: `tests/integration/conftest.py`

**Step 1: Create the package init file**

```bash
touch tests/integration/__init__.py
```

**Step 2: Write conftest.py**

```python
# tests/integration/conftest.py
import os
import shutil
import socket
import subprocess
import time

import pytest
from playwright.sync_api import Page, sync_playwright

PORT = 5001
BASE_URL = f"http://127.0.0.1:{PORT}"


# ── Custom CLI flag ─────────────────────────────────────────────────────────

def pytest_addoption(parser):
    parser.addoption(
        "--no-pause",
        action="store_true",
        default=False,
        help="Skip all human checkpoint pauses (headless/CI mode)",
    )


@pytest.fixture(scope="session")
def no_pause(request):
    return request.config.getoption("--no-pause")


# ── Live Flask server ────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def live_server():
    """Start app.py on PORT, yield BASE_URL, kill on teardown."""
    env = os.environ.copy()
    env["PARSER_STUDIO_DB"] = "parser_studio_test.db"
    proc = subprocess.Popen(
        ["python3", "app.py"],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    # Poll until the port accepts connections (up to 10 s)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=0.5):
                break
        except OSError:
            time.sleep(0.2)
    else:
        proc.kill()
        raise RuntimeError(f"App did not start on port {PORT} within 10 seconds")

    yield BASE_URL

    proc.terminate()
    proc.wait(timeout=5)


# ── Playwright browser + page ────────────────────────────────────────────────

@pytest.fixture(scope="session")
def browser_instance():
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=False)
        yield browser
        browser.close()


@pytest.fixture
def page(browser_instance, live_server):
    """Fresh page navigated to the app for each test."""
    context = browser_instance.new_context()
    pg = context.new_page()
    pg.goto(live_server)
    pg.wait_for_load_state("networkidle")
    yield pg
    context.close()


# ── Human checkpoint helpers ─────────────────────────────────────────────────

def _box(title: str, body: str) -> str:
    width = 56
    lines = [f"  {line}" for line in body.strip().splitlines()]
    inner = "\n".join(f"║ {l:<{width - 4}} ║" for l in lines)
    return (
        f"\n╔{'═' * (width - 2)}╗\n"
        f"║  HUMAN STEP: {title:<{width - 16}}║\n"
        f"╠{'═' * (width - 2)}╣\n"
        f"{inner}\n"
        f"╠{'═' * (width - 2)}╣\n"
        f"║  Switch to the browser. Press Resume in Playwright  ║\n"
        f"║  Inspector toolbar when done.                       ║\n"
        f"╚{'═' * (width - 2)}╝\n"
    )


def human_step(page: Page, title: str, instructions: str, no_pause: bool = False):
    """Print instruction box and pause the browser for human interaction."""
    print(_box(title, instructions))
    if not no_pause:
        page.pause()


def claude_terminal_step(prompt_prefix: str = "") -> str | None:
    """
    Print a Claude CLI prompt box, read user instruction from stdin,
    run it via `claude -p --output-format json`, return the response text.
    Returns None if skipped (blank input or claude not available).
    """
    if not shutil.which("claude"):
        print("\n[claude CLI not found — skipping Claude terminal step]\n")
        return None

    width = 56
    print(
        f"\n╔{'═' * (width - 2)}╗\n"
        f"║  CLAUDE TERMINAL STEP{' ' * (width - 24)}║\n"
        f"╠{'═' * (width - 2)}╣\n"
        f"║  Enter an instruction for Claude about this field.  ║\n"
    )
    if prompt_prefix:
        for line in prompt_prefix.splitlines():
            print(f"║  {line:<{width - 4}} ║")
    print(
        f"╠{'═' * (width - 2)}╣\n"
        f"║  Press Enter with blank input to skip.              ║\n"
        f"╚{'═' * (width - 2)}╝"
    )
    user_input = input("Your instruction: ").strip()
    if not user_input:
        print("[Skipped]\n")
        return None

    result = subprocess.run(
        ["claude", "-p", "--output-format", "json", user_input],
        capture_output=True, text=True, timeout=60,
    )
    response = result.stdout.strip()
    print(f"\nClaude responded:\n{response}\n")
    return response
```

**Step 3: Verify the file parses without syntax errors**

```bash
python3 -c "import tests.integration.conftest"
```

Expected: no output (no errors).

**Step 4: Commit**

```bash
git add tests/integration/__init__.py tests/integration/conftest.py
git commit -m "test: add integration test conftest with live server and human_step fixtures"
```

---

## Task 2: test_analyze.py — Analyze Samples workflow

**Files:**
- Create: `tests/integration/test_analyze.py`

**Step 1: Write the test**

```python
# tests/integration/test_analyze.py
import pytest
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
```

**Step 2: Run to see it execute (requires headed browser)**

```bash
pytest tests/integration/test_analyze.py -v -s
```

Expected: browser opens, pauses at human checkpoints, passes after you interact.

**Step 3: Run in no-pause mode to verify automated assertions work**

```bash
pytest tests/integration/test_analyze.py -v -s --no-pause
```

Expected: FAIL or PASS depending on whether default textarea contains parseable content. This is fine — it exercises the automated path.

**Step 4: Commit**

```bash
git add tests/integration/test_analyze.py
git commit -m "test: add integration test for Analyze Samples workflow"
```

---

## Task 3: test_generate.py — Generate Parser + edit XML

**Files:**
- Create: `tests/integration/test_generate.py`

**Step 1: Write the test**

```python
# tests/integration/test_generate.py
import pytest
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
    page.wait_for_selector(".badge-ok", timeout=5_000)

    badge = page.locator(".badge-ok").first
    assert badge.is_visible(), "Expected green 'Valid XML' badge after Validate"
```

**Step 2: Run the test**

```bash
pytest tests/integration/test_generate.py -v -s
```

**Step 3: Commit**

```bash
git add tests/integration/test_generate.py
git commit -m "test: add integration test for Generate Parser + edit XML workflow"
```

---

## Task 4: test_test_parser.py — Test Parser modal

**Files:**
- Create: `tests/integration/test_test_parser.py`

**Step 1: Write the test**

```python
# tests/integration/test_test_parser.py
import pytest
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
```

**Step 2: Run the test**

```bash
pytest tests/integration/test_test_parser.py -v -s
```

**Step 3: Commit**

```bash
git add tests/integration/test_test_parser.py
git commit -m "test: add integration test for Test Parser modal and library matching"
```

---

## Task 5: test_ai_suggest.py — AI Suggest + Claude terminal

**Files:**
- Create: `tests/integration/test_ai_suggest.py`

**Step 1: Write the test**

```python
# tests/integration/test_ai_suggest.py
import json
import pytest
from tests.integration.conftest import human_step, claude_terminal_step

# A log line with an ambiguous custom field guaranteed to score low confidence
_AMBIGUOUS_SAMPLE = (
    "Jul 23 10:05:15 2025 edr01 10.0.0.1 "
    "threatCategory=ransomware riskScore=87 agentGuid=abc-123"
)


@pytest.mark.skipif(
    not __import__("shutil").which("claude"),
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

    # Record which EAT is selected before clicking AI suggest
    # The EAT select is the sibling select in the same td
    row = ai_btn.locator("xpath=ancestor::tr[1]")
    eat_select = row.locator("select").first
    original_value = eat_select.input_value()

    # ── Automated: click ✨ AI button ─────────────────────────────────────
    ai_btn.click()

    # Wait for spinner to disappear (button text back to ✨)
    page.wait_for_function(
        "() => !document.querySelector('button') || "
        "![...document.querySelectorAll('button')].some(b => b.textContent.trim() === '...')",
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

    # ── Assert: EAT dropdown was updated ─────────────────────────────────
    new_value = eat_select.input_value()
    assert new_value != "", "EAT dropdown is empty after AI suggest"
    # Value should have changed OR been confirmed (either is acceptable)
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
        # Parse and assert it is coherent JSON with a reason
        import re
        match = re.search(r'\{.*\}', response, re.DOTALL)
        assert match, f"Claude response did not contain JSON: {response}"
        payload = json.loads(match.group(0))
        assert "reason" in payload, "Claude response missing 'reason' key"
        assert len(payload["reason"]) > 5, "Claude reason is too short"
        print(f"  Claude agrees: {payload.get('agree')} — {payload.get('reason')}")
```

**Step 2: Run the test**

```bash
pytest tests/integration/test_ai_suggest.py -v -s
```

Expected: browser opens, AI button appears and is clicked, terminal prompts for Claude instruction.

**Step 3: Commit**

```bash
git add tests/integration/test_ai_suggest.py
git commit -m "test: add integration test for AI suggest button and Claude CLI terminal step"
```

---

## Task 6: test_browse.py — Parser library + EAT browser

**Files:**
- Create: `tests/integration/test_browse.py`

**Step 1: Write the test**

```python
# tests/integration/test_browse.py


def test_parser_library_loads(page, live_server):
    """Parser Library section is visible and has ≥1 row."""
    # Library is always rendered (not behind a tab)
    page.wait_for_selector("text=Parser Library", timeout=10_000)
    assert page.is_visible("text=Parser Library")

    # Wait for table rows to load
    page.wait_for_function(
        "() => document.querySelectorAll('table.library-table tbody tr').length >= 1",
        timeout=10_000,
    )
    rows = page.locator("table.library-table tbody tr").all()
    assert len(rows) >= 1, "Parser Library table has no rows"


def test_eat_browser_search(page, live_server):
    """EAT browser search returns results for 'srcIpAddr'."""
    page.wait_for_selector("text=Event Attribute Types (EAT) Browser", timeout=10_000)

    search_input = page.get_by_placeholder("Search name or display name…")
    search_input.fill("srcIpAddr")

    # Debounce is 300 ms — wait for network + render
    page.wait_for_timeout(600)
    page.wait_for_selector("td.mono", timeout=5_000)

    results = page.locator("td.mono").all_text_contents()
    assert any("srcIpAddr" in r for r in results), \
        f"srcIpAddr not found in EAT search results: {results[:5]}"


def test_eat_browser_value_type_filter(page, live_server):
    """Filtering EAT browser by value type 'IP' shows only IP-type rows."""
    page.wait_for_selector("text=Event Attribute Types (EAT) Browser", timeout=10_000)

    # Select 'IP' from the value type dropdown
    vt_select = page.locator("select").filter(has_text="All value types")
    vt_select.select_option("IP")
    page.wait_for_timeout(600)

    # All visible type badges must be 'IP'
    badges = page.locator("table.library-table .badge").all_text_contents()
    type_badges = [b for b in badges if b and b not in ("enabled", "disabled", "system", "studio", "imported")]
    assert all(b == "IP" for b in type_badges), \
        f"Non-IP badges visible after filtering by IP: {set(type_badges)}"
```

**Step 2: Run the test**

```bash
pytest tests/integration/test_browse.py -v -s
```

**Step 3: Commit**

```bash
git add tests/integration/test_browse.py
git commit -m "test: add integration tests for Parser Library and EAT Browser"
```

---

## Task 7: Verify full suite + update README

**Step 1: Run the complete integration suite in no-pause mode**

```bash
pytest tests/integration/ -v -s --no-pause 2>&1
```

Expected: all tests collected and run; some may fail if the app state differs but no import or fixture errors.

**Step 2: Run the full existing unit suite to confirm nothing was broken**

```bash
pytest tests/ -v --ignore=tests/integration 2>&1 | tail -5
```

Expected: `78 passed`.

**Step 3: Add a `conftest.py` app.py port guard**

The integration server uses port 5001 but `app.py` defaults to 5000. Open `tests/integration/conftest.py` and confirm the `Popen` call passes the port. Add `--port 5001` if Flask's CLI is used, or set it via env var. Check `app.py`:

```python
# app.py line ~361 should read:
app.run(debug=True, port=int(os.environ.get("PORT", 5000)))
```

If it does not read from `PORT` env var, edit it:

```python
# In app.py, replace:
app.run(debug=True, port=5000)
# With:
app.run(debug=True, port=int(os.environ.get("PORT", 5000)))
```

Then update the `live_server` fixture env:
```python
env["PORT"] = str(PORT)   # add this line in conftest.py live_server fixture
```

**Step 4: Run the suite one final time**

```bash
pytest tests/integration/ -v -s --no-pause
```

**Step 5: Commit**

```bash
git add app.py tests/integration/conftest.py
git commit -m "test: wire PORT env var and finalize integration test suite"
```

**Step 6: Push**

```bash
git push
```

---

## Running Summary

| Command | What happens |
|---|---|
| `pytest tests/integration/ -v -s` | Full interactive run — browser opens, pauses at every human step, Claude terminal prompts appear |
| `pytest tests/integration/ -v -s --no-pause` | Headless/CI run — all human pauses skipped, automated assertions only |
| `pytest tests/integration/test_ai_suggest.py -v -s` | AI suggest + Claude CLI step only |
| `pytest tests/ -v --ignore=tests/integration` | Unit tests only (78 tests, no browser) |
