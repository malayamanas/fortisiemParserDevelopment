# Integration Test Suite Design
**Date:** 2026-03-02
**Approach:** pytest + pytest-playwright (Approach A)

---

## Overview

A semi-automated browser integration test suite layered on top of the existing 78 unit tests.
Most interactions are driven by Playwright; human-checkpoint steps pause execution so the tester
can paste real samples, review results, edit XML, or provide a live Claude CLI prompt.

---

## File Layout

```
tests/
  integration/
    conftest.py          # server + browser fixtures, human_step(), claude_terminal_step()
    test_analyze.py      # Analyze Samples workflow
    test_generate.py     # Generate Parser + edit XML workflow
    test_test_parser.py  # Test Parser modal (single + library)
    test_ai_suggest.py   # ✨ AI button + Claude CLI terminal step
    test_browse.py       # Parser library browse (EAT browser, save/load)
```

---

## Fixtures (conftest.py)

| Fixture | Description |
|---|---|
| `live_server` | Starts `python3 app.py` on port 5001 as subprocess; polls GET / up to 10 s; yields URL; kills on teardown |
| `page` | Headed Playwright Chromium page pre-navigated to `live_server` URL |
| `human_step(page, title, instructions)` | Prints ASCII instruction box to terminal; calls `page.pause()` (opens Playwright Inspector); skipped when `--no-pause` flag is set |
| `claude_terminal_step(prompt_prefix)` | Prints Claude terminal prompt box; reads user input via `input()`; runs `claude -p --output-format json`; asserts coherent JSON response; auto-skips on blank input or missing `claude` binary |

---

## Test Scenarios

### test_analyze.py — Analyze Samples workflow
1. **automated** — navigate to `/`, assert page title
2. **HUMAN pause** — "Paste your log samples into the Samples textarea, then press Resume"
3. **automated** — click Analyze Samples button, wait for results
4. **automated** — assert Token Matrix panel is visible
5. **HUMAN pause** — "Review the Token Matrix — does the column alignment look correct?"
6. **automated** — assert Field Mappings table has ≥1 row with EAT suggestions and confidence badges

### test_generate.py — Generate Parser + edit XML
1. **automated** — paste a KV-pair syslog sample, click Analyze
2. **automated** — click Generate button, wait for XML textarea
3. **automated** — assert XML textarea is visible and non-empty
4. **HUMAN pause** — "Review and optionally edit the generated XML, then press Resume"
5. **automated** — click Validate → assert green "Valid XML" badge appears

### test_test_parser.py — Test Parser modal
1. **automated** — paste Apache access log sample, click Analyze, click Generate
2. **HUMAN pause** — "Optionally edit the XML to match your parser, then press Resume"
3. **automated** — click Test button
4. **automated** — assert Test modal opens
5. **automated** — assert "Current parser extraction" results section appears
6. **automated** — assert "📝 Current Parser" row is visible in the library results table

### test_ai_suggest.py — AI Suggest + Claude terminal
1. **automated** — paste log with an ambiguous custom field name (e.g. `threatCategory=ransomware`)
2. **automated** — click Analyze, wait for Field Mappings; assert ✨ AI button visible on low-confidence row
3. **automated** — click ✨ AI button, wait for spinner to disappear
4. **HUMAN pause** — "Review the AI mapping suggestion shown in the EAT column"
5. **automated** — assert EAT dropdown value was updated to AI's suggestion
6. **HUMAN terminal** — Claude terminal step: user types a custom prompt; test runs it via `claude` CLI; asserts valid JSON response with reasoning

### test_browse.py — Parser library browse
1. **automated** — click Browse Parsers tab, assert parser list loads with ≥1 row
2. **automated** — click EAT Browser tab, type "srcIpAddr" in search, assert matching row appears
3. **automated** — filter by value type "IP", assert all visible rows have IP type

---

## Human Checkpoint System

```
╔══════════════════════════════════════════════════════╗
║  HUMAN STEP: <title>                                 ║
║                                                      ║
║  <instructions>                                      ║
║                                                      ║
║  Switch to the browser and press Resume in the       ║
║  Playwright Inspector toolbar when done.             ║
╚══════════════════════════════════════════════════════╝
```

- `page.pause()` opens the Playwright Inspector in the browser.
- `--no-pause` flag skips all `page.pause()` calls for headless/CI runs.

---

## Claude Terminal Step

```
╔══════════════════════════════════════════════════════╗
║  CLAUDE TERMINAL STEP                                ║
║  Enter an instruction for Claude about this field.   ║
║  Example: "What EAT best maps a field called         ║
║  'threatCategory' with values ['ransomware']?"       ║
╠══════════════════════════════════════════════════════╣
║  Press Enter with blank input to skip this step.     ║
╚══════════════════════════════════════════════════════╝
Your instruction:
```

- Reads prompt from stdin via `input()`.
- Runs `subprocess.run(['claude', '-p', '--output-format', 'json', prompt], timeout=60)`.
- Asserts response is parseable JSON with at least one sentence of reasoning.
- Auto-skips on blank input or when `shutil.which("claude")` is None.

---

## Error Handling

| Scenario | Behaviour |
|---|---|
| App doesn't start in 10 s | `RuntimeError("app did not start on port 5001")` |
| `claude` CLI not found | `pytest.skip("claude CLI not available")` on that step |
| Blank Claude terminal input | Step skipped silently, test continues |
| `--no-pause` flag set | All `page.pause()` calls skipped, fully headless |

---

## Running the Suite

```bash
# Full interactive run (headed browser, all human pauses active)
pytest tests/integration/ -v -s

# Headless / CI mode (no pauses)
pytest tests/integration/ -v -s --no-pause

# Single workflow
pytest tests/integration/test_ai_suggest.py -v -s
```

---

## Dependencies

```bash
pip install pytest-playwright
playwright install chromium
```
