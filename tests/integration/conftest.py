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
    db_path = "parser_studio_test.db"
    if os.path.exists(db_path):
        os.unlink(db_path)
    env["PARSER_STUDIO_DB"] = db_path
    env["PORT"] = str(PORT)
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
    if os.path.exists(db_path):
        os.unlink(db_path)


# ── Playwright browser + page ────────────────────────────────────────────────

@pytest.fixture(scope="session")
def browser_instance():
    playwright = sync_playwright().start()
    browser = playwright.chromium.launch(headless=False)
    yield browser
    browser.close()
    playwright.stop()


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
    title_display = title[:40]
    lines = [f"  {line}"[:(width - 4)] for line in body.strip().splitlines()]
    inner = "\n".join(f"║ {l:<{width - 4}} ║" for l in lines)
    return (
        f"\n╔{'═' * (width - 2)}╗\n"
        f"║  HUMAN STEP: {title_display:<40}║\n"
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
            print(f"║  {line[:(width - 5)]:<{width - 5}} ║")
    print(
        f"╠{'═' * (width - 2)}╣\n"
        f"║  Press Enter with blank input to skip.              ║\n"
        f"╚{'═' * (width - 2)}╝"
    )
    try:
        user_input = input("Your instruction: ").strip()
    except EOFError:
        print("\n[Non-interactive terminal — skipping Claude terminal step]\n")
        return None
    if not user_input:
        print("[Skipped]\n")
        return None

    try:
        result = subprocess.run(
            ["claude", "-p", "--output-format", "json", user_input],
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        print("\n[Claude CLI timed out — skipping]\n")
        return None
    if result.returncode != 0:
        print(f"\n[Claude CLI error (rc={result.returncode}) — skipping]\n")
        return None
    response = result.stdout.strip()
    print(f"\nClaude responded:\n{response}\n")
    return response
