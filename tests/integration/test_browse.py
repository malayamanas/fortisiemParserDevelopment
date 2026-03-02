# tests/integration/test_browse.py


def test_parser_library_loads(page, live_server):
    """Parser Library section is visible and has ≥1 row."""
    page.wait_for_selector("text=Parser Library", timeout=10_000)
    assert page.is_visible("text=Parser Library")

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

    # Scope to the EAT browser section to avoid picking up Parser Library badges
    eat_section = page.locator("section.panel").filter(has_text="Event Attribute Types")

    # Select 'IP' from the value type dropdown (scoped to EAT section)
    vt_select = eat_section.locator("select")
    vt_select.select_option("IP")
    page.wait_for_timeout(600)

    # All type badges inside the EAT section must be 'IP'
    badges = eat_section.locator(".badge").all_text_contents()
    # Filter out non-type badges: count summary (e.g. "3431 attributes"), deprecated markers, empty
    type_badges = [b for b in badges if b and b not in ("deprecated", "") and "attributes" not in b]
    assert len(type_badges) > 0, "No type badges visible after IP filter"
    assert all(b == "IP" for b in type_badges), \
        f"Non-IP badges visible after filtering by IP: {set(type_badges)}"
