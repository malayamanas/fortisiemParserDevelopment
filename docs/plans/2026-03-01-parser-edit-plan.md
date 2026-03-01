# Parser View / Edit / Test — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add an Edit modal to the Parser Library that lets users view, edit, and test any existing parser's XML and save changes to the database.

**Architecture:** Three layers — a new `update_parser` DB helper, two new Flask API routes (`GET` and `PUT /api/parsers/<id>`), and an Edit modal in the Alpine.js UI that pre-fills from the loaded parser record.

**Tech Stack:** Python/Flask, SQLite (sqlite3), Alpine.js, existing CSS classes.

---

## Task 1: `update_parser` DB function

**Files:**
- Modify: `parser_studio/db.py`
- Test: `tests/test_db.py`

**Step 1: Write the failing test**

Add to the bottom of `tests/test_db.py`:

```python
def test_update_parser(tmp_db):
    from parser_studio.db import update_parser
    init_db(tmp_db)
    pid = save_parser(tmp_db, {
        "name": "Original", "scope": "enabled", "parser_type": "User",
        "vendor": "A", "model": "B", "version": "ANY",
        "xml_content": "<old/>", "source": "studio", "file_path": None,
    })
    update_parser(tmp_db, pid, {
        "name": "Updated", "scope": "disabled",
        "vendor": "X", "model": "Y", "version": "2.0",
        "xml_content": "<new/>",
    })
    p = get_parser_by_id(tmp_db, pid)
    assert p["name"] == "Updated"
    assert p["scope"] == "disabled"
    assert p["vendor"] == "X"
    assert p["xml_content"] == "<new/>"
```

**Step 2: Run test to verify it fails**

```bash
pytest tests/test_db.py::test_update_parser -v
```

Expected: FAIL with `ImportError: cannot import name 'update_parser'`

**Step 3: Add `update_parser` to `parser_studio/db.py`**

Add after the `get_parser_by_id` function (after line 100):

```python
def update_parser(db_path: str, parser_id: int, data: dict) -> None:
    with _conn(db_path) as conn:
        conn.execute(
            """UPDATE parsers
               SET name=:name, scope=:scope, vendor=:vendor, model=:model,
                   version=:version, xml_content=:xml_content
               WHERE id=:id""",
            {**data, "id": parser_id}
        )
```

**Step 4: Run test to verify it passes**

```bash
pytest tests/test_db.py::test_update_parser -v
```

Expected: PASS

**Step 5: Run full suite to check nothing broke**

```bash
pytest tests/ -v
```

Expected: 50 passed

**Step 6: Commit**

```bash
git add parser_studio/db.py tests/test_db.py
git commit -m "feat: add update_parser DB helper"
```

---

## Task 2: New API routes — GET and PUT `/api/parsers/<id>`

**Files:**
- Modify: `app.py`

**Step 1: Add imports**

`app.py` already imports `get_parser_by_id` and `get_samples`. Add `update_parser` to the import line (line 6):

```python
from parser_studio.db import (init_db, get_device_types, add_device_type,
                               save_parser, get_parsers, get_parser_by_id,
                               update_parser, save_samples, get_samples)
```

**Step 2: Add GET route after the existing `api_list_parsers` route (after line 151)**

```python
@app.route("/api/parsers/<int:pid>", methods=["GET"])
def api_get_parser(pid: int):
    p = get_parser_by_id(DB_PATH, pid)
    if not p:
        return jsonify({"error": "Not found"}), 404
    samples = get_samples(DB_PATH, pid)
    return jsonify({"parser": p, "samples": samples})
```

**Step 3: Add PUT route directly after the GET route**

```python
@app.route("/api/parsers/<int:pid>", methods=["PUT"])
def api_update_parser(pid: int):
    p = get_parser_by_id(DB_PATH, pid)
    if not p:
        return jsonify({"error": "Not found"}), 404
    data = request.get_json(force=True)
    update_parser(DB_PATH, pid, {
        "name":        data.get("name", p["name"]),
        "scope":       data.get("scope", p["scope"]),
        "vendor":      data.get("vendor", p["vendor"]),
        "model":       data.get("model", p["model"]),
        "version":     data.get("version", p["version"]),
        "xml_content": data.get("xml", p["xml_content"]),
    })
    if "samples" in data:
        save_samples(DB_PATH, pid,
                     [{"raw_log": s, "label": f"Sample {i+1}"}
                      for i, s in enumerate(data["samples"])])
    return jsonify({"ok": True})
```

**Step 4: Smoke-test the new routes**

Start the server in one terminal:

```bash
flask --app app run --port 5001
```

In another terminal, run these checks (pick any real parser id from the DB — id 1 should exist after startup syncs parsers/):

```bash
# GET — should return parser record + samples array
curl -s http://localhost:5001/api/parsers/1 | python3 -m json.tool | head -20

# PUT — update name
curl -s -X PUT http://localhost:5001/api/parsers/1 \
  -H "Content-Type: application/json" \
  -d '{"name": "TestRename"}' | python3 -m json.tool

# Verify rename took effect
curl -s http://localhost:5001/api/parsers/1 | python3 -m json.tool | grep name
```

Expected GET: `{"parser": {"id": 1, "name": "...", "xml_content": "...", ...}, "samples": [...]}`
Expected PUT: `{"ok": true}`

Kill the server (`Ctrl-C`).

**Step 5: Run full test suite**

```bash
pytest tests/ -v
```

Expected: 50 passed

**Step 6: Commit**

```bash
git add app.py
git commit -m "feat: add GET and PUT /api/parsers/<id> routes"
```

---

## Task 3: Edit Modal UI

**Files:**
- Modify: `parser_studio/templates/index.html`

This task has no automated tests — verification is manual in the browser.

### Step 1: Add Alpine.js state variables

In `index.html`, find the `studioApp()` function. Inside the `return { ... }` object, find the line:

```js
    // Parser library
    parserLibrary: [],
```

Add these new state variables immediately after it:

```js
    // Edit modal
    showEditModal: false,
    editParser: { id: null, name: '', scope: 'enabled', vendor: '', model: '', version: 'ANY', xml_content: '' },
    editSamples: [],
    editValidateResult: null,
    editValidateError: '',
    editTestResults: [],
    editTesting: false,
```

### Step 2: Add Alpine.js methods

In `studioApp()`, find the last method `loadParserLibrary()`. Add these new methods after it (before the closing `};`):

```js
    async openEditModal(id) {
      const res = await fetch(`/api/parsers/${id}`);
      const data = await res.json();
      this.editParser = data.parser;
      this.editSamples = data.samples.length
        ? data.samples.map(s => s.raw_log)
        : [''];
      this.editValidateResult = null;
      this.editValidateError = '';
      this.editTestResults = [];
      this.editTesting = false;
      this.showEditModal = true;
    },

    async saveEdit() {
      await fetch(`/api/parsers/${this.editParser.id}`, {
        method: 'PUT',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
          name:    this.editParser.name,
          scope:   this.editParser.scope,
          vendor:  this.editParser.vendor,
          model:   this.editParser.model,
          version: this.editParser.version,
          xml:     this.editParser.xml_content,
          samples: this.editSamples.filter(s => s.trim()),
        }),
      });
      this.showEditModal = false;
      await this.loadParserLibrary();
    },

    async validateEdit() {
      const res = await fetch('/api/validate', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ xml: this.editParser.xml_content }),
      });
      const data = await res.json();
      this.editValidateResult = data.valid;
      this.editValidateError = data.error || '';
    },

    async runEditTest() {
      this.editTesting = true;
      this.editTestResults = [];
      try {
        const samples = this.editSamples.filter(s => s.trim());
        if (!samples.length) return;
        const res = await fetch('/api/test', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ xml: this.editParser.xml_content, samples }),
        });
        const data = await res.json();
        this.editTestResults = data.results || [];
      } finally { this.editTesting = false; }
    },
```

### Step 3: Add Edit button to Parser Library table

Find the Parser Library table's actions cell:

```html
            <td>
              <a :href="'/api/parsers/' + p.id + '/download'" class="btn btn-sm">Download</a>
            </td>
```

Replace it with:

```html
            <td style="display:flex;gap:.4rem">
              <button @click="openEditModal(p.id)" class="btn btn-sm btn-secondary">Edit</button>
              <a :href="'/api/parsers/' + p.id + '/download'" class="btn btn-sm">Download</a>
            </td>
```

### Step 4: Add Edit Modal HTML

Find the closing `</div>` of the TEST MODAL block (just before the `<!-- PARSER LIBRARY -->` comment). Insert the entire Edit Modal block between them:

```html
  <!-- EDIT MODAL -->
  <div class="modal-overlay" x-show="showEditModal" @click.self="showEditModal = false">
    <div class="modal modal-wide">
      <div class="modal-header">
        <h3>Edit Parser: <span x-text="editParser.name"></span></h3>
        <button @click="showEditModal = false" class="btn btn-sm">&#10005;</button>
      </div>
      <div class="modal-body">

        <!-- Metadata -->
        <div class="form-grid" style="margin-bottom:1rem">
          <label>Name
            <input type="text" x-model="editParser.name"/>
          </label>
          <label>Scope
            <select x-model="editParser.scope">
              <option value="enabled">Enabled</option>
              <option value="disabled">Disabled</option>
            </select>
          </label>
          <label>Vendor
            <input type="text" x-model="editParser.vendor"/>
          </label>
          <label>Model
            <input type="text" x-model="editParser.model"/>
          </label>
          <label>Version
            <input type="text" x-model="editParser.version"/>
          </label>
        </div>

        <!-- XML editor -->
        <label style="display:block;font-weight:600;font-size:.875rem;margin-bottom:.4rem">Parser XML</label>
        <textarea x-model="editParser.xml_content" rows="16"
                  style="font-family:monospace;font-size:.8rem;width:100%;
                         padding:.5rem;border:1px solid #d1d5db;border-radius:6px;
                         margin-bottom:1rem;resize:vertical"></textarea>

        <!-- Toolbar -->
        <div class="modal-toolbar">
          <button @click="validateEdit()" class="btn btn-secondary">Validate</button>
          <button @click="runEditTest()" class="btn btn-secondary" :disabled="editTesting">
            <span x-text="editTesting ? 'Testing...' : 'Run Test'"></span>
          </button>
          <button @click="saveEdit()" class="btn btn-primary">Save</button>
          <span x-show="editValidateResult !== null"
                :class="editValidateResult ? 'badge badge-ok' : 'badge badge-err'"
                x-text="editValidateResult ? '\u2713 Valid XML' : '\u2717 ' + editValidateError"></span>
        </div>

        <!-- Test results -->
        <template x-if="editTestResults.length > 0">
          <div style="margin-top:1rem">
            <template x-for="(result, i) in editTestResults" :key="i">
              <div class="test-result">
                <h4>
                  <span x-text="'Sample ' + (i+1)"></span>
                  <span :class="result.status === 'pass' ? 'badge badge-ok' : 'badge badge-err'"
                        x-text="result.status === 'pass' ? 'PASS' : 'FAIL'"></span>
                </h4>
                <table class="result-table">
                  <thead><tr><th>EAT</th><th>Value</th></tr></thead>
                  <tbody>
                    <template x-for="[k, v] in Object.entries(result.fields)" :key="k">
                      <tr><td x-text="k"></td><td class="mono" x-text="v"></td></tr>
                    </template>
                    <tr x-show="Object.keys(result.fields).length === 0">
                      <td colspan="2" class="hint">No fields extracted.</td>
                    </tr>
                  </tbody>
                </table>
              </div>
            </template>
          </div>
        </template>

        <!-- Test samples -->
        <div style="margin-top:1rem">
          <div style="font-weight:600;font-size:.875rem;margin-bottom:.5rem">
            Test Samples
            <button @click="editSamples.push('')" class="btn btn-sm" style="margin-left:.5rem">+ Add</button>
          </div>
          <template x-for="(s, i) in editSamples" :key="i">
            <div class="sample-block">
              <div class="sample-header">
                <span x-text="'Sample ' + (i+1)"></span>
                <button x-show="editSamples.length > 1" @click="editSamples.splice(i,1)"
                        class="btn btn-danger btn-sm">&#10005;</button>
              </div>
              <textarea x-model="editSamples[i]" rows="2"></textarea>
            </div>
          </template>
        </div>

      </div>
    </div>
  </div>
```

### Step 5: Verify in browser

```bash
flask --app app run --port 5001
```

Open `http://localhost:5001`. In the Parser Library table:
- Each row should now have an **Edit** button alongside Download
- Click **Edit** on any parser → modal opens with name, scope, vendor, model, version fields pre-filled and XML in a large textarea
- Edit the XML (make a trivial change like adding a space) → click **Validate** → badge shows `✓ Valid XML`
- Paste a sample log into the Test Samples textarea → click **Run Test** → results table appears below toolbar
- Click **Save** → modal closes, library table refreshes

### Step 6: Commit

```bash
git add parser_studio/templates/index.html
git commit -m "feat: add Edit modal to Parser Library (view, edit XML, validate, test, save)"
```

---

## Summary

| Task | Files changed | Tests |
|---|---|---|
| 1 | `parser_studio/db.py`, `tests/test_db.py` | 1 new (total: 50) |
| 2 | `app.py` | manual curl |
| 3 | `parser_studio/templates/index.html` | manual browser |
