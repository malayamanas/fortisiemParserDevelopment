# Parser View / Edit / Test Design

**Date:** 2026-03-01
**Status:** Approved

---

## Goal

Allow users to open any parser in the library, read and edit its XML directly, run test samples against it, validate it, and save changes back to the database — all without leaving the single-page app.

## Constraints

- Editing an imported parser (source='imported') updates only the DB; does NOT write back to the disk file.
- No new page navigation — stays on the existing single-page layout.
- Reuses existing CSS classes and modal patterns.

## Architecture

### Backend

**New routes in `app.py`:**

```
GET  /api/parsers/<id>   → full parser record + saved samples
PUT  /api/parsers/<id>   → update parser metadata + xml_content + samples
```

**New DB function in `parser_studio/db.py`:**

```python
def update_parser(db_path, parser_id, data) -> None:
    # UPDATE parsers SET name=, scope=, vendor=, model=, version=, xml_content= WHERE id=
    # Then replace test_samples via save_samples()
```

No changes to any other backend module.

### Frontend (`parser_studio/templates/index.html`)

**Parser Library table:** Add "Edit" button per row alongside existing Download button.

**Edit Modal (new `x-show="showEditModal"` block):**

| Section | Content |
|---|---|
| Metadata | Name, Scope, Vendor, Model, Version — pre-filled, editable |
| XML editor | Large monospace `<textarea>` pre-filled with `xml_content` |
| Test samples | List of textarea rows pre-filled from saved samples; add/remove rows |
| Toolbar | Validate · Run Test · Save · ✕ close |
| Test results | Inline below toolbar — single-parser mode result table |

**New Alpine.js state:**

```js
showEditModal: false,
editParser: {},          // loaded record
editSamples: [],         // [{raw_log}]
editValidateResult: null,
editValidateError: '',
editTestResults: [],
```

**New Alpine.js methods:**

```js
async openEditModal(id)  // GET /api/parsers/<id>, populate state, open modal
async saveEdit()         // PUT /api/parsers/<id>, close modal, refresh library
async validateEdit()     // POST /api/validate with editParser.xml_content
async runEditTest()      // POST /api/test with editParser.xml_content + editSamples
```

**CSS:** No new classes — reuses `.modal`, `.modal-wide`, `.modal-header`,
`.modal-body`, `.modal-toolbar`, `.xml-preview`, `.result-table`, `.btn-*`.

## Data Flow

```
User clicks Edit
  → openEditModal(id)
    → GET /api/parsers/<id>
    → state: editParser, editSamples, showEditModal=true

User edits XML / samples

User clicks Validate
  → POST /api/validate { xml: editParser.xml_content }
  → shows badge in toolbar

User clicks Run Test
  → POST /api/test { xml: editParser.xml_content, samples: editSamples }
  → shows result table inline

User clicks Save
  → PUT /api/parsers/<id> { name, scope, vendor, model, version, xml, samples }
  → showEditModal=false
  → loadParserLibrary()
```

## Testing

- Unit: `test_db.py` — add `test_update_parser` covering metadata + xml_content update
- API: manual curl for `GET /api/parsers/<id>` and `PUT /api/parsers/<id>`
- UI: manual — open edit modal, change XML, validate, run test, save, verify library reflects change
