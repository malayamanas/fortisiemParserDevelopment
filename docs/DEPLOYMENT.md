# FortiSIEM Parser Studio — Deployment Guide

## Overview

**FortiSIEM Parser Studio** is a web-based IDE for creating, testing, and managing custom FortiSIEM event log parsers. It is a self-contained Python Flask application with a SQLite database — no external services are required.

---

## Requirements

| Requirement | Version |
|---|---|
| Python | 3.11 or later |
| Flask | 3.0 or later |
| pytest (optional, for tests) | 8.0 or later |

No database server, message broker, or external API is required. The only optional external dependency is the `claude` CLI binary (used for AI-assisted EAT field suggestions — the application degrades gracefully if it is absent).

---

## Quick Start (Local Development)

```bash
# 1. Clone the repository
git clone <repo-url>
cd FortiSIEM_Parser_Creation_Script

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate          # macOS / Linux
# venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run the development server
python3 app.py
```

The application will be available at **http://localhost:5000**.

The SQLite database (`parser_studio.db`) is created automatically on the first request. Device types and FortiSIEM Event Attribute Types (EATs) are loaded from the `docs/SIEM_Event_Attributes/` directory on startup. Any parser XML files found in the project root or the `parsers/` subdirectory are imported into the database automatically.

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PARSER_STUDIO_DB` | `parser_studio.db` | Path to the SQLite database file. Use an absolute path in production so the file location is predictable. |
| `PORT` | `5000` | TCP port the HTTP server listens on. |

Example:

```bash
export PARSER_STUDIO_DB=/var/lib/parser-studio/parsers.db
export PORT=8080
python3 app.py
```

---

## Production Deployment

The built-in Flask development server is not suitable for production. Use a production WSGI server behind a reverse proxy.

### Option A — Gunicorn

```bash
pip install gunicorn

gunicorn \
  --workers 2 \
  --bind 0.0.0.0:5000 \
  --timeout 120 \
  app:app
```

Two workers are sufficient; the application is I/O-bound (SQLite reads/writes and subprocess calls for AI suggestions).

### Option B — uWSGI

```bash
pip install uwsgi

uwsgi \
  --http :5000 \
  --wsgi-file app.py \
  --callable app \
  --processes 2 \
  --threads 2
```

### Reverse Proxy (nginx)

Place nginx in front of the WSGI server to handle TLS, static file serving, and connection management.

```nginx
server {
    listen 443 ssl;
    server_name parserstudio.example.com;

    ssl_certificate     /etc/ssl/certs/parserstudio.crt;
    ssl_certificate_key /etc/ssl/private/parserstudio.key;

    # Serve static assets directly — avoids Flask overhead
    location /static/ {
        alias /opt/parser-studio/parser_studio/static/;
        expires 7d;
    }

    location / {
        proxy_pass         http://127.0.0.1:5000;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Real-IP         $remote_addr;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
    }
}
```

---

## systemd Service (Linux)

Create `/etc/systemd/system/parser-studio.service`:

```ini
[Unit]
Description=FortiSIEM Parser Studio
After=network.target

[Service]
Type=simple
User=parser-studio
WorkingDirectory=/opt/parser-studio
Environment=PARSER_STUDIO_DB=/var/lib/parser-studio/parsers.db
Environment=PORT=5000
ExecStart=/opt/parser-studio/venv/bin/gunicorn --workers 2 --bind 127.0.0.1:5000 --timeout 120 app:app
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable parser-studio
sudo systemctl start parser-studio
sudo systemctl status parser-studio
```

---

## File Layout After Installation

```
/opt/parser-studio/              # Application root
├── app.py                       # Flask entry point
├── requirements.txt
├── parser_studio/
│   ├── db.py
│   ├── detector.py
│   ├── extractor.py
│   ├── mapper.py
│   ├── generator.py
│   ├── simulator.py
│   ├── importer.py
│   ├── templates/
│   │   └── index.html
│   └── static/
│       └── style.css
├── docs/
│   └── SIEM_Event_Attributes/
│       ├── FortiSIEM_Event_Atrributes.json   # EAT definitions
│       └── device_types.txt                  # Device type catalog
├── parsers/                     # Optional: parser XML fragments to auto-import
└── venv/                        # Virtual environment

/var/lib/parser-studio/
└── parsers.db                   # SQLite database (persistent data)
```

---

## Database

The application uses **SQLite** — no database server is required.

The schema is created automatically on first startup. Four tables are managed:

| Table | Contents |
|---|---|
| `device_types` | Vendor / Model / Version catalog |
| `parsers` | Parser XML, metadata, scope, and source |
| `test_samples` | Raw log samples linked to each parser |
| `event_attributes` | FortiSIEM EAT definitions (synced from JSON file on startup) |

**Backup:** Copy `parsers.db` to a safe location. The database contains all parsers and samples created through the UI.

```bash
# Simple backup
cp /var/lib/parser-studio/parsers.db /backup/parsers-$(date +%Y%m%d).db
```

**Reset:** Delete `parsers.db` and restart the application. The database will be recreated with seed data from `docs/SIEM_Event_Attributes/`.

---

## Seeded Reference Data

On first startup the application loads two reference files:

| File | Purpose |
|---|---|
| `docs/SIEM_Event_Attributes/FortiSIEM_Event_Atrributes.json` | 3,400+ FortiSIEM Event Attribute Types (EATs) — field name, display name, value type, description |
| `docs/SIEM_Event_Attributes/device_types.txt` | Device type list used to populate the parser metadata dropdown |

These files are bundled in the repository. If the JSON file is absent, the EAT browser and AI-suggest features will have no data, but the rest of the application will function normally.

---

## Parser Auto-Import

On every startup the application scans two directories for `.xml` files and imports any parsers not already in the database:

- `.` — project root (complete `<eventParser>` documents)
- `parsers/` — parser fragment files

To trigger a re-import without restarting the server, POST to `/api/parsers/sync`:

```bash
curl -X POST http://localhost:5000/api/parsers/sync
```

---

## Optional: AI-Assisted EAT Suggestions

The application can use the **Claude CLI** (`claude`) to suggest the best EAT mapping for a log field. This is entirely optional — the UI hides the AI button when the binary is not found.

To enable it, install the Claude CLI and ensure it is on `PATH` for the process running the application:

```bash
which claude          # should return a path, e.g. /usr/local/bin/claude
```

The feature calls `claude -p --output-format json <prompt>` as a subprocess with a 30-second timeout. No network configuration is needed beyond what the Claude CLI itself requires.

---

## Running Tests

```bash
# Unit tests (fast, no browser required)
python3 -m pytest tests/test_generator.py tests/test_extractor.py \
                  tests/test_mapper.py tests/test_detector.py \
                  tests/test_db.py tests/test_simulator.py \
                  tests/test_importer.py -v

# All tests including integration (requires Playwright browser)
python3 -m pytest -v

# Install Playwright browser if needed for integration tests
python3 -m playwright install chromium
```

---

## Security Considerations

- The application is designed for **internal / trusted-network use**. It does not implement authentication or authorisation.
- If exposed to an untrusted network, place it behind a reverse proxy that enforces access control (e.g., HTTP Basic Auth, IP allowlist, or VPN requirement).
- The `debug=True` flag in `app.py` enables the Werkzeug interactive debugger. **Set `debug=False`** for any deployment accessible outside localhost:

  ```python
  # app.py, last line
  app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
  ```

  When using Gunicorn or uWSGI, `debug=True` in `app.py` has no effect — debug mode is controlled by the WSGI server.

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `ModuleNotFoundError: flask` | Virtual environment not activated | `source venv/bin/activate` |
| Blank EAT dropdown in UI | `FortiSIEM_Event_Atrributes.json` missing or not loaded | Check `docs/SIEM_Event_Attributes/` exists; restart app and check console for sync errors |
| AI button not visible | `claude` binary not on PATH | Install Claude CLI or ignore — feature is optional |
| `parser_studio.db` keeps growing | Parser imports re-running on each restart | Normal behaviour; duplicate detection prevents actual duplicates |
| Port 5000 conflict on macOS | macOS AirPlay Receiver uses port 5000 | Set `PORT=8080` or disable AirPlay Receiver in System Settings |
| `sqlite3.OperationalError: database is locked` | Concurrent writes to SQLite | Run a single worker (`--workers 1`) or switch to PostgreSQL via a Flask-SQLAlchemy migration |
