import os
import re
import json
import shutil
import subprocess
from flask import Flask, render_template, request, jsonify, send_file
import io

from parser_studio.db import (init_db, get_device_types, add_device_type,
                               save_parser, get_parsers, get_parser_by_id,
                               update_parser, save_samples, get_samples,
                               sync_device_types, sync_event_attributes,
                               get_event_attributes, get_eat_value_types,
                               get_eat_names)

DEVICE_TYPES_FILE = "docs/SIEM_Event_Attributes/device_types.txt"
EAT_FILE          = "docs/SIEM_Event_Attributes/FortiSIEM_Event_Atrributes.json"


def _load_device_types_from_file() -> list[tuple]:
    """Parse device_types.txt — strip leading number, import full line as device type name."""
    if not os.path.isfile(DEVICE_TYPES_FILE):
        return []
    seen, entries = set(), []
    with open(DEVICE_TYPES_FILE) as f:
        for line in f:
            text = re.sub(r'^\d+\.\s*', '', line).strip()
            if text and text not in seen:
                seen.add(text)
                entries.append((text, "ANY", "ANY"))
    return entries
from parser_studio.detector import detect_format
from parser_studio.extractor import extract_fields, build_token_matrix
from parser_studio.mapper import suggest_mappings
from parser_studio.generator import generate_parser
from parser_studio.simulator import simulate, test_against_library
from parser_studio.importer import sync_parsers
import xml.etree.ElementTree as ET

DB_PATH      = os.environ.get("PARSER_STUDIO_DB", "parser_studio.db")
PARSERS_DIRS = [".", "parsers"]   # "." = complete <eventParser> files; "parsers/" = fragments

app = Flask(__name__, template_folder="parser_studio/templates",
            static_folder="parser_studio/static")


@app.before_request
def startup():
    """Init DB and sync parsers on first request only."""
    if not hasattr(app, "_started"):
        init_db(DB_PATH)
        sync_device_types(DB_PATH, _load_device_types_from_file())
        if os.path.isfile(EAT_FILE):
            sync_event_attributes(DB_PATH, EAT_FILE)
        for d in PARSERS_DIRS:
            if os.path.isdir(d):
                sync_parsers(d, DB_PATH)
        app._started = True


@app.route("/")
def index():
    return render_template("index.html")


# === Device Types ===

@app.route("/api/device-types", methods=["GET"])
def api_get_device_types():
    return jsonify(get_device_types(DB_PATH))


@app.route("/api/device-types", methods=["POST"])
def api_add_device_type():
    data = request.get_json(force=True)
    add_device_type(DB_PATH, data["vendor"], data["model"],
                    data.get("version", "ANY"))
    return jsonify({"ok": True})


# === Analysis ===

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data    = request.get_json(force=True)
    samples = [s.strip() for s in data.get("samples", []) if s.strip()]
    if not samples:
        return jsonify({"error": "No samples provided"}), 400

    fmt    = detect_format(samples)
    fields = extract_fields(samples, fmt)
    eat_rows = get_event_attributes(DB_PATH)
    field_values = {f: info.get("values", []) for f, info in fields.items()}
    mappings = suggest_mappings(list(fields.keys()), eat_rows, field_values)
    matrix = build_token_matrix(samples, fmt)

    return jsonify({
        "format":       fmt,
        "fields":       fields,
        "mappings":     mappings,
        "token_matrix": matrix,
        "sample_count": len(samples),
    })


# === Generate ===

@app.route("/api/generate", methods=["POST"])
def api_generate():
    data     = request.get_json(force=True)
    meta     = data.get("meta", {})
    mappings = data.get("mappings", {})   # {field: eat}
    fmt      = data.get("format", "syslog+text")
    samples  = data.get("samples", [])

    xml_str = generate_parser(meta, mappings, fmt, samples)
    return jsonify({"xml": xml_str})


# === Validate ===

@app.route("/api/validate", methods=["POST"])
def api_validate():
    data    = request.get_json(force=True)
    xml_str = (data.get("xml") or "").strip()
    # Accept both a complete <eventParser> document and a <patternDefinitions> fragment
    to_parse = (xml_str if xml_str.startswith("<eventParser")
                else f"<eventParser>{xml_str}</eventParser>")
    try:
        ET.fromstring(to_parse)
        return jsonify({"valid": True})
    except ET.ParseError as e:
        return jsonify({"valid": False, "error": str(e)})


# === Test / Simulate ===

@app.route("/api/test", methods=["POST"])
def api_test():
    """Two modes:
    - Single-parser: body contains "xml" → simulate() against provided XML.
    - Library mode: no "xml" → test_against_library() checks all enabled parsers.
    """
    data    = request.get_json(force=True)
    xml_str = (data.get("xml") or "").strip()
    samples = [s for s in data.get("samples", []) if s.strip()]
    if not samples:
        return jsonify({"error": "No samples provided"}), 400

    if xml_str:
        # Single-parser mode
        results = simulate(xml_str, samples)
        return jsonify({"mode": "single", "results": results})
    else:
        # Library mode: rank all enabled parsers and return structured result
        # current_xml (optional) is prepended as a virtual entry so the editor's
        # unsaved XML appears in results even before it is saved to the DB.
        current_xml = (data.get("current_xml") or "").strip()
        result = test_against_library(samples, DB_PATH, current_xml)
        return jsonify({"mode": "library", **result})


# === Save Parser ===

@app.route("/api/parsers/save", methods=["POST"])
def api_save_parser():
    data = request.get_json(force=True)
    pid  = save_parser(DB_PATH, {
        "name":        data["name"],
        "scope":       data.get("scope", "enabled"),
        "parser_type": data.get("parser_type", "User"),
        "vendor":      data.get("vendor"),
        "model":       data.get("model"),
        "version":     data.get("version", "ANY"),
        "xml_content": data.get("xml"),
        "source":      "studio",
        "file_path":   None,
    })
    if data.get("samples"):
        save_samples(DB_PATH, pid,
                     [{"raw_log": s, "label": f"Sample {i+1}"}
                      for i, s in enumerate(data["samples"])])
    return jsonify({"ok": True, "id": pid})


# === List Parsers ===

@app.route("/api/parsers", methods=["GET"])
def api_list_parsers():
    return jsonify(get_parsers(DB_PATH))


@app.route("/api/parsers/<int:pid>", methods=["GET"])
def api_get_parser(pid: int):
    p = get_parser_by_id(DB_PATH, pid)
    if not p:
        return jsonify({"error": "Not found"}), 404
    samples = get_samples(DB_PATH, pid)
    return jsonify({"parser": p, "samples": samples})


@app.route("/api/parsers/<int:pid>", methods=["PUT"])
def api_update_parser(pid: int):
    p = get_parser_by_id(DB_PATH, pid)
    if not p:
        return jsonify({"error": "Not found"}), 404
    data = request.get_json(force=True)
    try:
        update_parser(DB_PATH, pid, {
            "name":        data.get("name", p["name"]),
            "scope":       data.get("scope", p["scope"]),
            "vendor":      data.get("vendor", p["vendor"]),
            "model":       data.get("model", p["model"]),
            "version":     data.get("version", p["version"]),
            "xml_content": data.get("xml", p["xml_content"]),
        })
    except ValueError:
        return jsonify({"error": "Not found"}), 404
    if "samples" in data:
        save_samples(DB_PATH, pid,
                     [{"raw_log": s, "label": f"Sample {i+1}"}
                      for i, s in enumerate(data["samples"])])
    return jsonify({"ok": True})


# === Download Parser ===

@app.route("/api/parsers/<int:pid>/download", methods=["GET"])
def api_download_parser(pid: int):
    p = get_parser_by_id(DB_PATH, pid)
    if not p:
        return jsonify({"error": "Not found"}), 404
    # Reconstruct the full <eventParser> document from stored metadata + fragment.
    # Only include <deviceType> when vendor and model are real values — omit it
    # when they are "Unknown" or blank (e.g. parsers imported from fragments).
    vendor  = (p.get("vendor")  or "").strip()
    model   = (p.get("model")   or "").strip()
    version = (p.get("version") or "ANY").strip()
    known   = vendor and vendor != "Unknown" and model and model != "Unknown"
    device_type_block = (
        f'  <deviceType>\n'
        f'    <Vendor>{vendor}</Vendor>\n'
        f'    <Model>{model}</Model>\n'
        f'    <Version>{version}</Version>\n'
        f'  </deviceType>\n'
    ) if known else ""
    full_xml = (
        f'<eventParser name="{p["name"]}">\n'
        f'{device_type_block}'
        f'{p["xml_content"] or ""}\n'
        '</eventParser>\n'
    )
    fname = f"{p['name']}.xml"
    return send_file(
        io.BytesIO(full_xml.encode()),
        mimetype="application/xml",
        as_attachment=True,
        download_name=fname,
    )


# === Sync from disk ===

@app.route("/api/parsers/sync", methods=["POST"])
def api_sync_parsers():
    count = sum(sync_parsers(d, DB_PATH) for d in PARSERS_DIRS if os.path.isdir(d))
    return jsonify({"imported": count})


# === Event Attribute Types (EAT) ===

@app.route("/api/eat", methods=["GET"])
def api_get_eat():
    search     = request.args.get("q", "").strip()
    value_type = request.args.get("valueType", "").strip()
    return jsonify(get_event_attributes(DB_PATH, search, value_type))


@app.route("/api/eat/value-types", methods=["GET"])
def api_eat_value_types():
    return jsonify(get_eat_value_types(DB_PATH))


@app.route("/api/eat/names", methods=["GET"])
def api_eat_names():
    return jsonify(get_eat_names(DB_PATH))


def _claude_binary() -> str | None:
    """Return path to the claude CLI binary, or None if unavailable."""
    return shutil.which("claude")


@app.route("/api/ai-suggest-eat", methods=["GET"])
def api_ai_suggest_eat_probe():
    """Probe endpoint: returns {"available": bool}."""
    return jsonify({"available": _claude_binary() is not None})


@app.route("/api/ai-suggest-eat", methods=["POST"])
def api_ai_suggest_eat():
    """Ask the claude CLI to pick the best EAT for a single field."""
    claude = _claude_binary()
    if not claude:
        return jsonify({"error": "claude CLI not available"}), 503

    data = request.get_json(force=True)
    field = (data.get("field") or "").strip()
    values = data.get("values") or []
    candidates = data.get("candidates") or []

    if not field:
        return jsonify({"error": "field is required"}), 400

    # Top 20 candidates by name for context
    all_candidates = candidates[:20]

    prompt = (
        "You are a FortiSIEM EAT mapping expert. Reply with ONLY valid JSON, no markdown.\n\n"
        f"Field name: {field}\n"
        f"Sample values: {json.dumps(values[:10])}\n"
        f"Top programmatic candidates: {json.dumps(candidates[:5])}\n"
        f"Full candidate list (pick from these only): {json.dumps(all_candidates)}\n\n"
        'Reply format: {"eat": "<name>", "reason": "<one sentence max>"}'
    )

    try:
        result = subprocess.run(
            [claude, "-p", "--output-format", "json", prompt],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return jsonify({"error": f"claude exited {result.returncode}",
                            "detail": result.stderr[:500]}), 502

        # claude --output-format json wraps output; try to extract inner JSON
        raw = result.stdout.strip()
        # Try to parse the outer wrapper ({"type":"result","result":"..."})
        try:
            outer = json.loads(raw)
            inner_text = outer.get("result") or raw
        except (json.JSONDecodeError, AttributeError):
            inner_text = raw

        # Extract the first JSON object from inner_text
        match = re.search(r'\{[^{}]*"eat"[^{}]*\}', inner_text, re.DOTALL)
        if match:
            payload = json.loads(match.group(0))
        else:
            payload = json.loads(inner_text)

        return jsonify({
            "eat": payload.get("eat", ""),
            "reason": payload.get("reason", ""),
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "claude timed out"}), 504
    except (json.JSONDecodeError, ValueError) as e:
        return jsonify({"error": f"Failed to parse claude response: {e}",
                        "raw": result.stdout[:500] if 'result' in dir() else ""}), 502


if __name__ == "__main__":
    app.run(debug=True, port=5000)
