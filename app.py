import os
import re
from flask import Flask, render_template, request, jsonify, send_file
import io

from parser_studio.db import (init_db, get_device_types, add_device_type,
                               save_parser, get_parsers, get_parser_by_id,
                               update_parser, save_samples, get_samples,
                               sync_device_types)

DEVICE_TYPES_FILE = "docs/SIEM_Event_Attributes/device_types.txt"


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
from parser_studio.extractor import extract_fields
from parser_studio.mapper import suggest_mappings
from parser_studio.generator import generate_parser
from parser_studio.simulator import simulate, test_against_library
from parser_studio.importer import sync_parsers
import xml.etree.ElementTree as ET

DB_PATH      = os.environ.get("PARSER_STUDIO_DB", "parser_studio.db")
PARSERS_DIR  = "."

app = Flask(__name__, template_folder="parser_studio/templates",
            static_folder="parser_studio/static")


@app.before_request
def startup():
    """Init DB and sync parsers on first request only."""
    if not hasattr(app, "_started"):
        init_db(DB_PATH)
        sync_device_types(DB_PATH, _load_device_types_from_file())
        if os.path.isdir(PARSERS_DIR):
            sync_parsers(PARSERS_DIR, DB_PATH)
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
    mappings = suggest_mappings(list(fields.keys()))

    return jsonify({
        "format":   fmt,
        "fields":   fields,
        "mappings": mappings,
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
    xml_str = data.get("xml", "")
    try:
        ET.fromstring(xml_str)
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
        result = test_against_library(samples, DB_PATH)
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
    fname = f"{p['name']}.xml"
    return send_file(
        io.BytesIO(p["xml_content"].encode()),
        mimetype="application/xml",
        as_attachment=True,
        download_name=fname,
    )


# === Sync from disk ===

@app.route("/api/parsers/sync", methods=["POST"])
def api_sync_parsers():
    if not os.path.isdir(PARSERS_DIR):
        return jsonify({"imported": 0})
    count = sync_parsers(PARSERS_DIR, DB_PATH)
    return jsonify({"imported": count})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
