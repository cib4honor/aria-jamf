"""
ARIA — Automated Resolution & Incident Assistant
Self-hosted AI-powered Jamf Pro troubleshooting tool.
https://github.com/YOUR_USERNAME/aria-jamf
"""

import os, time, logging, json
from functools import wraps
from pathlib import Path

import requests
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv

# ── Load config ───────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
load_dotenv(BASE_DIR / ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(os.path.expanduser("~/Library/Logs/aria_server.log")),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("aria")

app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app, origins="*")

JAMF_URL        = os.environ["JAMF_URL"].rstrip("/")
JAMF_CLIENT_ID  = os.environ["JAMF_CLIENT_ID"]
JAMF_CLIENT_SEC = os.environ["JAMF_CLIENT_SECRET"]
ARIA_API_KEY    = os.environ["ARIA_API_KEY"]
ANTHROPIC_KEY   = os.environ.get("ANTHROPIC_API_KEY", "")
ORG_NAME        = os.environ.get("ORG_NAME", "Your Organization")
TECH_NAMES      = [t.strip() for t in os.environ.get("TECH_NAMES", "").split(",") if t.strip()]

# Load EA field name mappings
EA_CONFIG_PATH = BASE_DIR / "config" / "extension_attributes.json"
EA_CONFIG = {}
if EA_CONFIG_PATH.exists():
    with open(EA_CONFIG_PATH) as f:
        EA_CONFIG = json.load(f)

# Load system prompt
SYSTEM_PROMPT_PATH = BASE_DIR / "config" / "system_prompt.txt"
SYSTEM_PROMPT = ""
if SYSTEM_PROMPT_PATH.exists():
    SYSTEM_PROMPT = SYSTEM_PROMPT_PATH.read_text()

LOG_FILE = BASE_DIR / "handoff_log.json"

# ── Token Cache ───────────────────────────────────────────────────
_token_cache = {"token": None, "expires_at": 0}

def get_bearer_token() -> str:
    now = time.time()
    if _token_cache["token"] and now < _token_cache["expires_at"] - 60:
        return _token_cache["token"]
    log.info("Refreshing Jamf bearer token...")
    resp = requests.post(
        f"{JAMF_URL}/api/oauth/token",
        data={"client_id": JAMF_CLIENT_ID, "client_secret": JAMF_CLIENT_SEC, "grant_type": "client_credentials"},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    _token_cache["token"] = data["access_token"]
    _token_cache["expires_at"] = now + data.get("expires_in", 1800)
    return _token_cache["token"]

def jamf_headers() -> dict:
    return {"Authorization": f"Bearer {get_bearer_token()}", "Accept": "application/json", "Content-Type": "application/json"}

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.headers.get("X-ARIA-Key", "") != ARIA_API_KEY:
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

def get_computer_id(serial: str):
    resp = requests.get(f"{JAMF_URL}/JSSResource/computers/serialnumber/{serial}", headers=jamf_headers(), timeout=10)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    return resp.json()["computer"]["general"]["id"]

def send_mdm_command(computer_id: int, command: str) -> dict:
    resp = requests.post(
        f"{JAMF_URL}/JSSResource/computercommands/command/{command}/id/{computer_id}",
        headers=jamf_headers(), timeout=10,
    )
    resp.raise_for_status()
    return {"success": True, "command": command}

# ── Handoff Log ───────────────────────────────────────────────────
def read_log():
    if not LOG_FILE.exists():
        return []
    try:
        return json.loads(LOG_FILE.read_text())
    except Exception:
        return []

def write_log(entries):
    LOG_FILE.write_text(json.dumps(entries, indent=2))

# ── Fleet Cache ───────────────────────────────────────────────────
_fleet_cache = {"data": None, "fetched_at": 0}
FLEET_TTL = 900

def fetch_fleet(force=False) -> list:
    now = time.time()
    if not force and _fleet_cache["data"] and now < _fleet_cache["fetched_at"] + FLEET_TTL:
        return _fleet_cache["data"]
    log.info("Fetching fleet inventory...")
    sections = "GENERAL&section=DISK_ENCRYPTION&section=HARDWARE&section=USER_AND_LOCATION&section=EXTENSION_ATTRIBUTES&section=OPERATING_SYSTEM"
    page, all_devices = 0, []
    while True:
        resp = requests.get(
            f"{JAMF_URL}/api/v1/computers-inventory?page={page}&page-size=100&section={sections}",
            headers=jamf_headers(), timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        results = data.get("results", [])
        all_devices.extend(results)
        if len(all_devices) >= data.get("totalCount", 0) or not results:
            break
        page += 1
    _fleet_cache["data"] = all_devices
    _fleet_cache["fetched_at"] = now
    log.info("Fleet cached — %d devices", len(all_devices))
    return all_devices

def ea_value(device: dict, name: str) -> str:
    if not name:
        return ""
    for ea in device.get("extensionAttributes", []):
        if ea.get("name") == name:
            vals = ea.get("values", [])
            return vals[0] if vals else ""
    return ""

def fleet_device_summary(d: dict) -> dict:
    gen = d.get("general", {})
    hw  = d.get("hardware", {})
    loc = d.get("userAndLocation", {})
    fv  = d.get("diskEncryption", {})
    os_ = d.get("operatingSystem", {})
    fv_users = fv.get("fileVault2EnabledUserNames", [])
    filevault = fv.get("fileVault2Enabled", False) or (isinstance(fv_users, list) and len(fv_users) > 0)
    last_contact = gen.get("lastContactTime") or gen.get("reportDate")
    hours_since = None
    if last_contact:
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(last_contact.replace("Z", "+00:00"))
            hours_since = round((datetime.now(timezone.utc) - dt).total_seconds() / 3600, 1)
        except Exception:
            pass
    ea_cfg = EA_CONFIG
    return {
        "id":            d.get("id"),
        "name":          gen.get("name", ""),
        "serial":        hw.get("serialNumber", ""),
        "model":         hw.get("model", ""),
        "site":          (gen.get("site") or {}).get("name", ""),
        "username":      loc.get("username", ""),
        "os_version":    os_.get("version", ""),
        "managed":       (gen.get("remoteManagement") or {}).get("managed", False),
        "last_contact":  last_contact,
        "hours_since":   hours_since,
        "filevault":     filevault,
        "super_compliant": ea_value(d, ea_cfg.get("super", {}).get("compliant", "")),
        "jc_version":    ea_value(d, ea_cfg.get("jamf_connect", {}).get("version", "")),
    }

# ── Routes ────────────────────────────────────────────────────────

@app.route("/")
def index():
    return send_from_directory("templates", "index.html")

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "ARIA", "org": ORG_NAME})

@app.route("/api/config")
@require_api_key
def get_config():
    """Return non-sensitive config to the frontend."""
    return jsonify({
        "org_name": ORG_NAME,
        "tech_names": TECH_NAMES,
        "ea_config": EA_CONFIG,
    })

@app.route("/api/chat", methods=["POST"])
@require_api_key
def chat_proxy():
    if not ANTHROPIC_KEY:
        return jsonify({"error": "ANTHROPIC_API_KEY not set in .env"}), 503
    payload = request.get_json(force=True, silent=True) or {}
    # Inject system prompt from file if not provided
    if "system" not in payload and SYSTEM_PROMPT:
        payload["system"] = SYSTEM_PROMPT
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        json=payload, timeout=30,
    )
    return jsonify(resp.json()), resp.status_code

@app.route("/api/device/<serial>")
@require_api_key
def get_device(serial):
    serial = serial.upper().strip()
    resp = requests.get(f"{JAMF_URL}/JSSResource/computers/serialnumber/{serial}", headers=jamf_headers(), timeout=10)
    if resp.status_code == 404:
        return jsonify({"error": f"Device not found: {serial}"}), 404
    resp.raise_for_status()
    c   = resp.json()["computer"]
    gen = c.get("general", {})
    hw  = c.get("hardware", {})
    loc = c.get("location", {})
    raw_ea = c.get("extension_attributes", {})
    ea_list = raw_ea if isinstance(raw_ea, list) else raw_ea.get("extension_attribute", [])
    if isinstance(ea_list, dict): ea_list = [ea_list]
    ext = {ea["name"]: ea.get("value") for ea in ea_list if isinstance(ea, dict)}
    fv_users = hw.get("filevault2_users", [])
    filevault_enabled = hw.get("filevault2_enabled") is True or (isinstance(fv_users, list) and len(fv_users) > 0)
    apple_silicon = (
        hw.get("apple_silicon") is True
        or hw.get("processor_architecture", "").lower() == "arm64"
        or hw.get("processor_type", "").lower().startswith("apple")
    )
    return jsonify({
        "id": gen.get("id"), "name": gen.get("name"), "serial": serial,
        "model": hw.get("model"), "apple_silicon": apple_silicon,
        "processor_type": hw.get("processor_type"),
        "os_version": hw.get("os_version"), "os_build": hw.get("os_build"),
        "last_check_in": gen.get("last_contact_time"),
        "managed": gen.get("remote_management", {}).get("managed"),
        "supervised": gen.get("supervised"),
        "site": gen.get("site", {}).get("name"),
        "department": loc.get("department") or "—",
        "username": loc.get("username") or gen.get("username"),
        "realname": loc.get("realname"),
        "email": loc.get("email_address"),
        "filevault_enabled": filevault_enabled,
        "filevault_users": len(fv_users) if isinstance(fv_users, list) else 0,
        "extension_attributes": ext,
    })

@app.route("/api/device/<serial>/flush-mdm", methods=["POST"])
@require_api_key
def flush_mdm(serial):
    cid = get_computer_id(serial.upper())
    if not cid: return jsonify({"error": "Not found"}), 404
    try: return jsonify(send_mdm_command(cid, "BlankPush"))
    except requests.exceptions.HTTPError as e:
        if e.response.status_code in (401, 403):
            return jsonify({"success": False, "note": "BlankPush not authorized in your Jamf API role."}), 200
        raise

@app.route("/api/device/<serial>/restart", methods=["POST"])
@require_api_key
def restart_device(serial):
    cid = get_computer_id(serial.upper())
    if not cid: return jsonify({"error": "Not found"}), 404
    return jsonify(send_mdm_command(cid, "RestartNow"))

@app.route("/api/device/<serial>/lock", methods=["POST"])
@require_api_key
def lock_device(serial):
    cid = get_computer_id(serial.upper())
    if not cid: return jsonify({"error": "Not found"}), 404
    try: return jsonify(send_mdm_command(cid, "DeviceLock"))
    except requests.exceptions.HTTPError as e:
        if e.response.status_code in (401, 403):
            return jsonify({"success": False, "note": "Lock not authorized in your Jamf API role."}), 200
        raise

@app.route("/api/device/<serial>/policies")
@require_api_key
def get_device_policies(serial):
    cid = get_computer_id(serial.upper())
    if not cid: return jsonify({"error": "Not found"}), 404
    resp = requests.get(f"{JAMF_URL}/JSSResource/computerhistory/id/{cid}/subset/PolicyLogs", headers=jamf_headers(), timeout=10)
    resp.raise_for_status()
    ch = resp.json().get("computer_history", {})
    pl = ch.get("policy_logs", [])
    if isinstance(pl, dict): pl = pl.get("policy_log", [])
    if isinstance(pl, dict): pl = [pl]
    logs = sorted(pl if isinstance(pl, list) else [], key=lambda x: x.get("date_completed_epoch", 0), reverse=True)
    offset = int(request.args.get("offset", 0))
    limit  = int(request.args.get("limit", 15))
    return jsonify({"policy_logs": logs[offset:offset+limit], "total": len(logs), "offset": offset})

@app.route("/api/user/<username>")
@require_api_key
def get_user_devices(username):
    resp = requests.get(f"{JAMF_URL}/JSSResource/computers", headers=jamf_headers(), timeout=15)
    resp.raise_for_status()
    matches = [c for c in resp.json().get("computers", []) if (c.get("username") or "").lower() == username.lower()]
    return jsonify({"username": username, "devices": matches})

@app.route("/api/fleet/sites")
@require_api_key
def fleet_sites():
    devices = fetch_fleet()
    sites = sorted(set((d.get("general", {}).get("site") or {}).get("name", "") for d in devices) - {""})
    return jsonify({"sites": sites})

@app.route("/api/fleet/query")
@require_api_key
def fleet_query():
    query = request.args.get("q", "").strip().lower()
    force = request.args.get("refresh", "false").lower() == "true"
    if not query: return jsonify({"error": "Missing ?q="}), 400
    devices = fetch_fleet(force=force)
    summaries = [fleet_device_summary(d) for d in devices]
    queries = {
        "stale_7":           (lambda d: d["hours_since"] is not None and d["hours_since"] > 168,  "Not checked in > 7 days"),
        "stale_14":          (lambda d: d["hours_since"] is not None and d["hours_since"] > 336,  "Not checked in > 14 days"),
        "stale_30":          (lambda d: d["hours_since"] is not None and d["hours_since"] > 720,  "Not checked in > 30 days"),
        "filevault_off":     (lambda d: not d["filevault"],                                        "FileVault disabled"),
        "unmanaged":         (lambda d: not d["managed"],                                          "Not managed by Jamf"),
        "super_noncompliant":(lambda d: d["super_compliant"] and "non" in d["super_compliant"].lower(), "SUPER non-compliant"),
        "jc_missing":        (lambda d: not d["jc_version"] or d["jc_version"] in ("", "Does not exist"), "Jamf Connect not installed"),
        "all":               (lambda d: True,                                                      "All devices"),
    }
    if query.startswith("site:"):
        site_name = query[5:].strip()
        results = [d for d in summaries if d["site"].lower() == site_name.lower()]
        label = f"Site: {site_name}"
    elif query in queries:
        fn, label = queries[query]
        results = [d for d in summaries if fn(d)]
    else:
        return jsonify({"error": f"Unknown query: {query}"}), 400
    results.sort(key=lambda x: x["hours_since"] or 0, reverse=True)
    cache_age = round((time.time() - _fleet_cache["fetched_at"]) / 60, 1) if _fleet_cache["fetched_at"] else None
    return jsonify({"query": query, "label": label, "count": len(results), "total_fleet": len(summaries), "cache_age_minutes": cache_age, "results": results})

@app.route("/api/log", methods=["GET"])
@require_api_key
def get_log():
    entries = read_log()
    device = request.args.get("device", "").strip().upper()
    if device:
        entries = [e for e in entries if e.get("device") and device in str(e.get("device", "")).upper()]
    return jsonify({"entries": entries})

@app.route("/api/log", methods=["POST"])
@require_api_key
def add_log():
    payload = request.get_json(force=True, silent=True) or {}
    text = payload.get("text", "").strip()
    if not text: return jsonify({"error": "No text"}), 400
    entry = {"tech": payload.get("tech", "Unknown"), "text": text, "ts": payload.get("ts", int(time.time() * 1000)), "device": payload.get("device")}
    entries = read_log()
    entries.append(entry)
    write_log(entries)
    return jsonify({"success": True, "entry": entry})

@app.route("/api/log/<int:index>", methods=["DELETE"])
@require_api_key
def delete_log(index):
    entries = read_log()
    if index < 0 or index >= len(entries): return jsonify({"error": "Invalid index"}), 404
    entries.pop(index)
    write_log(entries)
    return jsonify({"success": True})

@app.route("/api/log/<int:index>", methods=["PATCH"])
@require_api_key
def edit_log(index):
    entries = read_log()
    if index < 0 or index >= len(entries): return jsonify({"error": "Invalid index"}), 404
    text = (request.get_json(force=True, silent=True) or {}).get("text", "").strip()
    if not text: return jsonify({"error": "No text"}), 400
    entries[index]["text"] = text
    entries[index]["edited"] = True
    write_log(entries)
    return jsonify({"success": True, "entry": entries[index]})

@app.route("/api/escalate", methods=["POST"])
@require_api_key
def escalate():
    webhook = os.environ.get("SLACK_WEBHOOK_URL", "")
    if not webhook: return jsonify({"error": "SLACK_WEBHOOK_URL not set"}), 503
    text = (request.get_json(force=True, silent=True) or {}).get("text", "")
    if not text: return jsonify({"error": "No text"}), 400
    resp = requests.post(webhook, json={"text": text}, timeout=10)
    return jsonify({"success": resp.status_code == 200})

@app.errorhandler(500)
def handle_500(e):
    log.error("Server error: %s", e, exc_info=True)
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("ARIA_PORT", 5001))
    cert = BASE_DIR / "aria-cert.pem"
    key  = BASE_DIR / "aria-key.pem"
    ssl_ctx = (str(cert), str(key)) if cert.exists() and key.exists() else None
    log.info("ARIA starting on port %d (%s) — %s", port, "HTTPS" if ssl_ctx else "HTTP", ORG_NAME)
    app.run(host="0.0.0.0", port=port, debug=False, ssl_context=ssl_ctx)
