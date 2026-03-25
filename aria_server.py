"""
ARIA Backend Server
Runs on your Mac as a LaunchAgent on port 5001 (HTTPS).
"""

import os, time, logging, json, secrets, warnings
from functools import wraps
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Suppress LibreSSL/OpenSSL version mismatch noise from urllib3 on macOS
warnings.filterwarnings("ignore", message=".*OpenSSL.*")
warnings.filterwarnings("ignore", message=".*LibreSSL.*")

import requests
import bcrypt
import jwt as pyjwt
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv

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
log.propagate = False
# Suppress werkzeug's duplicate access log and exception log
logging.getLogger("werkzeug").setLevel(logging.ERROR)
logging.getLogger("werkzeug").propagate = False
# Suppress Flask's own exception logger to avoid duplicate error entries
logging.getLogger("flask.app").propagate = False

app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app, origins="*")

# ── Config ────────────────────────────────────────────────────────
JAMF_URL        = os.environ["JAMF_URL"].rstrip("/")
JAMF_CLIENT_ID  = os.environ["JAMF_CLIENT_ID"]
JAMF_CLIENT_SEC = os.environ["JAMF_CLIENT_SECRET"]
ANTHROPIC_KEY   = os.environ.get("ANTHROPIC_API_KEY", "")
JWT_SECRET      = os.environ.get("ARIA_JWT_SECRET", secrets.token_hex(32))
SESSION_HOURS   = int(os.environ.get("ARIA_SESSION_HOURS", 8))

USERS_FILE      = BASE_DIR / "config" / "users.json"
AUDIT_FILE      = BASE_DIR / "audit_log.json"
LOG_FILE        = BASE_DIR / "handoff_log.json"
CONNECTWISE_URL = os.environ.get("CONNECTWISE_URL","").rstrip("/")
SMTP_FROM       = os.environ.get("SMTP_FROM","")

# ── Rate limiting (in-memory) ─────────────────────────────────────
_failed_logins = {}   # ip -> {"count": N, "lockout_until": timestamp}
MAX_ATTEMPTS  = 5
LOCKOUT_SECS  = 900   # 15 minutes

# ── User helpers ──────────────────────────────────────────────────
def load_users() -> dict:
    if not USERS_FILE.exists():
        return {}
    try:
        return json.loads(USERS_FILE.read_text())
    except Exception:
        return {}

def save_users(users: dict):
    USERS_FILE.parent.mkdir(exist_ok=True)
    USERS_FILE.write_text(json.dumps(users, indent=2))

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False

def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt(12)).decode()

def issue_token(username: str, role: str, display_name: str) -> str:
    payload = {
        "sub":          username,
        "role":         role,
        "display_name": display_name,
        "iat":          datetime.now(timezone.utc),
        "exp":          datetime.now(timezone.utc) + timedelta(hours=SESSION_HOURS),
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm="HS256")

def decode_token(token: str):
    """Returns claims dict or None."""
    try:
        return pyjwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except pyjwt.ExpiredSignatureError:
        return None
    except pyjwt.InvalidTokenError:
        return None

# ── Auth decorator ────────────────────────────────────────────────
def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        claims = decode_token(auth[7:])
        if not claims:
            return jsonify({"error": "Session expired — please log in again"}), 401
        request.user = claims
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        claims = decode_token(auth[7:])
        if not claims:
            return jsonify({"error": "Session expired"}), 401
        if claims.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        request.user = claims
        return f(*args, **kwargs)
    return decorated

# ── Audit log ─────────────────────────────────────────────────────
def write_audit(action: str, tech: str, detail: str, ip: str = ""):
    entries = []
    if AUDIT_FILE.exists():
        try:
            entries = json.loads(AUDIT_FILE.read_text())
        except Exception:
            entries = []
    entries.append({
        "ts":     int(time.time() * 1000),
        "action": action,
        "tech":   tech,
        "detail": detail,
        "ip":     ip,
    })
    AUDIT_FILE.write_text(json.dumps(entries, indent=2))
    log.info("AUDIT: %s by %s — %s", action, tech, detail)

# ── Jamf token cache ──────────────────────────────────────────────
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
    _token_cache["token"]      = data["access_token"]
    _token_cache["expires_at"] = now + data.get("expires_in", 1800)
    return _token_cache["token"]

def jamf_headers() -> dict:
    return {"Authorization": f"Bearer {get_bearer_token()}", "Accept": "application/json", "Content-Type": "application/json"}

def get_computer_id(serial: str):
    resp = requests.get(f"{JAMF_URL}/JSSResource/computers/serialnumber/{serial}", headers=jamf_headers(), timeout=10)
    if resp.status_code == 404:
        return None
    resp.raise_for_status()
    try:
        return resp.json()["computer"]["general"]["id"]
    except (ValueError, KeyError, TypeError):
        return None

def send_mdm_command(computer_id: int, command: str) -> dict:
    resp = requests.post(
        f"{JAMF_URL}/JSSResource/computercommands/command/{command}/id/{computer_id}",
        headers=jamf_headers(), timeout=10,
    )
    resp.raise_for_status()
    return {"success": True, "command": command, "computer_id": computer_id}

# ── Auth routes ───────────────────────────────────────────────────
@app.route("/")
def index():
    return send_from_directory("templates", "index.html")

@app.route("/health")
def health():
    return jsonify({"status": "ok", "service": "ARIA"})

@app.route("/api/auth/login", methods=["POST"])
def login():
    ip = request.remote_addr
    # Check lockout
    record = _failed_logins.get(ip, {"count": 0, "lockout_until": 0})
    if time.time() < record["lockout_until"]:
        remaining = int(record["lockout_until"] - time.time())
        return jsonify({"error": f"Too many failed attempts. Try again in {remaining//60+1} minutes."}), 429

    data = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""

    users = load_users()
    user  = users.get(username)

    if not user or not verify_password(password, user.get("password_hash", "")):
        record["count"] = record.get("count", 0) + 1
        if record["count"] >= MAX_ATTEMPTS:
            record["lockout_until"] = time.time() + LOCKOUT_SECS
            log.warning("LOCKOUT: %s after %d failed attempts", ip, record["count"])
        _failed_logins[ip] = record
        log.warning("Failed login attempt for '%s' from %s", username, ip)
        return jsonify({"error": "Invalid username or password"}), 401

    # Success — clear failed attempts
    _failed_logins.pop(ip, None)
    token = issue_token(username, user["role"], user["display_name"])
    write_audit("LOGIN", user["display_name"], f"Logged in from {ip}", ip)
    log.info("Login: %s (%s) from %s", username, user["role"], ip)

    # Pre-warm fleet cache in background so it's ready when needed
    import threading
    def warm_fleet():
        try:
            fetch_fleet()
            log.info("Fleet cache pre-warmed after login by %s", username)
        except Exception as e:
            log.warning("Fleet pre-warm failed: %s", e)
    if not _fleet_cache["data"]:
        threading.Thread(target=warm_fleet, daemon=True).start()

    return jsonify({
        "token":               token,
        "username":            username,
        "display_name":        user["display_name"],
        "role":                user["role"],
        "must_change_password": user.get("must_change_password", False),
        "session_hours":       SESSION_HOURS,
    })

@app.route("/api/auth/logout", methods=["POST"])
@require_auth
def logout():
    write_audit("LOGOUT", request.user.get("display_name","?"), "Logged out", request.remote_addr)
    return jsonify({"success": True})

@app.route("/api/auth/me")
@require_auth
def me():
    return jsonify(request.user)

@app.route("/api/auth/change-password", methods=["POST"])
@require_auth
def change_password():
    data     = request.get_json(force=True, silent=True) or {}
    current  = data.get("current_password", "")
    new_pw   = data.get("new_password", "")
    username = request.user["sub"]

    if len(new_pw) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    users = load_users()
    user  = users.get(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Skip current password check if must_change_password (temp password flow)
    if not user.get("must_change_password"):
        if not verify_password(current, user.get("password_hash", "")):
            return jsonify({"error": "Current password is incorrect"}), 401

    users[username]["password_hash"]        = hash_password(new_pw)
    users[username]["must_change_password"] = False
    save_users(users)
    write_audit("PASSWORD_CHANGE", user["display_name"], "Password changed", request.remote_addr)
    log.info("Password changed for %s", username)

    # Issue a fresh token
    token = issue_token(username, user["role"], user["display_name"])
    return jsonify({"success": True, "token": token})

# ── Admin routes ──────────────────────────────────────────────────
@app.route("/api/admin/users")
@require_admin
def admin_list_users():
    users = load_users()
    safe  = [{
        "username":            u,
        "display_name":        d["display_name"],
        "role":                d["role"],
        "must_change_password": d.get("must_change_password", False),
    } for u, d in users.items()]
    return jsonify({"users": safe})

@app.route("/api/admin/users", methods=["POST"])
@require_admin
def admin_add_user():
    data     = request.get_json(force=True, silent=True) or {}
    username = (data.get("username") or "").strip().lower()
    display  = (data.get("display_name") or username.title()).strip()
    role     = data.get("role", "tech")

    if not username:
        return jsonify({"error": "Username required"}), 400

    users = load_users()
    if username in users:
        return jsonify({"error": f"User '{username}' already exists"}), 409

    # Generate temp password
    chars    = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789!@#$"
    temp_pw  = ''.join(secrets.choice(chars) for _ in range(12))
    users[username] = {
        "display_name":        display,
        "role":                role,
        "password_hash":       hash_password(temp_pw),
        "must_change_password": True,
    }
    save_users(users)
    write_audit("USER_ADDED", request.user["display_name"], f"Added user {username} ({role})", request.remote_addr)
    return jsonify({"success": True, "username": username, "temp_password": temp_pw, "display_name": display})

@app.route("/api/admin/users/<username>/role", methods=["PATCH"])
@require_admin
def admin_change_role(username):
    if username == request.user["sub"]:
        return jsonify({"error": "Cannot change your own role"}), 400
    users = load_users()
    if username not in users:
        return jsonify({"error": "User not found"}), 404
    new_role = (request.get_json(force=True, silent=True) or {}).get("role", "")
    if new_role not in ("tech", "admin"):
        return jsonify({"error": "Role must be tech or admin"}), 400
    users[username]["role"] = new_role
    save_users(users)
    write_audit("ROLE_CHANGE", request.user["display_name"], f"Changed {username} role to {new_role}", request.remote_addr)
    return jsonify({"success": True, "username": username, "role": new_role})

@app.route("/api/admin/users/<username>", methods=["DELETE"])
@require_admin
def admin_remove_user(username):
    if username == request.user["sub"]:
        return jsonify({"error": "Cannot remove yourself"}), 400
    users = load_users()
    if username not in users:
        return jsonify({"error": "User not found"}), 404
    removed = users.pop(username)
    save_users(users)
    write_audit("USER_REMOVED", request.user["display_name"], f"Removed user {username}", request.remote_addr)
    return jsonify({"success": True})

@app.route("/api/admin/users/<username>/reset", methods=["POST"])
@require_admin
def admin_reset_password(username):
    users = load_users()
    if username not in users:
        return jsonify({"error": "User not found"}), 404
    chars   = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789!@#$"
    temp_pw = ''.join(secrets.choice(chars) for _ in range(12))
    users[username]["password_hash"]        = hash_password(temp_pw)
    users[username]["must_change_password"] = True
    save_users(users)
    write_audit("PASSWORD_RESET", request.user["display_name"], f"Reset password for {username}", request.remote_addr)
    return jsonify({"success": True, "temp_password": temp_pw, "display_name": users[username]["display_name"]})

@app.route("/api/admin/audit")
@require_admin
def admin_audit_log():
    entries = []
    if AUDIT_FILE.exists():
        try:
            entries = json.loads(AUDIT_FILE.read_text())
        except Exception:
            entries = []
    limit  = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))
    total  = len(entries)
    page   = list(reversed(entries))[offset:offset+limit]
    return jsonify({"entries": page, "total": total})

# ── Chat ──────────────────────────────────────────────────────────
@app.route("/api/chat", methods=["POST"])
@require_auth
def chat_proxy():
    if not ANTHROPIC_KEY:
        return jsonify({"error": "ANTHROPIC_API_KEY not set in .env"}), 503
    payload = request.get_json(force=True, silent=True)
    if not payload:
        return jsonify({"error": "No payload"}), 400
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        json=payload, timeout=30,
    )
    try:
        return jsonify(resp.json()), resp.status_code
    except ValueError:
        return jsonify({"error": "Invalid response from Anthropic API"}), 502

# ── Device ────────────────────────────────────────────────────────
@app.route("/api/device/<serial>")
@require_auth
def get_device(serial):
    serial = serial.upper().strip()
    log.info("Device lookup: %s by %s", serial, request.user.get("sub","?"))
    try:
        resp = requests.get(f"{JAMF_URL}/JSSResource/computers/serialnumber/{serial}", headers=jamf_headers(), timeout=15)
    except requests.exceptions.Timeout:
        return jsonify({"error": "Jamf API timed out"}), 504
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Jamf connection error: {e}"}), 502
    if resp.status_code == 404:
        return jsonify({"error": f"Device not found: {serial}"}), 404
    try:
        resp.raise_for_status()
        c = resp.json()["computer"]
    except requests.exceptions.HTTPError:
        return jsonify({"error": f"Jamf returned HTTP {resp.status_code}"}), 502
    except (ValueError, KeyError) as e:
        return jsonify({"error": f"Unexpected Jamf response: {e}"}), 502
    gen = c.get("general", {})
    hw  = c.get("hardware", {})
    loc = c.get("location", {})
    raw_ea  = c.get("extension_attributes", {})
    ea_list = raw_ea if isinstance(raw_ea, list) else raw_ea.get("extension_attribute", [])
    if isinstance(ea_list, dict): ea_list = [ea_list]
    ext      = {ea["name"]: ea.get("value") for ea in ea_list if isinstance(ea, dict) and "name" in ea}
    fv_users = hw.get("filevault2_users", [])
    filevault_enabled = hw.get("filevault2_enabled") is True or (isinstance(fv_users, list) and len(fv_users) > 0)
    apple_silicon = (
        hw.get("apple_silicon") is True
        or hw.get("processor_architecture","").lower() == "arm64"
        or hw.get("processor_type","").lower().startswith("apple")
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
        "department": loc.get("department") or "Missing Dept.",
        "username": loc.get("username") or gen.get("username"),
        "realname": loc.get("realname") or loc.get("real_name"),
        "email": loc.get("email_address") or gen.get("email_address"),
        "filevault_enabled": filevault_enabled,
        "filevault_users": len(fv_users) if isinstance(fv_users, list) else 0,
        "extension_attributes": ext,
    })

@app.route("/api/user/<username>")
@require_auth
def get_user_devices(username):
    username = username.strip().lower()
    log.info("User lookup: %s by %s", username, request.user.get("sub","?"))
    import urllib.parse
    wildcard = "*" + "*".join(p for p in username.replace("."," ").replace("_"," ").replace("-"," ").split() if p) + "*"
    devices = []
    try:
        resp = requests.get(f"{JAMF_URL}/JSSResource/computers/match/{urllib.parse.quote(wildcard)}", headers=jamf_headers(), timeout=15)
        if resp.ok:
            for d in resp.json().get("computers", []):
                serial = d.get("serial_number") or d.get("serial") or ""
                if serial:
                    devices.append({"id":d.get("id"),"name":d.get("name",""),"serial":serial,
                        "serial_number":serial,"model":d.get("model",""),"site":d.get("site_name",""),
                        "username":d.get("username",""),"realname":d.get("real_name",""),
                        "last_contact_time":d.get("last_contact_time",""),"managed":True})
    except Exception as e:
        log.warning("Wildcard user lookup failed: %s", e)
    seen, unique = set(), []
    for d in devices:
        s = d.get("serial","")
        if s and s not in seen:
            seen.add(s); unique.append(d)
    return jsonify({"username": username, "devices": unique, "count": len(unique)})

# ── MDM Actions (with audit logging) ─────────────────────────────
@app.route("/api/device/<serial>/flush-mdm", methods=["POST"])
@require_auth
def flush_mdm(serial):
    serial = serial.upper().strip()
    cid    = get_computer_id(serial)
    if not cid: return jsonify({"error": f"Device not found: {serial}"}), 404
    try:
        result = send_mdm_command(cid, "BlankPush")
        write_audit("MDM_FLUSH", request.user["display_name"], f"Flush MDM → {serial}", request.remote_addr)
        return jsonify(result)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code in (401, 403):
            return jsonify({"success": False, "note": "BlankPush not authorized in your Jamf API role."}), 200
        return jsonify({"error": f"Jamf returned HTTP {e.response.status_code} for BlankPush command"}), 502

@app.route("/api/device/<serial>/restart", methods=["POST"])
@require_auth
def restart_device(serial):
    serial = serial.upper().strip()
    cid    = get_computer_id(serial)
    if not cid: return jsonify({"error": f"Device not found: {serial}"}), 404
    result = send_mdm_command(cid, "RestartNow")
    write_audit("MDM_RESTART", request.user["display_name"], f"Restart → {serial}", request.remote_addr)
    return jsonify(result)

@app.route("/api/device/<serial>/lock", methods=["POST"])
@require_auth
def lock_device(serial):
    serial = serial.upper().strip()
    cid    = get_computer_id(serial)
    if not cid: return jsonify({"error": f"Device not found: {serial}"}), 404
    try:
        result = send_mdm_command(cid, "DeviceLock")
        write_audit("MDM_LOCK", request.user["display_name"], f"LOCK → {serial}", request.remote_addr)
        return jsonify(result)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code in (401, 403):
            return jsonify({"success": False, "note": "Lock not authorized in your Jamf API role."}), 200
        return jsonify({"error": f"Jamf returned HTTP {e.response.status_code} for DeviceLock command"}), 502

# ── Policies ──────────────────────────────────────────────────────
@app.route("/api/device/<serial>/policies")
@require_auth
def get_device_policies(serial):
    serial = serial.upper().strip()
    cid    = get_computer_id(serial)
    if not cid: return jsonify({"error": f"Device not found: {serial}"}), 404
    try:
        resp = requests.get(f"{JAMF_URL}/JSSResource/computerhistory/id/{cid}/subset/PolicyLogs", headers=jamf_headers(), timeout=15)
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        return jsonify({"error": "Jamf API timed out fetching policy logs"}), 504
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Could not fetch policy logs: {e}"}), 502
    try:
        raw = resp.json()
        ch  = raw.get("computer_history", {}) if isinstance(raw, dict) else {}
        pl  = ch.get("policy_logs", [])
        if isinstance(pl, dict): pl = pl.get("policy_log", [])
        if isinstance(pl, dict): pl = [pl]
    except (ValueError, AttributeError, TypeError):
        pl = []
    logs = sorted(pl if isinstance(pl, list) else [], key=lambda x: x.get("date_completed_epoch", 0), reverse=True)
    offset = int(request.args.get("offset", 0))
    limit  = int(request.args.get("limit", 15))
    return jsonify({"computer_id": cid, "policy_logs": logs[offset:offset+limit], "total": len(logs), "offset": offset, "limit": limit})

import threading as _threading
_fleet_cache = {"data": None, "fetched_at": 0}
_fleet_lock  = _threading.Lock()
FLEET_TTL    = 1800  # 30 minutes

def fetch_fleet(force=False) -> list:
    now = time.time()
    if not force and _fleet_cache["data"] and now < _fleet_cache["fetched_at"] + FLEET_TTL:
        return _fleet_cache["data"]
    if not _fleet_lock.acquire(blocking=False):
        log.info("Fleet fetch already in progress, returning cached data")
        return _fleet_cache["data"] or []
    try:
        log.info("Fetching fleet inventory...")
        sections  = "GENERAL&section=DISK_ENCRYPTION&section=HARDWARE&section=USER_AND_LOCATION&section=EXTENSION_ATTRIBUTES&section=OPERATING_SYSTEM"
        page, all_devices = 0, []
        while True:
            resp = requests.get(f"{JAMF_URL}/api/v1/computers-inventory?page={page}&page-size=100&section={sections}", headers=jamf_headers(), timeout=30)
            resp.raise_for_status()
            data    = resp.json()
            results = data.get("results", [])
            all_devices.extend(results)
            if len(all_devices) >= data.get("totalCount", 0) or not results:
                break
            page += 1
        _fleet_cache["data"]       = all_devices
        _fleet_cache["fetched_at"] = now
        log.info("Fleet cached — %d devices", len(all_devices))
        return all_devices
    finally:
        _fleet_lock.release()

def _fleet_background_refresh():
    """Refresh fleet cache every 25 minutes in the background."""
    while True:
        _threading.Event().wait(1500)  # 25 minutes
        try:
            fetch_fleet(force=True)
            log.info("Fleet cache auto-refreshed")
        except Exception as e:
            log.warning("Fleet auto-refresh failed: %s", e)

# Start background refresh thread
_threading.Thread(target=_fleet_background_refresh, daemon=True).start()

def ea_value(device: dict, name: str) -> str:
    for ea in device.get("extensionAttributes", []):
        if ea.get("name") == name:
            vals = ea.get("values", [])
            return vals[0] if vals else ""
    return ""

def fleet_device_summary(d: dict) -> dict:
    gen      = d.get("general", {})
    hw       = d.get("hardware", {})
    loc      = d.get("userAndLocation", {})
    fv       = d.get("diskEncryption", {})
    os_      = d.get("operatingSystem", {})
    fv_users = fv.get("fileVault2EnabledUserNames", [])
    filevault = fv.get("fileVault2Enabled", False) or (isinstance(fv_users, list) and len(fv_users) > 0)
    last_contact = gen.get("lastContactTime") or gen.get("reportDate")
    hours_since  = None
    if last_contact:
        try:
            dt = datetime.fromisoformat(last_contact.replace("Z", "+00:00"))
            hours_since = round((datetime.now(timezone.utc) - dt).total_seconds() / 3600, 1)
        except Exception:
            pass
    return {
        "id": d.get("id"), "name": gen.get("name",""), "serial": hw.get("serialNumber",""),
        "model": hw.get("model",""), "site": (gen.get("site") or {}).get("name",""),
        "username": loc.get("username",""), "os_version": os_.get("version",""),
        "managed": (gen.get("remoteManagement") or {}).get("managed", False),
        "last_contact": last_contact, "hours_since": hours_since, "filevault": filevault,
        "super_compliant": ea_value(d, "SUPER Compliant"),
        "jc_version":      ea_value(d, "Jamf Connect Version"),
        "jc_users":        ea_value(d, "Jamf Connect Users"),
    }

# ── Jamf Protect Integration ─────────────────────────────────────
PROTECT_URL       = os.environ.get("PROTECT_URL","").rstrip("/")
PROTECT_CLIENT_ID = os.environ.get("PROTECT_CLIENT_ID","")
PROTECT_TOKEN_PW  = os.environ.get("PROTECT_TOKEN","")

_protect_token_cache = {"token": None, "expires_at": 0}

def get_protect_token() -> str:
    now = time.time()
    if _protect_token_cache["token"] and now < _protect_token_cache["expires_at"] - 60:
        return _protect_token_cache["token"]
    if not PROTECT_URL or not PROTECT_CLIENT_ID or not PROTECT_TOKEN_PW:
        raise ValueError("Jamf Protect credentials not configured")
    resp = requests.post(
        f"{PROTECT_URL}/token",
        json={"client_id": PROTECT_CLIENT_ID, "password": PROTECT_TOKEN_PW},
        headers={"Content-Type": "application/json"},
        timeout=10,
    )
    resp.raise_for_status()
    data = resp.json()
    _protect_token_cache["token"]      = data["access_token"]
    _protect_token_cache["expires_at"] = now + data.get("expires_in", 86400)
    log.info("Protect token refreshed")
    return _protect_token_cache["token"]

def protect_gql(query: str, variables: dict = None) -> dict:
    token = get_protect_token()
    resp  = requests.post(
        f"{PROTECT_URL}/graphql",
        json={"query": query, "variables": variables or {}},
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        timeout=15,
    )
    resp.raise_for_status()
    return resp.json()

def get_protect_device(serial: str) -> dict:
    """Look up a device in Protect by serial number."""
    query = """
    query GetDevice($serial: String!) {
      listComputers(input: {pageSize: 1, filter: {serial: {equals: $serial}}}) {
        items {
          hostName serial version connectionStatus
          lastConnection lastDisconnection
          insightsStatsFail insightsStatsPass
          plan { name }
        }
      }
    }"""
    data = protect_gql(query, {"serial": serial})
    items = data.get("data", {}).get("listComputers", {}).get("items", [])
    return items[0] if items else None

def get_protect_alerts(serial: str) -> list:
    """Get alerts for a device by serial."""
    query = """
    query GetAlerts($serial: String!) {
      listAlerts(input: {
        pageSize: 20,
        filter: { computer: { equals: $serial } }
      }) {
        items { id status severity eventType created }
        pageInfo { total }
      }
    }"""
    data  = protect_gql(query, {"serial": serial})
    items = data.get("data", {}).get("listAlerts", {}).get("items", [])
    total = data.get("data", {}).get("listAlerts", {}).get("pageInfo", {}).get("total", 0)
    return items, total

@app.route("/api/device/<serial>/protect")
@require_auth
def device_protect(serial):
    serial = serial.upper().strip()
    if not PROTECT_URL:
        return jsonify({"error": "Jamf Protect not configured"}), 503
    try:
        device = get_protect_device(serial)
        if not device:
            return jsonify({"found": False, "serial": serial})
        alerts, total_alerts = get_protect_alerts(serial)
        open_alerts   = [a for a in alerts if a.get("status") not in ("Resolved","AutoResolved")]
        # Connection status
        last_conn = device.get("lastConnection")
        hours_offline = None
        if last_conn:
            try:
                dt = datetime.fromisoformat(last_conn.replace("Z","+00:00"))
                hours_offline = round((datetime.now(timezone.utc) - dt).total_seconds() / 3600, 1)
            except Exception:
                pass
        return jsonify({
            "found":          True,
            "serial":         serial,
            "version":        device.get("version"),
            "connection":     device.get("connectionStatus"),
            "last_connection": last_conn,
            "hours_offline":  hours_offline,
            "plan":           (device.get("plan") or {}).get("name"),
            "insights_fail":  device.get("insightsStatsFail", 0),
            "insights_pass":  device.get("insightsStatsPass", 0),
            "open_alerts":    open_alerts,
            "total_alerts":   total_alerts,
        })
    except Exception as e:
        log.error("Protect lookup failed for %s: %s", serial, e)
        return jsonify({"error": str(e)}), 500

@app.route("/api/fleet/protect-status")
@require_auth
def fleet_protect_status():
    """Get fleet-wide Protect health: offline devices and open alerts."""
    if not PROTECT_URL:
        return jsonify({"error": "Jamf Protect not configured"}), 503
    try:
        # Devices disconnected for >24h
        q_offline = """
        query {
          listComputers(input: {
            pageSize: 200,
            filter: { connectionStatus: { equals: "Disconnected" } }
          }) {
            items { hostName serial lastConnection version plan { name } }
            pageInfo { total }
          }
        }"""
        offline_data = protect_gql(q_offline)
        offline_all  = offline_data.get("data",{}).get("listComputers",{}).get("items",[])
        total_protect = offline_data.get("data",{}).get("listComputers",{}).get("pageInfo",{}).get("total",0)

        now = datetime.now(timezone.utc)
        offline_24h = []
        for d in offline_all:
            lc = d.get("lastConnection")
            if lc:
                try:
                    dt = datetime.fromisoformat(lc.replace("Z","+00:00"))
                    hours = (now - dt).total_seconds() / 3600
                    if hours > 24:
                        d["hours_offline"] = round(hours, 1)
                        offline_24h.append(d)
                except Exception:
                    pass

        # Open alerts
        q_alerts = """
        query {
          listAlerts(input: {
            pageSize: 100,
            filter: { status: { equals: "Open" } }
          }) {
            items {
              id severity eventType created
              computer { hostName serial }
            }
            pageInfo { total }
          }
        }"""
        alerts_data  = protect_gql(q_alerts)
        open_alerts  = alerts_data.get("data",{}).get("listAlerts",{}).get("items",[])
        total_alerts = alerts_data.get("data",{}).get("listAlerts",{}).get("pageInfo",{}).get("total",0)

        return jsonify({
            "offline_24h":   offline_24h[:50],
            "offline_count": len(offline_24h),
            "open_alerts":   open_alerts[:50],
            "alert_count":   total_alerts,
            "total_protect_devices": total_protect,
        })
    except Exception as e:
        log.error("Fleet protect status failed: %s", e)
        return jsonify({"error": str(e)}), 500

# ── Conflict & Security Analyzer ─────────────────────────────────
@app.route("/api/device/<serial>/analyze", methods=["POST"])
@require_auth
def analyze_device(serial):
    """
    Run rule-based conflict and security checks on a device,
    then use Claude to summarize findings and suggest actions.
    """
    serial = serial.upper().strip()
    log.info("Analyze: %s by %s", serial, request.user.get("sub","?"))
    try:
        return _do_analyze(serial)
    except Exception as e:
        log.exception("analyze_device unhandled error for %s", serial)
        return jsonify({"error": f"Analysis failed — {type(e).__name__}: {e}"}), 500

def _do_analyze(serial):
    # ── Step 1: Gather all data ───────────────────────────────────
    # Classic API — base computer record
    try:
        resp = requests.get(f"{JAMF_URL}/JSSResource/computers/serialnumber/{serial}", headers=jamf_headers(), timeout=15)
    except requests.exceptions.Timeout:
        return jsonify({"error": "Jamf API timed out — try again in a moment"}), 504
    except requests.exceptions.RequestException as e:
        return jsonify({"error": f"Jamf connection error: {e}"}), 502
    if resp.status_code == 404:
        return jsonify({"error": f"Device not found: {serial}"}), 404
    try:
        resp.raise_for_status()
    except requests.exceptions.HTTPError:
        return jsonify({"error": f"Jamf returned HTTP {resp.status_code} for {serial}"}), 502
    try:
        computer = resp.json()["computer"]
    except (ValueError, KeyError) as e:
        return jsonify({"error": f"Unexpected Jamf response format: {e}"}), 502
    gen        = computer.get("general", {})
    hw         = computer.get("hardware", {})
    loc        = computer.get("location", {})
    cid        = gen.get("id")

    # v1 API — profiles, groups, security, EAs
    v1_resp = requests.get(
        f"{JAMF_URL}/api/v1/computers-inventory/{cid}?section=CONFIGURATION_PROFILES&section=GROUP_MEMBERSHIPS&section=SECURITY&section=EXTENSION_ATTRIBUTES&section=GENERAL",
        headers=jamf_headers(), timeout=15
    )
    try:
        _v1 = v1_resp.json() if v1_resp.ok else {}
    except ValueError:
        _v1 = {}
    v1 = _v1 if isinstance(_v1, dict) else {}
    profiles  = v1.get("configurationProfiles", [])
    groups    = v1.get("groupMemberships", [])
    security  = v1.get("security", {})
    eas_raw   = v1.get("extensionAttributes", [])
    eas       = {ea["name"]: (ea.get("values") or [""])[0] for ea in eas_raw if isinstance(ea, dict) and "name" in ea}
    # v1 API doesn't return all EAs — merge in classic API EAs for ones we need
    classic_ea_raw  = computer.get("extension_attributes") or {}
    classic_ea_list = classic_ea_raw if isinstance(classic_ea_raw, list) else (classic_ea_raw.get("extension_attribute", []) if isinstance(classic_ea_raw, dict) else [])
    if isinstance(classic_ea_list, dict): classic_ea_list = [classic_ea_list]
    for ea in classic_ea_list:
        name = ea.get("name","")
        if name and name not in eas:
            eas[name] = ea.get("value","") or ""

    # Policy history
    ph_resp = requests.get(f"{JAMF_URL}/JSSResource/computerhistory/id/{cid}/subset/PolicyLogs", headers=jamf_headers(), timeout=10)
    try:
        _ph = ph_resp.json() if ph_resp.ok else {}
        ch  = _ph.get("computer_history", {}) if isinstance(_ph, dict) else {}
    except (ValueError, AttributeError):
        ch = {}
    pl = ch.get("policy_logs", [])
    if isinstance(pl, dict): pl = pl.get("policy_log", [])
    if isinstance(pl, dict): pl = [pl]
    policy_logs = pl if isinstance(pl, list) else []

    # Pending MDM commands
    pending_resp = requests.get(f"{JAMF_URL}/JSSResource/computercommands/status/Pending", headers=jamf_headers(), timeout=10)
    pending_all  = []
    if pending_resp.ok:
        try:
            _pr = pending_resp.json()
            pc  = _pr.get("computer_commands", {}).get("computer_command", []) if isinstance(_pr, dict) else []
        except (ValueError, AttributeError):
            pc = []
        if isinstance(pc, dict): pc = [pc]
        pending_all = [c for c in (pc if isinstance(pc, list) else []) if str(c.get("management_id","")) == str(cid) or str(c.get("computer_id","")) == str(cid)]

    # ── Step 1b: Protect data (non-blocking) ─────────────────────
    protect_data = None
    if PROTECT_URL:
        try:
            protect_device = get_protect_device(serial)
            if protect_device:
                protect_alerts, protect_total = get_protect_alerts(serial)
                protect_open = [a for a in protect_alerts if a.get("status") not in ("Resolved","AutoResolved")]
                lc = protect_device.get("lastConnection")
                p_hours_offline = None
                if lc:
                    try:
                        dt = datetime.fromisoformat(lc.replace("Z","+00:00"))
                        p_hours_offline = round((datetime.now(timezone.utc) - dt).total_seconds() / 3600, 1)
                    except Exception:
                        pass
                protect_data = {
                    "version":       protect_device.get("version"),
                    "connection":    protect_device.get("connectionStatus"),
                    "hours_offline": p_hours_offline,
                    "plan":          (protect_device.get("plan") or {}).get("name"),
                    "insights_fail": protect_device.get("insightsStatsFail", 0),
                    "insights_pass": protect_device.get("insightsStatsPass", 0),
                    "open_alerts":   protect_open,
                    "total_alerts":  protect_total,
                }
        except Exception as pe:
            log.warning("Protect data unavailable for %s: %s", serial, pe)

    # ── Step 2: Rule-based checks ─────────────────────────────────
    issues = []
    def add(severity, category, title, detail, action="", escalate=False):
        issues.append({"severity":severity,"category":category,"title":title,
                        "detail":detail,"action":action,"escalate":escalate})

    now_ms   = time.time() * 1000
    day_ms   = 86400000
    profile_names = [p.get("displayName","") for p in profiles]
    smart_groups  = [g["groupName"] for g in groups if g.get("smartGroup")]
    fv_users      = hw.get("filevault2_users", [])
    fv_on         = hw.get("filevault2_enabled") is True or (isinstance(fv_users,list) and len(fv_users)>0)
    apple_silicon = (hw.get("apple_silicon") is True
                     or hw.get("processor_architecture","").lower()=="arm64"
                     or hw.get("processor_type","").lower().startswith("apple"))
    bt_status     = security.get("bootstrapTokenEscrowedStatus","")
    bt_escrowed   = bt_status == "ESCROWED"
    sip           = security.get("sipStatus","")
    last_ci       = gen.get("last_contact_time","")
    hours_stale   = None
    if last_ci:
        try:
            dt = datetime.fromisoformat(last_ci.replace("Z","+00:00"))
            hours_stale = round((datetime.now(timezone.utc)-dt).total_seconds()/3600,1)
        except Exception: pass

    super_compliant = eas.get("SUPER Compliant","")
    super_status    = eas.get("SUPER status","")
    super_last_run  = eas.get("Last Super Run","")
    super_deferrals = eas.get("number of times the user has deferred the Deadline Focus, S.U.P.E.R.M.A.N","0") or "0"
    jc_version      = eas.get("Jamf Connect Version","")
    jc_users        = eas.get("Jamf Connect Users","")
    guest_ea        = eas.get("OS - Guest Account Disabled","")
    protect_ea      = eas.get("Jamf Protect - Smart Groups","")
    department      = loc.get("department","") or ""
    username        = loc.get("username","") or gen.get("username","") or ""
    device_name     = gen.get("name","") or serial
    super_days_since = None
    if super_last_run:
        try:
            dt2 = datetime.strptime(super_last_run, "%a %b %d %H:%M:%S %Z %Y")
            super_days_since = round((datetime.now()-dt2).total_seconds()/86400,1)
        except Exception:
            try:
                from dateutil import parser as dparser
                dt2 = dparser.parse(super_last_run)
                super_days_since = round((datetime.now(timezone.utc)-dt2.replace(tzinfo=timezone.utc)).total_seconds()/86400,1)
            except Exception: pass

    # ── PROFILE CONFLICTS ──────────────────────────────────────────
    for label, matches in [
        ("SUPER",        [n for n in profile_names if "super" in n.lower()]),
        ("Jamf Connect", [n for n in profile_names if "jamf connect" in n.lower()]),
        ("FileVault",    [n for n in profile_names if any(x in n.lower() for x in ["filevault","fde","disk encrypt"])]),
        ("Password",     [n for n in profile_names if any(x in n.lower() for x in ["password","passcode"])]),
    ]:
        if len(matches) > 1:
            sev = "HIGH" if label != "Password" else "MEDIUM"
            add(sev,"CONFLICT",f"Duplicate {label} profiles ({len(matches)})",
                f"Applied: {', '.join(matches)}",
                f"Remove duplicate {label} profiles — review scope and smart group membership.")

    # ── POLICY HISTORY ANALYSIS ────────────────────────────────────
    # Repeated failures
    fail_counts = {}
    fail_epochs = {}
    for p in policy_logs:
        s = (p.get("status") or "").lower()
        if "fail" in s:
            n = p.get("policy_name","Unknown")
            fail_counts[n] = fail_counts.get(n,0)+1
            fail_epochs.setdefault(n,[]).append(p.get("date_completed_epoch",0) or 0)
    for name,count in sorted(fail_counts.items(), key=lambda x:-x[1])[:3]:
        if count >= 2:
            add("HIGH","POLICY",f"Repeated policy failure: {name}",
                f"Failed {count} time{'s' if count>1 else ''} in history.",
                "Check script errors, package integrity, and Jamf policy logs. Escalate to Bob if 5+ failures.",
                escalate=(count>=5))

    # Policy cluster — 3+ different policies failing in same 7-day window
    if len(fail_counts) >= 3:
        # Find if most failures cluster in a time window
        all_fail_epochs = [e for epochs in fail_epochs.values() for e in epochs if e]
        if all_fail_epochs:
            all_fail_epochs.sort()
            for i in range(len(all_fail_epochs)-2):
                window = all_fail_epochs[i+2] - all_fail_epochs[i]
                if window < 7*day_ms:
                    add("HIGH","PATTERN","Multiple policies failing in same window",
                        f"{len(fail_counts)} policies failed within a 7-day window — suggests infrastructure or network issue, not individual policy problems.",
                        "Check Jamf distribution point, network connectivity, and package download logs.")
                    break

    # Policy suddenly stopped — ran regularly then went quiet
    policy_history = {}
    for p in policy_logs:
        n = p.get("policy_name","Unknown")
        e = p.get("date_completed_epoch",0) or 0
        if e: policy_history.setdefault(n,[]).append(e)
    for name, epochs in policy_history.items():
        if len(epochs) >= 4:
            epochs_s = sorted(epochs)
            # Average interval between first 3 runs
            avg_interval = (epochs_s[-2]-epochs_s[0]) / max(len(epochs_s)-2,1)
            days_since_last = (now_ms - epochs_s[-1]) / day_ms
            if avg_interval > 0 and days_since_last > (avg_interval/day_ms)*3:
                add("MEDIUM","PATTERN",f"Policy stopped running: {name}",
                    f"Ran regularly every ~{round(avg_interval/day_ms)}d, last ran {round(days_since_last)}d ago.",
                    "Check if device was removed from scope, or if a scope change occurred around the last run date.")
                break  # one is enough

    # Managed but no policies in 30 days
    gen_managed = gen.get("remote_management",{}).get("managed",False)
    recent_runs = [p for p in policy_logs if (p.get("date_completed_epoch",0) or 0) > now_ms - 30*day_ms]
    if gen_managed and not recent_runs and len(policy_logs) > 0:
        add("HIGH","PATTERN","Managed but no policies ran in 30+ days",
            "Device is marked managed but has had no policy activity in over a month.",
            "Run Blank Push Check-in and check device scoping. May indicate broken MDM enrollment.")

    # Pending commands + stale
    if pending_all and hours_stale and hours_stale > 48:
        add("HIGH","MDM",f"{len(pending_all)} MDM command(s) queued — device unreachable",
            f"Device hasn't checked in for {round(hours_stale/24,1)}d. Queued: {', '.join(set(c.get('name','?') for c in pending_all))}",
            "Commands will not execute until device comes back online. Locate device physically if possible.")
    elif pending_all:
        add("MEDIUM","MDM",f"{len(pending_all)} MDM command(s) pending",
            f"Queued: {', '.join(set(c.get('name','?') for c in pending_all))}",
            "Run Blank Push Check-in to flush the queue.")

    # ── SECURITY CHECKS ────────────────────────────────────────────
    if not fv_on:
        add("HIGH","SECURITY","FileVault NOT enabled",
            "Disk is unencrypted. Sensitive data is at risk if device is lost or stolen.",
            "Push FileVault enforcement profile and ensure user with Secure Token logs in. Escalate to Bob.",
            escalate=True)

    if sip and sip != "ENABLED":
        add("HIGH","SECURITY",f"SIP is {sip}",
            "System Integrity Protection disabled — malware can modify protected system files.",
            "Investigate how SIP was disabled. Re-enable via Recovery if intentional.", escalate=True)

    gk = security.get("gatekeeperStatus","")
    if gk and gk not in ("APP_STORE_AND_IDENTIFIED_DEVELOPERS","APP_STORE"):
        add("MEDIUM","SECURITY",f"Gatekeeper: {gk}",
            "Unsigned apps can run without restriction.",
            "Push Gatekeeper enforcement profile.")

    if security.get("firewallEnabled") is False:
        add("MEDIUM","SECURITY","macOS Firewall disabled",
            "Incoming connections are not blocked.",
            "Push firewall enforcement profile.")

    sb = security.get("secureBootLevel","")
    if sb and sb not in ("FULL_SECURITY","MEDIUM_SECURITY"):
        add("LOW","SECURITY",f"Secure Boot: {sb}",
            "Not using Full or Medium Secure Boot.",
            "Review if intentional — Full Security recommended for managed Macs.")

    if not bt_escrowed and bt_status:
        add("MEDIUM","SECURITY","Bootstrap Token not escrowed",
            f"Status: {bt_status}. Required for MDM software updates and FileVault recovery.",
            "Have user log in, then: sudo profiles install -type bootstraptoken")

    if guest_ea and "fail" in guest_ea.lower():
        add("MEDIUM","SECURITY","Guest account enabled",
            "Guest login is active — unauthenticated access to this Mac.",
            "Run guest account remediation policy or push disable profile.")

    if not protect_ea or protect_ea in ("","Does not exist","Not Installed"):
        add("MEDIUM","SECURITY","Jamf Protect not installed",
            "No Protect smart group membership. Device has no endpoint threat detection.",
            "Push Jamf Protect installer via Jamf policy.")

    # ── CROSS-CORRELATIONS — things only dangerous in combination ─
    # 1. Apple Silicon + Bootstrap Token not escrowed
    #    SUPER silent MDM updates require BT on Apple Silicon
    if apple_silicon and not bt_escrowed and bt_status:
        add("HIGH","CORRELATION","Apple Silicon + Bootstrap Token not escrowed",
            "On Apple Silicon, SUPER cannot perform silent MDM-triggered updates without an escrowed Bootstrap Token. "
            "Software updates will require user interaction or will fail silently.",
            "Priority: get BT escrowed before next SUPER deadline. Have user log in and run: sudo profiles install -type bootstraptoken",
            escalate=True)

    # 2. FileVault ON + Bootstrap Token not escrowed
    #    MDM can't rotate the FileVault recovery key or perform unlock
    if fv_on and not bt_escrowed and bt_status:
        add("HIGH","CORRELATION","FileVault on but Bootstrap Token not escrowed",
            "FileVault is active but MDM cannot rotate the recovery key or unlock the disk remotely. "
            "If the user forgets their password, recovery will require physical access.",
            "Escrow Bootstrap Token urgently: have user log in → sudo profiles install -type bootstraptoken",
            escalate=True)

    # 3. SUPER non-compliant + last run > 14 days
    #    Not just deferred — SUPER may not be running at all
    if super_compliant and "non" in super_compliant.lower():
        if super_days_since and super_days_since > 14:
            add("HIGH","CORRELATION","SUPER non-compliant and not running",
                f"SUPER is non-compliant AND hasn't run in {round(super_days_since)}d. "
                "This suggests SUPER is broken or stopped, not just that the user is deferring.",
                "Check: sudo launchctl list | grep super — if missing, re-push SUPER policy. Also check Bootstrap Token.")
        else:
            add("MEDIUM","POLICY","SUPER non-compliant",
                f"Status: {super_compliant}. User may be actively deferring.",
                "Check SUPER deferrals and deadline settings.")

    # 4. High deferrals
    try:
        deferral_count = int(super_deferrals)
        if deferral_count >= 5:
            add("HIGH","POLICY",f"SUPER deferrals critical: {deferral_count}x",
                f"User has deferred updates {deferral_count} times — hard deadline likely imminent.",
                "Contact user immediately. Check hard deadline EA. Escalate to Bob if > 10 deferrals.",
                escalate=(deferral_count>10))
        elif deferral_count >= 3:
            add("MEDIUM","POLICY",f"SUPER deferrals: {deferral_count}x",
                "User is repeatedly deferring updates.",
                "Contact user about upcoming deadline.")
    except (ValueError, TypeError): pass

    # 5. Protect offline + open alerts
    if protect_data:
        open_alerts = protect_data.get("open_alerts",[])
        hours_offline = protect_data.get("hours_offline") or 0
        if open_alerts and hours_offline > 2:
            add("HIGH","CORRELATION","Protect offline with unresolved alerts",
                f"Protect agent offline {round(hours_offline)}h AND {len(open_alerts)} open alert(s). "
                "Active threats cannot be monitored or auto-remediated.",
                "Locate device. Check Protect agent: sudo /usr/local/bin/jamf-protect check-in. Escalate to Bob.",
                escalate=True)
        elif open_alerts:
            for alert in open_alerts[:3]:
                sev = alert.get("severity","?")
                aria_sev = "HIGH" if sev in ("High","Critical") else "MEDIUM"
                add(aria_sev,"PROTECT",f"Open Protect alert: {alert.get('eventType','Unknown')}",
                    f"Severity: {sev} · Created: {alert.get('created','')[:10]}",
                    "Review in Jamf Protect console. Escalate High/Critical to Bob.", escalate=(sev in ("High","Critical")))
        if hours_offline > 24:
            days = round(hours_offline/24,1)
            add("MEDIUM","PROTECT",f"Protect offline {days}d",
                f"Last connected: {protect_data.get('last_connection','unknown')[:10] if protect_data.get('last_connection') else 'unknown'}",
                "Check agent: sudo /usr/local/bin/jamf-protect check-in")
        # Protect insights > 50% failing
        ins_fail = protect_data.get("insights_fail",0) or 0
        ins_pass = protect_data.get("insights_pass",0) or 0
        ins_total = ins_fail + ins_pass
        if ins_total > 0 and ins_fail/ins_total > 0.5:
            add("HIGH","PROTECT",f"Protect insights: {ins_fail}/{ins_total} failing ({round(ins_fail/ins_total*100)}%)",
                "More than half of security baseline checks are failing — overall security posture is poor.",
                "Review failing insights in Jamf Protect console for this device.")
        elif ins_fail > 5:
            add("LOW","PROTECT",f"Protect insights: {ins_fail} failing",
                f"Pass: {ins_pass} · Fail: {ins_fail}",
                "Review failing insights in Jamf Protect console.")
    elif PROTECT_URL:
        add("LOW","PROTECT","Device not found in Jamf Protect",
            "No Protect record for this serial. Agent may not be installed.",
            "Push Jamf Protect agent via Jamf policy if this device should be protected.")

    # 6. SIP disabled + Protect issues
    if sip and sip != "ENABLED" and protect_data and (protect_data.get("insights_fail",0) or 0) > 5:
        add("HIGH","CORRELATION","SIP disabled + Protect insights failing",
            "SIP is disabled AND Protect is reporting multiple security failures. "
            "This combination significantly elevates risk of undetected compromise.",
            "Treat as potential security incident. Re-enable SIP and review Protect alerts. Escalate to Bob.",
            escalate=True)

    # 7. No user assigned + stale
    if not username and hours_stale and hours_stale > 168:
        add("MEDIUM","ASSET","Unassigned device — possibly orphaned",
            f"No user in Jamf record and not checked in for {round(hours_stale/24,1)}d. "
            "May be decommissioned, lost, or forgotten.",
            "Verify physical location. If no longer in use, begin retirement process.")

    # 8. Jamf Connect installed but 0 users
    jc_installed = jc_version and jc_version not in ("","Does not exist","Not Installed")
    try:
        jc_user_count = int(jc_users or "0")
    except (ValueError, TypeError):
        jc_user_count = 0
    if jc_installed and jc_user_count == 0:
        add("MEDIUM","CORRELATION","Jamf Connect installed but no users authenticated",
            f"JC {jc_version} is installed but 0 users have logged in through it. "
            "Users may be logging in with local accounts, bypassing IdP authentication.",
            "Verify login window is showing JC. Check for local account usage. May indicate a JC login loop.")

    # 9. Department missing — enrollment incomplete
    if not department or department.lower() in ("","missing dept.","none"):
        add("LOW","ASSET","Department not assigned",
            "Missing department suggests enrollment was incomplete or record was never updated.",
            "Update department in Jamf → Inventory → Location. Useful for scoping and reporting.")

    # 10. Device name suggests shared use — extra guest/security scrutiny
    name_lower = device_name.lower()
    is_shared = any(x in name_lower for x in ["cart","lab","shared","loaner","spare","kiosk","library"])
    if is_shared and guest_ea and "fail" in guest_ea.lower():
        add("HIGH","CORRELATION","Shared/cart device with guest account enabled",
            f"Device name '{device_name}' suggests shared use, AND guest account is active. "
            "Any student or visitor can access this Mac without credentials.",
            "Priority: push guest account disable profile to this device immediately.", escalate=True)

    # 11. Exclusion groups
    exclusion_groups = [g for g in smart_groups if "exclude" in g.lower()]
    if exclusion_groups:
        add("LOW","SCOPE",f"In {len(exclusion_groups)} exclusion group(s)",
            f"Groups: {', '.join(exclusion_groups[:4])}",
            "Verify exclusions are intentional — may explain missing policies or profiles.")

    # ── DEEP INTELLIGENCE — cross-data correlations ───────────────

    # 1. macOS too old for the chip
    os_ver = hw.get("os_version","") or ""
    try:
        major_os = int(os_ver.split(".")[0]) if os_ver else 0
    except (ValueError, IndexError):
        major_os = 0
    if apple_silicon and major_os and major_os < 14:
        add("HIGH","INTELLIGENCE","macOS too old for Apple Silicon",
            f"This Apple Silicon Mac is running macOS {os_ver}. "
            "Apple Silicon Macs should be on Sonoma (14) or Sequoia (15). "
            "Ventura and earlier miss critical AS-specific security patches and SUPER capabilities.",
            "Prioritize this device for OS upgrade via SUPER.")
    elif not apple_silicon and major_os and major_os < 13:
        add("MEDIUM","INTELLIGENCE",f"macOS {os_ver} is outdated for Intel",
            "Intel Mac running Monterey or earlier — 2+ major versions behind.",
            "Push SUPER update. Check if hardware supports Ventura/Sonoma.")

    # 2. Jamf Connect version outdated (TRSD standard = 3.14.0)
    jc_installed = jc_version and jc_version not in ("","Does not exist","Not Installed","Does Not Exist")
    if jc_installed:
        try:
            jc_parts = [int(x) for x in jc_version.split(".")[:3]]
            trsd_min = [3, 14, 0]
            if jc_parts < trsd_min:
                add("MEDIUM","INTELLIGENCE",f"Jamf Connect outdated: {jc_version}",
                    f"TRSD standard is 3.14.0. Running {jc_version} may have known login issues or missing features.",
                    "Push JC 3.14.0 update policy to this device.")
        except (ValueError, TypeError):
            pass

    # 3. SUPER version outdated (SUPER 5.x is current)
    super_ver = eas.get("SUPER version","") or ""
    if super_ver and super_ver not in ("","Does not exist","Not Installed"):
        try:
            sv_major = int(super_ver.split(".")[0])
            if sv_major < 5:
                add("LOW","INTELLIGENCE",f"SUPER version outdated: {super_ver}",
                    "SUPER 5.x is current. Older versions may have update bugs or lack Apple Silicon support.",
                    "Push SUPER updater policy to refresh to latest version.")
        except (ValueError, TypeError):
            pass

    # 4. FileVault single user + Bootstrap Token not escrowed = disaster risk
    fv_user_list = hw.get("filevault2_users",[]) or []
    fv_user_count = len(fv_user_list) if isinstance(fv_user_list, list) else 0
    if fv_on and fv_user_count == 1 and not bt_escrowed and bt_status:
        add("HIGH","INTELLIGENCE","FileVault single-user + no Bootstrap Token",
            f"Only one FileVault user ({fv_user_list[0] if fv_user_list else 'unknown'}) AND Bootstrap Token not escrowed. "
            "If this user forgets their password, the disk is permanently unrecoverable — "
            "MDM cannot help without the Bootstrap Token.",
            "Escrow BT immediately: have user log in → sudo profiles install -type bootstraptoken. "
            "Then verify in Jamf.", escalate=True)

    # 5. Chrome update pending
    chrome_update = eas.get("Update Chrome","") or ""
    if chrome_update and chrome_update.strip() not in ("","No","None","Up To Date","Current"):
        add("LOW","INTELLIGENCE",f"Chrome update pending: {chrome_update}",
            "Chrome is not current — known vulnerabilities may be present in older versions.",
            "Push Chrome Self Service update or scope the Chrome update policy to this device.")

    # 6. Protect connected recently BUT Jamf MDM stale
    #    Device is on network (Protect talks to cloud) but not talking to Jamf — MDM enrollment broken
    if (protect_data and protect_data.get("connection") == "Connected"
            and hours_stale and hours_stale > 168):
        add("HIGH","INTELLIGENCE","Protect online but MDM stale — enrollment likely broken",
            f"Jamf Protect is reporting as connected (device is online) but MDM last check-in was "
            f"{round(hours_stale/24,1)}d ago. The Mac is reachable but NOT talking to Jamf. "
            "This usually means the MDM profile was removed or enrollment broke.",
            "SSH/ConnectWise in and check: sudo profiles list | grep MDM. "
            "Re-enroll if MDM profile is missing. Escalate to Bob.", escalate=True)

    # 7. User mismatch — Jamf record vs last logged-in user
    last_login_ea = eas.get("Last User to login","") or ""
    jamf_username = (loc.get("username","") or gen.get("username","") or "").lower().strip()
    if (last_login_ea and jamf_username
            and "." in jamf_username  # format: first.last
            and last_login_ea.lower() not in (jamf_username, jamf_username.split(".")[0])):
        add("LOW","INTELLIGENCE","Last login user ≠ assigned user in Jamf",
            f"Jamf record shows '{jamf_username}' but last login was '{last_login_ea}'. "
            "Device may have been reassigned without updating the Jamf inventory record.",
            "Update Jamf location record to reflect current user, or confirm reassignment "
            "is intentional. Affects policy scoping by username.")

    # 8. Shared/lab device + single FileVault user
    #    If it's a shared device, having only 1 FV user locks everyone else out at boot
    name_lower = device_name.lower()
    is_shared = any(x in name_lower for x in ["cart","lab","shared","loaner","spare","kiosk","library","class"])
    if is_shared and fv_on and fv_user_count == 1:
        add("MEDIUM","INTELLIGENCE","Shared device with single FileVault user",
            f"Device name '{device_name}' suggests shared use, but only one FileVault user is enrolled. "
            "If that user's password is unknown at boot, no one can unlock the disk.",
            "Add institutional FileVault key (bootstrap token) or add a secondary admin FV user.")

    # 9. High exclusion groups + active policy failures — exclusions may be the cause
    exclusion_groups = [g for g in smart_groups if "exclude" in g.lower()]
    if exclusion_groups and fail_counts:
        # Check if any exclusion group name overlaps with failing policy names
        failing_keywords = set()
        for name in fail_counts:
            failing_keywords.update(name.lower().split())
        overlap = [g for g in exclusion_groups
                   if any(kw in g.lower() for kw in failing_keywords if len(kw) > 4)]
        if overlap:
            add("MEDIUM","INTELLIGENCE","Exclusion groups may be blocking failing policies",
                f"Device is in exclusion group(s) '{', '.join(overlap[:2])}' "
                f"which share keywords with failing policies. "
                "The exclusions may intentionally or accidentally be preventing those policies from running.",
                "Review whether exclusion group membership is intentional for the failing policies.")

    # 10. No policies EVER ran — newly enrolled or silently broken
    if gen_managed and len(policy_logs) == 0:
        add("HIGH","INTELLIGENCE","No policy history — enrollment may be incomplete",
            "This managed device has zero policy history. Either it was just enrolled and "
            "hasn't been scoped to any policies yet, or policy delivery is fundamentally broken.",
            "Check device smart group membership. Scope a test policy and run Blank Push Check-in. "
            "If still nothing runs, re-enroll.")

    # 11. Apple Silicon + Bootstrap Token = NOT_SUPPORTED
    #     Older Intel Macs set this — flag it so admins know MDM updates will require user interaction
    if bt_status == "NOT_SUPPORTED":
        add("MEDIUM","INTELLIGENCE","Bootstrap Token not supported on this hardware",
            "This Mac does not support Bootstrap Token escrow — it's likely older Intel hardware. "
            "SUPER silent MDM-triggered updates and remote FileVault recovery are not available.",
            "Ensure a local admin account exists for recovery. SUPER will require user interaction for updates.")

    # 12. Protect version significantly behind
    if protect_data and protect_data.get("version"):
        try:
            pv_parts = [int(x) for x in protect_data["version"].split(".")[:2]]
            if pv_parts[0] < 8:
                add("LOW","INTELLIGENCE",f"Jamf Protect version old: {protect_data['version']}",
                    "Running an older Protect agent — may miss newer threat detection capabilities.",
                    "Update Protect agent via Jamf policy.")
        except (ValueError, TypeError, IndexError):
            pass

    # 13. Very high profile count — scoping sprawl
    if len(profiles) > 30:
        add("LOW","INTELLIGENCE",f"High profile count: {len(profiles)} profiles",
            f"This device has {len(profiles)} config profiles applied — above the typical range. "
            "Too many profiles can cause conflicts, slow login, and make troubleshooting difficult.",
            "Review profile scoping in Jamf. Look for redundant or overlapping profiles.")

    # 14. SUPER non-compliant + duplicate SUPER profiles — profiles ARE the cause
    super_profiles = [n for n in profile_names if "super" in n.lower()]
    if len(super_profiles) > 1 and super_compliant and "non" in super_compliant.lower():
        add("HIGH","INTELLIGENCE","Duplicate SUPER profiles causing non-compliance",
            f"Device has {len(super_profiles)} SUPER profiles AND is SUPER non-compliant. "
            "Competing SUPER configurations almost certainly explain the non-compliance — "
            "conflicting settings can prevent SUPER from running correctly.",
            "Remove duplicate SUPER profiles first, then re-check SUPER compliance. "
            "Keep only the correct scoped profile.")

    # 15. MDM stale + Protect also offline = device physically gone or network dead
    if (hours_stale and hours_stale > 336  # 14 days MDM stale
            and protect_data and (protect_data.get("hours_offline") or 0) > 72):
        add("HIGH","INTELLIGENCE","Device unreachable via MDM and Protect",
            f"Both Jamf MDM (stale {round(hours_stale/24)}d) and Jamf Protect "
            f"(offline {round((protect_data['hours_offline'] or 0)/24,1)}d) show the device as unreachable. "
            "Device may be powered off, physically removed from network, or lost.",
            "Locate device physically. If lost/stolen, escalate to Bob for remote lock/wipe.",
            escalate=True)

    # ── Step 3: AI summary ────────────────────────────────────────
    device_info = (f"{device_name} | {hw.get('model','?')} | "
                   f"macOS {hw.get('os_version','?')} | "
                   f"{'Apple Silicon' if apple_silicon else 'Intel'} | "
                   f"Site: {gen.get('site',{}).get('name','?') if isinstance(gen.get('site'),dict) else '?'} | "
                   f"Dept: {department or 'None'} | "
                   f"User: {username or 'Unassigned'}")

    high_issues   = [i for i in issues if i["severity"]=="HIGH"]
    medium_issues = [i for i in issues if i["severity"]=="MEDIUM"]
    low_issues    = [i for i in issues if i["severity"]=="LOW"]
    escalate_flag = any(i.get("escalate") for i in issues)

    issues_text = "\n".join(
        f"[{i['severity']}][{i['category']}] {i['title']}: {i['detail']}"
        for i in issues
    ) if issues else "No issues detected."

    ai_prompt = f"""You are an expert Mac admin and Jamf Pro specialist for Three Rivers School District (TRSD), Oregon.
TRSD environment: ~963 Macs, Jamf Pro MDM, Jamf Connect v3.14 (IdP auth), SUPER for macOS updates, 
ConnectWise Control for remote, Jamf Protect endpoint security, Apple Silicon fleet transitioning from Intel.
Bootstrap Token is critical for Apple Silicon — required for SUPER silent updates and FileVault key rotation.

DEVICE: {device_info}
Serial: {serial}
Stale: {f"{round(hours_stale/24,1)} days" if hours_stale else "Unknown"}
FileVault: {"ON" if fv_on else "OFF"} | Bootstrap Token: {bt_status or "Unknown"}
SIP: {sip or "Unknown"} | Managed: {gen_managed}
SUPER: compliant={super_compliant or "?"} status={super_status or "?"} last_run={super_days_since and f"{round(super_days_since)}d ago" or super_last_run or "unknown"} deferrals={super_deferrals}
Jamf Connect: version={jc_version or "not installed"} users={jc_users or "0"}
Config profiles: {len(profiles)} | Smart groups: {len(smart_groups)} | Policy log entries: {len(policy_logs)}
Protect: {f"connected={protect_data.get('connection')} offline={protect_data.get('hours_offline')}h insights_fail={protect_data.get('insights_fail')} open_alerts={len(protect_data.get('open_alerts',[]))}" if protect_data else "unavailable"}

DETECTED ISSUES ({len(high_issues)} HIGH · {len(medium_issues)} MEDIUM · {len(low_issues)} LOW):
{issues_text}

Write a sharp technical analysis for a field tech. Structure your response EXACTLY as:

DIAGNOSIS: [2-3 sentences — what is actually wrong and why, identifying root cause not just symptoms. Call out any cross-correlations that make issues worse in combination.]

ACTIONS:
1. [Most urgent action — be specific, include exact commands or Jamf steps]
2. [Next action]
3. [Next action]
(up to 5 actions max — only include what's actually needed)

{"ESCALATE TO BOB: [One sentence — what needs admin-level attention and why]" if escalate_flag else ""}

Keep it concise and field-ready. A tech reading this should know exactly what to do next."""

    ai_summary = "Analysis complete — see issues above."
    if ANTHROPIC_KEY:
        try:
            ai_resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key":ANTHROPIC_KEY,"anthropic-version":"2023-06-01","content-type":"application/json"},
                json={"model":"claude-haiku-4-5-20251001","max_tokens":500,
                      "messages":[{"role":"user","content":ai_prompt}]},
                timeout=25,
            )
            if ai_resp.ok:
                ai_summary = ai_resp.json().get("content",[{}])[0].get("text","Analysis complete.")
        except Exception as e:
            log.warning("AI summary failed: %s", e)

    # ── Step 4: Return results ────────────────────────────────────
    high   = [i for i in issues if i["severity"] == "HIGH"]
    medium = [i for i in issues if i["severity"] == "MEDIUM"]
    low    = [i for i in issues if i["severity"] == "LOW"]
    return jsonify({
        "serial":        serial,
        "device_name":   device_name,
        "model":         hw.get("model","?"),
        "os_version":    hw.get("os_version","?"),
        "site":          gen.get("site",{}).get("name","?") if isinstance(gen.get("site"),dict) else "?",
        "profile_count": len(profiles),
        "group_count":   len(smart_groups),
        "policy_count":  len(policy_logs),
        "issues":        issues,
        "high_count":    len(high),
        "medium_count":  len(medium),
        "low_count":     len(low),
        "ai_summary":    ai_summary,
        "profiles":      [{"name":p.get("displayName",""),"id":p.get("id"),"installed":p.get("lastInstalled")} for p in profiles],
        "smart_groups":  smart_groups,
        "pending_mdm":   len(pending_all),
        "protect":       protect_data,
    })

@app.route("/api/fleet/warm", methods=["POST"])
@require_auth
def fleet_warm():
    """Silently pre-warm the fleet cache in background. Returns immediately."""
    if not _fleet_cache["data"]:
        import threading
        threading.Thread(target=fetch_fleet, daemon=True).start()
        return jsonify({"warming": True})
    return jsonify({"warming": False, "cached": True})

@app.route("/api/fleet/sites")
@require_auth
def fleet_sites():
    devices = fetch_fleet()
    sites   = sorted(set((d.get("general",{}).get("site") or {}).get("name","") for d in devices) - {""})
    return jsonify({"sites": sites})

@app.route("/api/fleet/query")
@require_auth
def fleet_query():
    query = request.args.get("q","").strip().lower()
    force = request.args.get("refresh","false").lower() == "true"
    if not query: return jsonify({"error": "Missing ?q="}), 400
    devices   = fetch_fleet(force=force)
    summaries = [fleet_device_summary(d) for d in devices]
    queries = {
        "stale_7":           (lambda d: d["hours_since"] is not None and d["hours_since"] > 168,  "Not checked in > 7 days"),
        "stale_14":          (lambda d: d["hours_since"] is not None and d["hours_since"] > 336,  "Not checked in > 14 days"),
        "stale_30":          (lambda d: d["hours_since"] is not None and d["hours_since"] > 720,  "Not checked in > 30 days"),
        "filevault_off":     (lambda d: not d["filevault"],                                        "FileVault disabled"),
        "unmanaged":         (lambda d: not d["managed"],                                          "Not managed by Jamf"),
        "super_noncompliant":(lambda d: d["super_compliant"] and "non" in d["super_compliant"].lower(), "SUPER non-compliant"),
        "jc_no_users":       (lambda d: d.get("jc_users","") in ("","0"), "Jamf Connect — no users authenticated"),
        "all":               (lambda d: True,                                                      "All devices"),
    }
    if query == "protect_offline":
        # Special case — pull from Protect API directly
        try:
            ps = protect_gql("""query { listComputers(input: {pageSize:200, filter:{connectionStatus:{equals:"Disconnected"}}}) {
                items { hostName serial lastConnection version } pageInfo { total } } }""")
            items = ps.get("data",{}).get("listComputers",{}).get("items",[])
            now2  = datetime.now(timezone.utc)
            results = []
            for d in items:
                lc = d.get("lastConnection")
                if lc:
                    try:
                        dt = datetime.fromisoformat(lc.replace("Z","+00:00"))
                        h  = round((now2-dt).total_seconds()/3600,1)
                        if h > 24:
                            results.append({"name":d.get("hostName","?"),"serial":d.get("serial",""),"hours_since":h,"site":"","username":"","jc_version":""})
                    except Exception:
                        pass
            results.sort(key=lambda x: x["hours_since"], reverse=True)
            cache_age = round((time.time()-_fleet_cache["fetched_at"])/60,1) if _fleet_cache["fetched_at"] else None
            return jsonify({"query":query,"label":"Protect offline >24h","count":len(results),"total_fleet":len(items),"cache_age_minutes":cache_age,"results":results})
        except Exception as e:
            return jsonify({"error": f"Protect query failed: {e}"}), 500
    if query == "protect_alerts":
        try:
            pa = protect_gql("""query { listAlerts(input:{pageSize:100,filter:{status:{equals:"Open"}}}) {
                items { id severity eventType created computer { hostName serial } } pageInfo { total } } }""")
            alerts = pa.get("data",{}).get("listAlerts",{}).get("items",[])
            total  = pa.get("data",{}).get("listAlerts",{}).get("pageInfo",{}).get("total",0)
            results = [{"name":a["computer"].get("hostName","?"),"serial":a["computer"].get("serial",""),
                        "hours_since":None,"site":"","username":"",
                        "alert_severity":a.get("severity"),"alert_type":a.get("eventType")} for a in alerts]
            return jsonify({"query":query,"label":f"Open Protect alerts ({total} total)","count":len(results),"total_fleet":total,"cache_age_minutes":None,"results":results})
        except Exception as e:
            return jsonify({"error": f"Protect alerts query failed: {e}"}), 500
    if query.startswith("site:"):
        site_name = query[5:].strip()
        results, label = [d for d in summaries if d["site"].lower() == site_name.lower()], f"Site: {site_name}"
    elif query in queries:
        fn, label = queries[query]
        results = [d for d in summaries if fn(d)]
    else:
        return jsonify({"error": f"Unknown query: {query}"}), 400
    results.sort(key=lambda x: x["hours_since"] or 0, reverse=True)
    cache_age = round((time.time() - _fleet_cache["fetched_at"]) / 60, 1) if _fleet_cache["fetched_at"] else None
    return jsonify({"query": query, "label": label, "count": len(results), "total_fleet": len(summaries), "cache_age_minutes": cache_age, "results": results})

# ── Handoff Log ───────────────────────────────────────────────────
def read_log():
    if not LOG_FILE.exists(): return []
    try: return json.loads(LOG_FILE.read_text())
    except: return []

def write_log(entries):
    LOG_FILE.write_text(json.dumps(entries, indent=2))

@app.route("/api/log")
@require_auth
def get_log():
    entries = read_log()
    device  = request.args.get("device","").strip().upper()
    if device:
        entries = [e for e in entries if e.get("device") and device in str(e.get("device","")).upper()]
    return jsonify({"entries": entries})

@app.route("/api/log", methods=["POST"])
@require_auth
def add_log():
    payload = request.get_json(force=True, silent=True) or {}
    text    = payload.get("text","").strip()
    if not text: return jsonify({"error": "No text"}), 400
    entry   = {"tech": request.user["display_name"], "text": text, "ts": payload.get("ts", int(time.time()*1000)), "device": payload.get("device")}
    entries = read_log()
    entries.append(entry)
    write_log(entries)
    return jsonify({"success": True, "entry": entry})

@app.route("/api/log/<int:index>", methods=["DELETE"])
@require_auth
def delete_log(index):
    entries = read_log()
    if index < 0 or index >= len(entries): return jsonify({"error": "Invalid index"}), 404
    entries.pop(index)
    write_log(entries)
    return jsonify({"success": True})

@app.route("/api/log/<int:index>", methods=["PATCH"])
@require_auth
def edit_log(index):
    entries = read_log()
    if index < 0 or index >= len(entries): return jsonify({"error": "Invalid index"}), 404
    text = (request.get_json(force=True, silent=True) or {}).get("text","").strip()
    if not text: return jsonify({"error": "No text"}), 400
    entries[index]["text"]   = text
    entries[index]["edited"] = True
    write_log(entries)
    return jsonify({"success": True, "entry": entries[index]})

# ── Escalate ──────────────────────────────────────────────────────
@app.route("/api/escalate", methods=["POST"])
@require_auth
def escalate_to_slack():
    webhook = os.environ.get("SLACK_WEBHOOK_URL","")
    if not webhook: return jsonify({"error": "SLACK_WEBHOOK_URL not set"}), 503
    payload = request.get_json(force=True, silent=True) or {}
    # Accept both 'text' and 'message' keys for compatibility
    text = payload.get("text","") or payload.get("message","")
    if not text: return jsonify({"error": "No text"}), 400
    try:
        resp = requests.post(webhook, json={"text": text}, timeout=10)
        return jsonify({"success": resp.status_code == 200})
    except requests.exceptions.RequestException as e:
        log.error("Slack webhook failed: %s", e)
        return jsonify({"success": False, "error": str(e)}), 502

@app.route("/api/config/client")
@require_auth
def client_config():
    return jsonify({"connectwise_url": CONNECTWISE_URL, "jamf_url": JAMF_URL})

@app.route("/api/device/<serial>/email", methods=["POST"])
@require_auth
def send_device_email(serial):
    serial  = serial.upper().strip()
    payload = request.get_json(force=True, silent=True) or {}
    to      = payload.get("to","").strip()
    subject = payload.get("subject","").strip()
    body    = payload.get("body","").strip()
    if not to or not subject or not body:
        return jsonify({"error": "Missing to/subject/body"}), 400
    import urllib.parse
    mailto = f"mailto:{urllib.parse.quote(to)}?subject={urllib.parse.quote(subject)}&body={urllib.parse.quote(body)}"
    write_audit("EMAIL_COMPOSED", request.user["display_name"], f"Email to {to} re: {serial}", request.remote_addr)
    return jsonify({"success": True, "method": "mailto", "mailto": mailto})

@app.errorhandler(500)
def handle_500(e):
    log.error("Server error: %s", e, exc_info=True)
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    port    = int(os.environ.get("ARIA_PORT", 5001))
    cert    = BASE_DIR / "aria-cert.pem"
    key     = BASE_DIR / "aria-key.pem"
    ssl_ctx = (str(cert), str(key)) if cert.exists() and key.exists() else None
    log.info("ARIA starting on port %d (%s)", port, "HTTPS" if ssl_ctx else "HTTP")

    # Pre-warm fleet cache at startup in background
    import threading
    def startup_warm():
        try:
            time.sleep(3)  # Let Flask fully start first
            fetch_fleet()
            log.info("Startup fleet pre-warm complete")
        except Exception as e:
            log.warning("Startup fleet pre-warm failed: %s", e)
    threading.Thread(target=startup_warm, daemon=True).start()

    app.run(host="0.0.0.0", port=port, debug=False, ssl_context=ssl_ctx)
