"""
ARIA Backend Server
Runs on your Mac as a LaunchAgent on port 5001 (HTTPS).
"""

import os, time, logging, json, secrets
from functools import wraps
from datetime import datetime, timezone, timedelta
from pathlib import Path

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
    return resp.json()["computer"]["general"]["id"]

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
    return jsonify(resp.json()), resp.status_code

# ── Device ────────────────────────────────────────────────────────
@app.route("/api/device/<serial>")
@require_auth
def get_device(serial):
    serial = serial.upper().strip()
    log.info("Device lookup: %s by %s", serial, request.user.get("sub","?"))
    resp = requests.get(f"{JAMF_URL}/JSSResource/computers/serialnumber/{serial}", headers=jamf_headers(), timeout=10)
    if resp.status_code == 404:
        return jsonify({"error": f"Device not found: {serial}"}), 404
    resp.raise_for_status()
    c   = resp.json()["computer"]
    gen = c.get("general", {})
    hw  = c.get("hardware", {})
    loc = c.get("location", {})
    raw_ea  = c.get("extension_attributes", {})
    ea_list = raw_ea if isinstance(raw_ea, list) else raw_ea.get("extension_attribute", [])
    if isinstance(ea_list, dict): ea_list = [ea_list]
    ext      = {ea["name"]: ea.get("value") for ea in ea_list if isinstance(ea, dict)}
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
    log.info("User lookup: %s by %s", username, request.user.get("sub","?"))
    resp = requests.get(f"{JAMF_URL}/JSSResource/computers", headers=jamf_headers(), timeout=15)
    resp.raise_for_status()
    matches = [c for c in resp.json().get("computers", []) if (c.get("username") or "").lower() == username.lower()]
    return jsonify({"username": username, "devices": matches})

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
        raise

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
        raise

# ── Policies ──────────────────────────────────────────────────────
@app.route("/api/device/<serial>/policies")
@require_auth
def get_device_policies(serial):
    serial = serial.upper().strip()
    cid    = get_computer_id(serial)
    if not cid: return jsonify({"error": f"Device not found: {serial}"}), 404
    resp = requests.get(f"{JAMF_URL}/JSSResource/computerhistory/id/{cid}/subset/PolicyLogs", headers=jamf_headers(), timeout=10)
    resp.raise_for_status()
    ch   = resp.json().get("computer_history", {})
    pl   = ch.get("policy_logs", [])
    if isinstance(pl, dict): pl = pl.get("policy_log", [])
    if isinstance(pl, dict): pl = [pl]
    logs = sorted(pl if isinstance(pl, list) else [], key=lambda x: x.get("date_completed_epoch", 0), reverse=True)
    offset = int(request.args.get("offset", 0))
    limit  = int(request.args.get("limit", 15))
    return jsonify({"computer_id": cid, "policy_logs": logs[offset:offset+limit], "total": len(logs), "offset": offset, "limit": limit})

import threading as _threading
_fleet_cache = {"data": None, "fetched_at": 0}
_fleet_lock  = _threading.Lock()
FLEET_TTL    = 600

def fetch_fleet(force=False) -> list:
    now = time.time()
    if not force and _fleet_cache["data"] and now < _fleet_cache["fetched_at"] + FLEET_TTL:
        return _fleet_cache["data"]
    if not _fleet_lock.acquire(blocking=False):
        log.info("Fleet fetch already in progress, skipping duplicate")
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

    # ── Step 1: Gather all data ───────────────────────────────────
    # Classic API — base computer record
    resp = requests.get(f"{JAMF_URL}/JSSResource/computers/serialnumber/{serial}", headers=jamf_headers(), timeout=10)
    if resp.status_code == 404:
        return jsonify({"error": f"Device not found: {serial}"}), 404
    resp.raise_for_status()
    computer   = resp.json()["computer"]
    gen        = computer.get("general", {})
    hw         = computer.get("hardware", {})
    loc        = computer.get("location", {})
    cid        = gen.get("id")

    # v1 API — profiles, groups, security, EAs
    v1_resp = requests.get(
        f"{JAMF_URL}/api/v1/computers-inventory/{cid}?section=CONFIGURATION_PROFILES&section=GROUP_MEMBERSHIPS&section=SECURITY&section=EXTENSION_ATTRIBUTES&section=GENERAL",
        headers=jamf_headers(), timeout=15
    )
    v1 = v1_resp.json() if v1_resp.ok else {}
    profiles  = v1.get("configurationProfiles", [])
    groups    = v1.get("groupMemberships", [])
    security  = v1.get("security", {})
    eas_raw   = v1.get("extensionAttributes", [])
    eas       = {ea["name"]: (ea.get("values") or [""])[0] for ea in eas_raw}

    # Policy history
    ph_resp = requests.get(f"{JAMF_URL}/JSSResource/computerhistory/id/{cid}/subset/PolicyLogs", headers=jamf_headers(), timeout=10)
    ch = ph_resp.json().get("computer_history", {}) if ph_resp.ok else {}
    pl = ch.get("policy_logs", [])
    if isinstance(pl, dict): pl = pl.get("policy_log", [])
    if isinstance(pl, dict): pl = [pl]
    policy_logs = pl if isinstance(pl, list) else []

    # Pending MDM commands
    pending_resp = requests.get(f"{JAMF_URL}/JSSResource/computercommands/status/Pending", headers=jamf_headers(), timeout=10)
    pending_all  = []
    if pending_resp.ok:
        pc = pending_resp.json().get("computer_commands", {}).get("computer_command", [])
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

    def add(severity, category, title, detail, action=""):
        issues.append({"severity": severity, "category": category, "title": title, "detail": detail, "action": action})

    # --- Profile conflict checks ---
    profile_names = [p.get("displayName","") for p in profiles]

    # Duplicate SUPER profiles
    super_profiles = [n for n in profile_names if "super" in n.lower()]
    if len(super_profiles) > 1:
        add("HIGH","CONFLICT", f"Duplicate SUPER config profiles ({len(super_profiles)})",
            f"Multiple SUPER profiles applied: {', '.join(super_profiles)}",
            "Review profile scoping — only one SUPER config should apply to this device.")

    # Duplicate Jamf Connect profiles
    jc_profiles = [n for n in profile_names if "jamf connect" in n.lower() or "connect" in n.lower() and "jamf" in n.lower()]
    if len(jc_profiles) > 1:
        add("HIGH","CONFLICT", f"Duplicate Jamf Connect profiles ({len(jc_profiles)})",
            f"Multiple JC profiles: {', '.join(jc_profiles)}",
            "Remove duplicate Jamf Connect profiles — only one should be applied.")

    # Duplicate FileVault profiles
    fv_profiles = [n for n in profile_names if "filevault" in n.lower() or "fde" in n.lower() or "disk encrypt" in n.lower()]
    if len(fv_profiles) > 1:
        add("HIGH","CONFLICT", f"Duplicate FileVault profiles ({len(fv_profiles)})",
            f"Multiple FV profiles: {', '.join(fv_profiles)}",
            "Only one FileVault enforcement profile should be applied — review scope.")

    # Duplicate password/passcode profiles
    pw_profiles = [n for n in profile_names if "password" in n.lower() or "passcode" in n.lower()]
    if len(pw_profiles) > 1:
        add("MEDIUM","CONFLICT", f"Duplicate password policy profiles ({len(pw_profiles)})",
            f"Multiple password profiles: {', '.join(pw_profiles)}",
            "Conflicting password policies can cause unexpected lockouts — consolidate.")

    # --- Policy checks ---
    now_ms = __import__("time").time() * 1000
    days_30_ms = 30 * 24 * 3600 * 1000

    # Stale policies (scoped but not run in 30+ days)
    stale_policies = []
    for p in policy_logs:
        epoch = p.get("date_completed_epoch", 0) or 0
        if epoch and (now_ms - epoch) > days_30_ms:
            stale_policies.append(p.get("policy_name","Unknown"))
    if len(stale_policies) >= 3:
        add("LOW","POLICY", f"{len(stale_policies)} policies not run in 30+ days",
            f"Stale policies: {', '.join(stale_policies[:5])}{'...' if len(stale_policies)>5 else ''}",
            "Review why these policies haven't run — check scope, triggers, and device check-in.")

    # Repeated policy failures
    failures = {}
    for p in policy_logs:
        status = (p.get("status") or "").lower()
        if "fail" in status:
            name = p.get("policy_name","Unknown")
            failures[name] = failures.get(name, 0) + 1
    repeat_failures = {k:v for k,v in failures.items() if v >= 2}
    for name, count in list(repeat_failures.items())[:3]:
        add("HIGH","POLICY", f"Policy failing repeatedly: {name}",
            f"Failed {count} times in policy history.",
            "Check policy scope, package integrity, and script errors. Escalate to Bob if persists.")

    # Pending MDM commands
    if len(pending_all) > 0:
        add("MEDIUM","MDM", f"{len(pending_all)} MDM command(s) stuck in queue",
            f"Commands pending: {', '.join(set(c.get('name','?') for c in pending_all))}",
            "Flush MDM queue (BlankPush) and ensure device is online and checking in.")

    # --- Security checks ---
    fv_users = hw.get("filevault2_users", [])
    fv_on = hw.get("filevault2_enabled") is True or (isinstance(fv_users, list) and len(fv_users) > 0)
    if not fv_on:
        add("HIGH","SECURITY", "FileVault is NOT enabled",
            "This device has no FileVault users — disk is unencrypted.",
            "Push FileVault enforcement profile and ensure a user with Secure Token logs in.")

    # Guest account
    guest_ea = eas.get("OS - Guest Account Disabled","")
    if guest_ea and "fail" in guest_ea.lower():
        add("MEDIUM","SECURITY", "Guest account is enabled",
            "Guest account policy check failed — guest login may be active.",
            "Push guest account disable profile or run the guest account remediation policy.")

    # Jamf Protect
    protect_ea = eas.get("Jamf Protect - Smart Groups","")
    if not protect_ea or protect_ea in ("", "Does not exist", "Not Installed"):
        add("MEDIUM","SECURITY", "Jamf Protect not detected",
            "No Jamf Protect smart group membership found for this device.",
            "Check if Protect is deployed — re-push Protect installer via Jamf.")

    # SIP status
    sip = security.get("sipStatus","")
    if sip and sip != "ENABLED":
        add("HIGH","SECURITY", f"SIP is {sip}",
            "System Integrity Protection is not fully enabled on this device.",
            "SIP should always be enabled on managed Macs. Investigate how it was disabled.")

    # Gatekeeper
    gk = security.get("gatekeeperStatus","")
    if gk and gk not in ("APP_STORE_AND_IDENTIFIED_DEVELOPERS", "APP_STORE"):
        add("MEDIUM","SECURITY", f"Gatekeeper set to: {gk}",
            "Gatekeeper is not enforcing app signing — any software can run.",
            "Push Gatekeeper enforcement profile to restore security posture.")

    # Firewall
    fw = security.get("firewallEnabled")
    if fw is False:
        add("MEDIUM","SECURITY", "Firewall is disabled",
            "macOS firewall is turned off on this device.",
            "Push firewall enforcement profile.")

    # Secure Boot
    sb = security.get("secureBootLevel","")
    if sb and sb not in ("FULL_SECURITY", "MEDIUM_SECURITY"):
        add("LOW","SECURITY", f"Secure Boot level: {sb}",
            "Device is not using Full or Medium Secure Boot.",
            "Review if this is intentional — Full Security is recommended for managed Macs.")

    # Bootstrap Token
    bt = security.get("bootstrapTokenEscrowedStatus","")
    if bt and bt not in ("ESCROWED",):
        add("MEDIUM","SECURITY", "Bootstrap Token not escrowed",
            f"Bootstrap Token status: {bt}. Required for MDM-driven FileVault and software updates.",
            "Have user log in, then run sudo profiles install -type bootstraptoken.")

    # SUPER compliance
    super_compliant = eas.get("SUPER Compliant","")
    if super_compliant and "non" in super_compliant.lower():
        add("MEDIUM","POLICY", "SUPER reports non-compliant",
            f"SUPER Compliant EA: {super_compliant}",
            "Check SUPER status EA, last run date, and deadline settings.")

    # Smart group anomalies
    smart_groups = [g["groupName"] for g in groups if g.get("smartGroup")]
    exclusion_groups = [g for g in smart_groups if "exclude" in g.lower()]
    if exclusion_groups:
        add("LOW","SCOPE", f"Device in {len(exclusion_groups)} exclusion group(s)",
            f"Exclusion groups: {', '.join(exclusion_groups[:3])}",
            "Verify exclusions are intentional — may explain why policies or profiles aren't applying.")

    # --- Jamf Protect checks ---
    if protect_data:
        # Open threat alerts
        if protect_data["open_alerts"]:
            for alert in protect_data["open_alerts"][:3]:
                sev = alert.get("severity","?")
                etype = alert.get("eventType","Unknown")
                aria_sev = "HIGH" if sev in ("High","Critical") else "MEDIUM"
                add(aria_sev, "PROTECT", f"Open threat alert: {etype}",
                    f"Severity: {sev} · Status: {alert.get('status','?')} · Created: {alert.get('created','?')[:10]}",
                    "Review and resolve this alert in Jamf Protect. Escalate to Bob if High/Critical.")
        # Protect offline >24h
        if protect_data.get("hours_offline") and protect_data["hours_offline"] > 24:
            days = round(protect_data["hours_offline"] / 24, 1)
            add("MEDIUM", "PROTECT", f"Protect agent offline {days}d",
                f"Last connection: {protect_data.get('last_connection','?')[:10] if protect_data.get('last_connection') else 'unknown'}",
                "Verify Protect agent is running: sudo /usr/local/bin/jamf-protect check-in")
        # High insights failures
        fail = protect_data.get("insights_fail", 0)
        if fail and fail > 5:
            add("LOW", "PROTECT", f"{fail} Protect insight checks failing",
                f"Pass: {protect_data.get('insights_pass',0)} · Fail: {fail}",
                "Review failing insights in Jamf Protect console for this device.")
    elif PROTECT_URL:
        add("LOW", "PROTECT", "Device not found in Jamf Protect",
            "This device does not appear in Protect. It may not have the agent installed.",
            "Push Protect agent via Jamf policy if this device should be protected.")

    # ── Step 3: AI summary ────────────────────────────────────────
    device_info = f"{gen.get('name','?')} ({hw.get('model','?')}, macOS {hw.get('os_version','?')}, {gen.get('site',{}).get('name','?') if isinstance(gen.get('site'),dict) else '?'})"

    if issues:
        issues_text = "\n".join([f"[{i['severity']}][{i['category']}] {i['title']}: {i['detail']}" for i in issues])
        ai_prompt = f"""You are an expert Jamf Pro administrator reviewing a conflict and security analysis for a managed Mac.

Device: {device_info}
Serial: {serial}
Config profiles applied: {len(profiles)}
Smart groups: {len(smart_groups)}
Policy log entries: {len(policy_logs)}

DETECTED ISSUES:
{issues_text}

Write a concise 3-5 sentence technical summary for a help desk ticket. Cover: what the main problems are, likely root causes, and the most important next steps. Be specific and direct — the reader is a Mac admin."""
    else:
        ai_prompt = f"""Device {device_info} (serial {serial}) passed all conflict and security checks. {len(profiles)} profiles applied, {len(smart_groups)} smart groups, no issues detected. Write one sentence confirming this device looks healthy."""

    ai_summary = "Analysis complete."
    if ANTHROPIC_KEY:
        try:
            ai_resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                json={"model": "claude-haiku-4-5-20251001", "max_tokens": 300, "messages": [{"role": "user", "content": ai_prompt}]},
                timeout=20,
            )
            if ai_resp.ok:
                ai_summary = ai_resp.json().get("content", [{}])[0].get("text", "Analysis complete.")
        except Exception as e:
            log.warning("AI summary failed: %s", e)

    # ── Step 4: Return results ────────────────────────────────────
    high   = [i for i in issues if i["severity"] == "HIGH"]
    medium = [i for i in issues if i["severity"] == "MEDIUM"]
    low    = [i for i in issues if i["severity"] == "LOW"]

    return jsonify({
        "serial":       serial,
        "device_name":  gen.get("name","?"),
        "model":        hw.get("model","?"),
        "os_version":   hw.get("os_version","?"),
        "site":         gen.get("site",{}).get("name","?") if isinstance(gen.get("site"),dict) else "?",
        "profile_count": len(profiles),
        "group_count":  len(smart_groups),
        "policy_count": len(policy_logs),
        "issues":       issues,
        "high_count":   len(high),
        "medium_count": len(medium),
        "low_count":    len(low),
        "ai_summary":   ai_summary,
        "profiles":     [{"name": p.get("displayName",""), "id": p.get("id"), "installed": p.get("lastInstalled")} for p in profiles],
        "smart_groups": smart_groups,
        "pending_mdm":  len(pending_all),
        "protect":      protect_data,
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
        "jc_missing":        (lambda d: not d["jc_version"] or d["jc_version"] in ("","Does not exist"), "Jamf Connect not installed"),
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
    text = (request.get_json(force=True, silent=True) or {}).get("text","")
    if not text: return jsonify({"error": "No text"}), 400
    resp = requests.post(webhook, json={"text": text}, timeout=10)
    return jsonify({"success": resp.status_code == 200})

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
