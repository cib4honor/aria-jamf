#!/usr/bin/env python3
"""
ARIA Setup Script
Generates SSL certificate and optionally installs a LaunchAgent for auto-start.
"""

import os, sys, subprocess, argparse, secrets
from pathlib import Path

BASE_DIR = Path(__file__).parent

def generate_ssl_cert():
    cert = BASE_DIR / "aria-cert.pem"
    key  = BASE_DIR / "aria-key.pem"
    if cert.exists() and key.exists():
        print("✓ SSL certificate already exists — skipping generation")
        return
    print("Generating self-signed SSL certificate...")
    hostname = input("Enter your server hostname [aria.local]: ").strip() or "aria.local"
    ip = input("Enter your server IP address [127.0.0.1]: ").strip() or "127.0.0.1"
    san = f"DNS:{hostname},DNS:localhost,IP:{ip},IP:127.0.0.1"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(key), "-out", str(cert),
        "-days", "3650", "-nodes",
        "-subj", f"/CN={hostname}",
        "-addext", f"subjectAltName={san}"
    ], check=True)
    print(f"\n✓ Certificate generated: {cert}")
    print(f"✓ Private key generated:  {key}")
    print("\nTo trust this certificate on your Mac:")
    print("  1. Open Keychain Access")
    print(f"  2. Import: {cert}")
    print("  3. Set it to 'Always Trust'")
    print("\nTo distribute trust to managed Macs, deploy a config profile.")
    print("See docs/cert-profile.md for instructions.\n")

def generate_api_key():
    env_path = BASE_DIR / ".env"
    if not env_path.exists():
        print("No .env found — copying from .env.example")
        example = BASE_DIR / ".env.example"
        if example.exists():
            env_path.write_text(example.read_text())
    content = env_path.read_text()
    if "change-this-to-a-random-string" in content:
        new_key = secrets.token_hex(24)
        content = content.replace("change-this-to-a-random-string", new_key)
        env_path.write_text(content)
        print(f"✓ Generated ARIA_API_KEY: {new_key[:8]}...")

def install_launchagent():
    plist_path = Path.home() / "Library" / "LaunchAgents" / "com.aria.jamf.plist"
    python_path = BASE_DIR / "venv" / "bin" / "python3"
    if not python_path.exists():
        python_path = Path(sys.executable)
    log_path = Path.home() / "Library" / "Logs" / "aria_server.log"
    plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.aria.jamf</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python_path}</string>
        <string>{BASE_DIR / 'aria_server.py'}</string>
    </array>
    <key>WorkingDirectory</key><string>{BASE_DIR}</string>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>StandardOutPath</key><string>{log_path}</string>
    <key>StandardErrorPath</key><string>{log_path}</string>
</dict>
</plist>"""
    plist_path.write_text(plist_content)
    subprocess.run(["launchctl", "bootstrap", f"gui/{os.getuid()}", str(plist_path)])
    print(f"✓ LaunchAgent installed: {plist_path}")
    print("  ARIA will now start automatically at login.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ARIA Setup")
    parser.add_argument("--install-launchagent", action="store_true", help="Install LaunchAgent for auto-start")
    parser.add_argument("--cert-only", action="store_true", help="Only generate SSL certificate")
    args = parser.parse_args()

    print("\n═══ ARIA Setup ═══\n")
    generate_api_key()
    generate_ssl_cert()

    if args.install_launchagent:
        install_launchagent()

    print("\n✓ Setup complete!")
    print(f"  Start ARIA: python3 aria_server.py")
    print(f"  Then open:  https://localhost:{os.environ.get('ARIA_PORT', 5001)}\n")
