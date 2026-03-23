# Customizing ARIA for Your Environment

## System Prompt (`config/system_prompt.txt`)

This file controls everything ARIA knows about your environment. The more detail you add, the better the answers. Edit it to include:

**Identity / authentication:**
- What identity provider you use (Jamf Connect, LDAP, Azure AD, Google Workspace)
- How users log in and common auth issues you see

**macOS update management:**
- SUPER, Nudge, custom policy, or manual updates
- Your update schedule and deadline behavior

**Remote desktop:**
- ConnectWise Control, Apple Remote Desktop, Zoom IT, etc.
- How your techs initiate remote sessions

**Printers:**
- Makes and models deployed
- Print server setup (PaperCut, AirPrint, direct IP)
- Known printer issues

**Web filtering:**
- Securly, Cisco Umbrella, Lightspeed, etc.
- Known conflicts (e.g. Securly blocking local IPs)

**VPN:**
- Tailscale, Cisco AnyConnect, etc.
- When remote techs use it

**Common issues specific to your org:**
Add a "COMMON ISSUES" section with your most frequent problems and the steps that fix them.

## Extension Attributes (`config/extension_attributes.json`)

ARIA surfaces specific EA values in the device panel. Map the labels to your exact Jamf EA names.

If you don't use SUPER, remove the `super` section. If you use a different MDM client tool, add a new section for it.

**Example — adding a custom EA:**

```json
{
  "security": {
    "jamf_protect": "Jamf Protect - Smart Groups",
    "guest_account": "OS - Guest Account Disabled",
    "chrome_update": "Update Chrome",
    "my_custom_ea": "My Custom EA Name in Jamf"
  }
}
```

Then in `templates/index.html`, find the SECURITY section in `renderDeviceCard()` and add a line to surface your new EA.

## Tech Names (`TECH_NAMES` in .env)

Add every tech's name to the `TECH_NAMES` comma-separated list:

```env
TECH_NAMES=Alice Smith,Bob Jones,Carol Williams,Dave Brown
```

These populate the name dropdown on the setup screen.

## Background Image (`static/bg.jpg`)

Drop any JPEG into `static/bg.jpg` to use it as the setup screen background. ARIA darkens and overlays it automatically. Recommended dimensions: 1600×1200 or larger. Landscape orientation works best.

## Port (`ARIA_PORT` in .env)

Default is `5001`. Change if that port is in use:

```env
ARIA_PORT=5002
```

## Hostname

To access ARIA at a friendly hostname like `aria.local` instead of an IP:

```bash
sudo scutil --set LocalHostName aria
```

Make sure your SSL certificate includes this hostname as a Subject Alternative Name (handled automatically by `setup.py` if you enter it during setup).
