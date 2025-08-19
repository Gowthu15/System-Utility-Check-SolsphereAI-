#!/usr/bin/env python3
"""
Solsphere Agent (starter)
- Cross-platform (Windows / macOS / Linux) starter implementation.
- Run as admin/sudo for most accurate results.
- Usage:
    python main.py --once --output system_report.json
    python main.py --interval 900 --output system_report.json
    python main.py --once --output system_report.json --post-url https://your.server/ingest --auth-token TOKEN
"""

import os
import sys
import platform
import subprocess
import json
import socket
import uuid
import argparse
import logging
import time
import re

try:
    import requests
except Exception:
    requests = None

# ---------- Logging ----------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ---------- Helpers ----------
def run_cmd(cmd, timeout=20, shell=False):
    """
    Run a command (list or string). Returns (returncode, stdout, stderr).
    Prefer list for Windows commands; for complex shell commands use shell=True.
    """
    try:
        if isinstance(cmd, (list, tuple)):
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        else:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=shell)
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except subprocess.TimeoutExpired:
        return 1, "", "timeout"
    except Exception as e:
        return 1, "", str(e)

def machine_id():
    """Create a reasonably-stable machine id using hostname + mac address hex."""
    hn = socket.gethostname()
    mac = uuid.getnode()
    mac_hex = format(mac, '012x')
    return f"{hn}-{mac_hex[-6:]}"

# ---------- Checks: Windows ----------
def check_disk_encryption_windows():
    """Check BitLocker (Windows). Uses manage-bde -status C:"""
    rc, out, err = run_cmd(["manage-bde", "-status", "C:"])
    if rc == 0 and out:
        # Try to parse Protection Status or Percentage Encrypted
        prot = re.search(r'Protection Status:\s*(.+)', out, flags=re.IGNORECASE)
        perc = re.search(r'Percentage Encrypted:\s*(\d+)%', out, flags=re.IGNORECASE)
        if prot and 'on' in prot.group(1).lower():
            return {"status": True, "detail": prot.group(1).strip()}
        if perc and int(perc.group(1)) >= 100:
            return {"status": True, "detail": f"{perc.group(1)}% encrypted"}
        return {"status": False, "detail": out}
    return {"status": None, "detail": err or "manage-bde not available or requires admin"}

def check_av_windows():
    """Check Windows Security Center for installed AV products via PowerShell"""
    ps = r"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct | Select-Object displayName,productState | ConvertTo-Json"
    rc, out, err = run_cmd(["powershell", "-NoProfile", "-Command", ps])
    if rc == 0 and out:
        try:
            data = json.loads(out)
            names = []
            if isinstance(data, list):
                for d in data:
                    n = d.get("displayName")
                    if n:
                        names.append(n)
            elif isinstance(data, dict):
                n = data.get("displayName")
                if n:
                    names.append(n)
            if names:
                return {"status": True, "products": names}
            return {"status": False, "detail": "No AV entries from SecurityCenter2"}
        except Exception:
            return {"status": True, "detail": out}
    return {"status": None, "detail": err or "PowerShell/WMI query failed (admin?)"}

def check_os_updates_windows():
    """Check if Windows updates are available using Update COM API (best-effort)."""
    ps = r"""
$session = New-Object -ComObject Microsoft.Update.Session;
$searcher = $session.CreateUpdateSearcher();
$results = $searcher.Search("IsInstalled=0 and IsHidden=0");
$out = [PSCustomObject]@{Count = $results.Updates.Count; Titles = $results.Updates | ForEach-Object { $_.Title }};
$out | ConvertTo-Json -Depth 3
"""
    rc, out, err = run_cmd(["powershell", "-NoProfile", "-Command", ps])
    if rc == 0 and out:
        try:
            data = json.loads(out)
            count = data.get("Count", 0) if isinstance(data, dict) else 0
            titles = data.get("Titles") if isinstance(data, dict) else None
            return {"status": "updates_available" if count and int(count) > 0 else "up_to_date", "count": int(count) if count is not None else 0, "titles": titles}
        except Exception:
            # fallback - return raw
            return {"status": "unknown", "detail": out}
    return {"status": None, "detail": err or "Update query failed (admin?)"}

def check_sleep_windows():
    """
    Best-effort: parse 'powercfg /q' output for numeric values that look like timeouts.
    This is a heuristic; for robust enterprise use you'd parse specific GUIDs.
    """
    rc, out, err = run_cmd(["powercfg", "/q"])
    if rc != 0:
        return {"status": None, "detail": err or "powercfg not available"}
    # Find any decimal/hex numbers that could be timeouts (heuristic)
    # powercfg prints indexes in hex like 0x0000003c (60)
    hex_matches = re.findall(r'0x([0-9a-fA-F]+)', out)
    cand = []
    for h in hex_matches:
        try:
            val = int(h, 16)
            if 0 < val <= 86400:  # up to 1 day in seconds
                cand.append(val)
        except:
            pass
    if cand:
        # convert to minutes and pick a small reasonable one
        minutes = sorted(set([int(v/60) for v in cand if v >= 60]))  # show minute values
        if minutes:
            return {"status": minutes[0], "detail": f"Detected candidate sleep timeout (minutes): {minutes}"}
    # direct decimal numbers
    nums = re.findall(r'\b(\d{1,5})\b', out)
    for n in nums:
        v = int(n)
        if 0 < v <= 1440:  # minutes possibly
            return {"status": v, "detail": "Detected numeric candidate (may be minutes)"}
    return {"status": None, "detail": "Could not reliably parse sleep timeout (requires admin parsing of GUIDs)"}

# ---------- Checks: macOS ----------
def check_disk_encryption_macos():
    rc, out, err = run_cmd(["fdesetup", "status"])
    if rc == 0 and out:
        if "On" in out:
            return {"status": True, "detail": out.strip()}
        return {"status": False, "detail": out.strip()}
    return {"status": None, "detail": err or "fdesetup not available (requires admin/root or FileVault unsupported)"}

def check_os_updates_macos():
    # softwareupdate -l outputs "No new software available." when up-to-date
    rc, out, err = run_cmd(["softwareupdate", "-l"], shell=False)
    combined = (out or "") + ("\n" + err if err else "")
    if rc == 0 and ("No new software available." in combined):
        return {"status": "up_to_date", "detail": "No new software available"}
    # If rc==0 but output lists items -> updates available
    if "softwareupdate found the following" in combined.lower() or "recommended" in combined.lower() or " - " in combined:
        return {"status": "updates_available", "detail": combined.strip()}
    if rc != 0 and combined:
        # sometimes softwareupdate needs sudo; return message
        return {"status": None, "detail": combined.strip()}
    # fallback
    return {"status": "unknown", "detail": combined.strip()}

def check_av_unix():
    """
    macOS / Linux: look for common AV processes (best-effort).
    """
    rc, out, err = run_cmd(["ps", "aux"], timeout=10)
    if rc != 0:
        return {"status": None, "detail": err or "ps failed"}
    out = out.lower()
    known = ["clamd", "clamav", "sophos", "norton", "mcafee", "crowdstrike", "sentinel", "kaspersky", "avast", "avira", "bitdefender"]
    found = [name for name in known if name in out]
    if found:
        return {"status": True, "products": found}
    return {"status": False, "detail": "No common AV processes detected"}

def check_sleep_macos():
    rc, out, err = run_cmd(["pmset", "-g"], shell=False)
    if rc != 0:
        return {"status": None, "detail": err or "pmset error (may need sudo)"}
    # look for ' sleep <num>' or ' sleep <num>' line
    m = re.search(r'\s+sleep\s+(\d+)', out)
    if m:
        mins = int(m.group(1))
        return {"status": mins, "detail": "system sleep (minutes)"}
    # look for 'disksleep' 'displaysleep' etc.
    m2 = re.search(r'displaysleep:\s*(\d+)', out)
    if m2:
        return {"status": int(m2.group(1)), "detail": "display sleep (minutes)"}
    return {"status": None, "detail": "Could not parse pmset output"}

# ---------- Checks: Linux ----------
def check_disk_encryption_linux():
    # look for LUKS in lsblk output
    rc, out, err = run_cmd(["lsblk", "-o", "NAME,FSTYPE,MOUNTPOINT"], timeout=8)
    if rc == 0 and out:
        if "crypto_LUKS" in out or "LUKS" in out.upper():
            return {"status": True, "detail": "LUKS/cryptsetup detected in lsblk"}
        return {"status": False, "detail": "No LUKS entries in lsblk"}
    return {"status": None, "detail": err or "lsblk not available"}

def check_os_updates_linux():
    # Try apt, dnf, zypper, pacman - best-effort
    # Debian/Ubuntu:
    rc, out, err = run_cmd(["bash", "-lc", "which apt >/dev/null && apt list --upgradable 2>/dev/null | sed -n '2,$p' || true"], shell=True)
    if rc == 0 and out:
        out = out.strip()
        if out:
            return {"status": "updates_available", "detail": out.splitlines()[:10]}
        else:
            return {"status": "up_to_date"}
    # dnf/yum
    rc, out, err = run_cmd(["bash", "-lc", "which dnf >/dev/null && dnf check-update 2>/dev/null || true"], shell=True)
    if rc == 0 and out and "No packages marked for update" not in out:
        return {"status": "updates_available", "detail": out.splitlines()[:10]}
    return {"status": "unknown", "detail": "Could not determine package manager (try running with sudo)"}

def check_sleep_linux():
    # try gsettings (GNOME)
    rc, out, err = run_cmd(["bash", "-lc", "which gsettings >/dev/null && gsettings get org.gnome.settings-daemon.plugins.power sleep-inactive-ac-timeout || true"], shell=True)
    if rc == 0 and out and out.strip() and out.strip() != "uint32 0":
        try:
            val = int(re.sub(r'\D','', out))
            return {"status": int(val/60) if val > 60 else val, "detail": "gsettings value (seconds -> minutes)"}
        except:
            pass
    # systemd logind IdleActionSec
    try:
        if os.path.exists("/etc/systemd/logind.conf"):
            with open("/etc/systemd/logind.conf","r") as f:
                txt = f.read()
            m = re.search(r'IdleActionSec\s*=\s*([0-9]+)s', txt)
            if m:
                v = int(m.group(1))
                return {"status": int(v/60), "detail": "IdleActionSec from logind.conf"}
    except Exception:
        pass
    return {"status": None, "detail": "Could not determine (desktop env dependent)"}

# ---------- Collector ----------
def collect():
    info = {
        "machineId": machine_id(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "agentVersion": "0.1.0",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    }
    sysname = platform.system().lower()
    if "windows" in sysname:
        info["diskEncryption"] = check_disk_encryption_windows()
        info["osUpdate"] = check_os_updates_windows()
        info["antivirus"] = check_av_windows()
        info["sleepTimeout"] = check_sleep_windows()
    elif "darwin" in sysname or "mac" in sysname:
        info["diskEncryption"] = check_disk_encryption_macos()
        info["osUpdate"] = check_os_updates_macos()
        info["antivirus"] = check_av_unix()
        info["sleepTimeout"] = check_sleep_macos()
    else:  # assume linux / unix
        info["diskEncryption"] = check_disk_encryption_linux()
        info["osUpdate"] = check_os_updates_linux()
        info["antivirus"] = check_av_unix()
        info["sleepTimeout"] = check_sleep_linux()
    return info

# ---------- Persistence & send ----------
def save_report(report, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

def load_last(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return None

def reports_differ(a, b):
    # Simple difference check ignoring timestamp
    if a is None or b is None:
        return True
    a2 = dict(a)
    b2 = dict(b)
    a2.pop("timestamp", None)
    b2.pop("timestamp", None)
    return json.dumps(a2, sort_keys=True) != json.dumps(b2, sort_keys=True)

def post_report(report, url, token=None):
    if requests is None:
        return {"ok": False, "detail": "requests library not installed"}
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        r = requests.post(url, json=report, headers=headers, timeout=15, verify=True)
        return {"ok": r.ok, "status_code": r.status_code, "text": r.text}
    except Exception as e:
        return {"ok": False, "detail": str(e)}

# ---------- CLI ----------
def parse_args():
    p = argparse.ArgumentParser(description="Solsphere System Utility (starter)")
    p.add_argument("--once", action="store_true", help="Run once and exit")
    p.add_argument("--interval", type=int, default=900, help="Run interval in seconds (default 900)")
    p.add_argument("--output", type=str, default="system_report.json", help="Output JSON file path")
    p.add_argument("--last-file", type=str, default=".last_report.json", help="Path to store last report for change detection")
    p.add_argument("--post-url", type=str, help="Optional: POST URL to send reports")
    p.add_argument("--auth-token", type=str, help="Optional: auth token for POST")
    return p.parse_args()

def main():
    args = parse_args()
    last_path = args.last_file
    prev = load_last(last_path)
    if args.once:
        report = collect()
        save_report(report, args.output)
        logging.info("Wrote report -> %s", args.output)
        changed = reports_differ(report, prev)
        if changed:
            logging.info("Report changed (or no previous).")
            save_report(report, last_path)
            if args.post_url:
                res = post_report(report, args.post_url, args.auth_token)
                logging.info("POST result: %s", res)
        else:
            logging.info("No change since last report; not posting.")
        print(json.dumps(report, indent=2))
        return

    # daemon loop
    logging.info("Starting agent loop (interval=%ds). Ctrl+C to stop.", args.interval)
    try:
        while True:
            report = collect()
            # write report always locally
            save_report(report, args.output)
            changed = reports_differ(report, prev)
            if changed:
                logging.info("Change detected; saving last and posting if configured.")
                save_report(report, last_path)
                prev = report
                if args.post_url:
                    res = post_report(report, args.post_url, args.auth_token)
                    logging.info("POST result: %s", res)
            else:
                logging.info("No significant change; not posting.")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        logging.info("Agent stopped by user.")

if __name__ == "__main__":
    main()
