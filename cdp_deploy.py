#!/usr/bin/env python3
"""Deploy Cactarium + root shell to TV via CDP.
Downloads files to /mtd_rwarea/apdat/ via Page.setDownloadBehavior.
customer_env.sh v13 moves them to /mtd_rwarea/apdat/opt/cactarium/ on boot.

Usage: python3 cdp_deploy.py [TV_IP [PC_IP]]
"""
import json, socket, struct, urllib.request, re, time, http.server, threading, os, sys

TV = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"
PC = sys.argv[2] if len(sys.argv) > 2 else "192.168.1.50"
PORT = 8098

BASEDIR = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.join(BASEDIR, '..', '..', 'cactarium')

FILES = {
    'customer_env.sh': os.path.join(BASEDIR, 'customer_env_v14.sh'),
    'cactarium': os.path.join(REPO, 'dist', 'cactarium-linux-arm64'),
    'cactariumctl': os.path.join(REPO, 'server', 'cactariumctl'),
    'config.json': os.path.join(BASEDIR, 'cactarium_config.json'),
}

for name, path in FILES.items():
    if not os.path.exists(path):
        print(f"MISSING: {name} -> {path}")
        sys.exit(1)
    sz = os.path.getsize(path)
    print(f"  {name}: {sz:,} bytes ({path})")

# --- WebSocket helpers ---
mid = [0]

def ws_connect(ws_url):
    m = re.match(r'ws://([^:]+):(\d+)(.*)', ws_url)
    h, p, path = m.group(1), int(m.group(2)), m.group(3)
    s = socket.create_connection((h, p), timeout=10)
    s.sendall(f'GET {path} HTTP/1.1\r\nHost: {h}:{p}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n'.encode())
    r = b''
    while b'\r\n\r\n' not in r:
        r += s.recv(4096)
    return s

def ws_send(sk, d):
    p = d.encode()
    f = bytearray([0x81])
    l = len(p)
    if l < 126:
        f.append(0x80 | l)
    elif l < 65536:
        f.append(0x80 | 126)
        f.extend(struct.pack('>H', l))
    else:
        f.append(0x80 | 127)
        f.extend(struct.pack('>Q', l))
    mask = b'\x01\x02\x03\x04'
    f.extend(mask)
    f.extend(bytes(b ^ mask[i % 4] for i, b in enumerate(p)))
    sk.sendall(bytes(f))

def ws_recv(sk, t=15):
    sk.settimeout(t)
    try:
        d = sk.recv(131072)
        if len(d) < 2:
            return None
        pl = d[1] & 0x7f
        o = 2
        if pl == 126:
            pl = struct.unpack('>H', d[2:4])[0]
            o = 4
        elif pl == 127:
            pl = struct.unpack('>Q', d[2:10])[0]
            o = 10
        payload = d[o:]
        while len(payload) < pl:
            payload += sk.recv(65536)
        return payload[:pl].decode('utf-8', errors='replace')
    except Exception:
        return None

def ev(sock, expr, t=15):
    mid[0] += 1
    ws_send(sock, json.dumps({
        'id': mid[0], 'method': 'Runtime.evaluate',
        'params': {'expression': expr, 'returnByValue': True, 'awaitPromise': True}
    }))
    r = ws_recv(sock, t)
    if r:
        d = json.loads(r)
        res = d.get('result', {}).get('result', {})
        return res.get('value', res.get('description', str(res)))
    return None

def cdp_cmd(sock, method, params=None):
    mid[0] += 1
    c = {'id': mid[0], 'method': method}
    if params:
        c['params'] = params
    ws_send(sock, json.dumps(c))
    r = ws_recv(sock, 15)
    return json.loads(r) if r else None

def fread(sock, fpath):
    return ev(sock, f'''new Promise(function(resolve){{var x=new XMLHttpRequest();x.onload=function(){{resolve(x.responseText);}};x.onerror=function(){{resolve('ERR');}};x.open('GET','file://{fpath}',true);x.send();}})''')

# --- HTTP server ---
hits = []
file_data = {}
for name, path in FILES.items():
    with open(path, 'rb') as f:
        file_data[name] = f.read()

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        hits.append(self.path)
        fname = self.path.split('/')[-1]
        if fname in file_data:
            data = file_data[fname]
            print(f'  [HTTP] {fname} ({len(data):,} bytes)')
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Disposition', f'attachment; filename="{fname}"')
            self.send_header('Content-Length', len(data))
            self.end_headers()
            self.wfile.write(data)
        else:
            print(f'  [HTTP] 404: {self.path}')
            self.send_response(404)
            self.end_headers()
    def log_message(self, *a):
        pass

httpd = http.server.HTTPServer(('0.0.0.0', PORT), Handler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
print(f'\n[+] HTTP server on :{PORT}')

# --- Wait for CDP ---
print(f'\n[*] Connecting to CDP on {TV}:7788 ...')
try:
    targets = json.loads(urllib.request.urlopen(f'http://{TV}:7788/json', timeout=3).read())
except Exception:
    print('CDP not available. Make sure the TV is on with USB inserted and a browser app open.')
    httpd.shutdown()
    sys.exit(1)

tidx = 1 if len(targets) > 1 else 0
ws_url = targets[tidx]['webSocketDebuggerUrl']
print(f'[+] Target {tidx}: {targets[tidx]["title"]}')
sock = ws_connect(ws_url)
print('[+] WebSocket connected\n')

# --- Set download path ---
r = cdp_cmd(sock, 'Page.setDownloadBehavior', {
    'behavior': 'allow',
    'downloadPath': '/mtd_rwarea/apdat/'
})
print(f'setDownloadBehavior: {json.dumps(r)[:80]}')
if not r or 'error' in r:
    print('FAILED to set download behavior!')
    sock.close()
    httpd.shutdown()
    sys.exit(1)

# --- Download each file ---
for name in ['customer_env.sh', 'cactariumctl', 'config.json', 'cactarium']:
    print(f'\n--- Downloading {name} ({len(file_data[name]):,} bytes) ---')
    ev(sock, f'''new Promise(function(resolve){{
        var a=document.createElement('a');
        a.href='http://{PC}:{PORT}/download/{name}';
        a.download='{name}';
        document.body.appendChild(a);
        a.click();
        setTimeout(function(){{resolve('ok');}},2000);
    }})''')

    # Wait for download to complete (longer for bigger files)
    wait_time = max(5, len(file_data[name]) // 500000)
    print(f'  waiting {wait_time}s for download...')
    time.sleep(wait_time)

# --- Verify ---
print('\n=== Verification ===')
for name in FILES:
    path = f'/mtd_rwarea/apdat/{name}'
    r = fread(sock, path)
    if r and len(r) > 10:
        print(f'  {name}: OK ({len(r):,} chars)')
    elif r:
        print(f'  {name}: {r[:100]}')
    else:
        print(f'  {name}: MISSING or empty!')

print(f'\n  HTTP hits: {len(hits)}')
for h in hits:
    print(f'    {h}')

sock.close()
httpd.shutdown()

print('\n' + '=' * 60)
print('DEPLOY COMPLETE!')
print('=' * 60)
print(f'''
Files staged in /mtd_rwarea/apdat/:
  - customer_env.sh (v13: DNS block at T+0, privacy popup fix, REJECT rules, audio watchdog)
  - cactarium (arm64 binary, {len(file_data["cactarium"]):,} bytes)
  - cactariumctl (startup/supervisor script)

NEXT STEPS:
  1. Cold reboot the TV (unplug AC 10s, plug back in)
  2. Wait ~30s for Cactarium launcher (iptables/shell at 90s)
  3. Test:
     echo 'id' | nc -w3 {TV} 9999     # root shell
     curl http://{TV}:8090/            # Cactarium dashboard
''')
