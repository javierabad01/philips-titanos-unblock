#!/bin/bash
# quick_test.sh — Test rápido de CDP antes de lanzar el exploit completo
# Uso: ./quick_test.sh [TV_IP]

TV_IP="${1:-192.168.1.100}"

echo "=== Quick CDP Test ==="
echo "TV: $TV_IP"
echo ""

# 1. Ping
echo "[1] Ping..."
ping -c 1 -W 2 "$TV_IP" > /dev/null 2>&1 && echo "  OK" || { echo "  FAIL - TV no responde"; exit 1; }

# 2. JointSpace (siempre abierto)
echo "[2] JointSpace (:1925)..."
JS=$(curl -sf --connect-timeout 3 "http://$TV_IP:1925/6/system" 2>/dev/null)
if [ -n "$JS" ]; then
    echo "  OK: $(echo "$JS" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("name","?"), d.get("softwareversion","?"))' 2>/dev/null || echo "$JS" | head -c 100)"
else
    echo "  FAIL - JointSpace no responde (¿TV encendida?)"
fi

# 3. CDP puerto 7788
echo "[3] CDP (:7788)..."
CDP=$(curl -sf --connect-timeout 3 "http://$TV_IP:7788/json/version" 2>/dev/null)
if [ -n "$CDP" ]; then
    echo "  ★★★ CDP ABIERTO ★★★"
    echo "  $CDP" | python3 -m json.tool 2>/dev/null || echo "  $CDP"
    echo ""
    echo "[4] CDP targets..."
    TARGETS=$(curl -sf "http://$TV_IP:7788/json" 2>/dev/null)
    echo "  $TARGETS" | python3 -c "
import json, sys
targets = json.load(sys.stdin)
for i, t in enumerate(targets):
    print(f'  [{i}] {t.get(\"type\",\"?\")}: {t.get(\"title\",\"?\")[:40]} → {t.get(\"url\",\"?\")[:60]}')
    if t.get('webSocketDebuggerUrl'):
        print(f'       WS: {t[\"webSocketDebuggerUrl\"]}')
" 2>/dev/null || echo "  $TARGETS"
    echo ""
    echo "→ CDP está abierto. Lanzar: python3 cdp_root.py $TV_IP"
else
    echo "  CERRADO - Intentar:"
    echo "  a) ¿Está el USB con nbrowser_log_to_file insertado?"
    echo "  b) ¿Hay una app del browser abierta? (Titan OS store, Internet...)"
    echo "  c) Probar cerrar y reabrir la app del browser"
    echo "  d) Cold reboot (desenchufar AC 10s) con el USB puesto, luego abrir app"
fi

# 4. CDP puerto 7001 (browser.out / com.tpv.opera — LAUNCHER context!)
echo ""
echo "[5] CDP alt (:7001) — browser.out LAUNCHER (opw=0, sendPlatformMessage!)..."
CDP2=$(curl -sf --connect-timeout 3 "http://$TV_IP:7001/json/version" 2>/dev/null)
if [ -n "$CDP2" ]; then
    echo "  ★★★ PUERTO 7001 ABIERTO — LAUNCHER CONTEXT! ★★★"
    echo "  Este es el contexto privilegiado con sendPlatformMessage"
    echo "  $CDP2" | python3 -m json.tool 2>/dev/null || echo "  $CDP2"
    echo ""
    echo "[5b] CDP:7001 targets..."
    TARGETS2=$(curl -sf "http://$TV_IP:7001/json" 2>/dev/null)
    echo "  $TARGETS2" | python3 -c "
import json, sys
targets = json.load(sys.stdin)
for i, t in enumerate(targets):
    print(f'  [{i}] {t.get(\"type\",\"?\")}: {t.get(\"title\",\"?\")[:40]} → {t.get(\"url\",\"?\")[:60]}')
    if t.get('webSocketDebuggerUrl'):
        print(f'       WS: {t[\"webSocketDebuggerUrl\"]}')
" 2>/dev/null || echo "  $TARGETS2"
    echo ""
    echo "→ ¡CDP:7001 abierto! Lanzar: python3 cdp_root.py $TV_IP (intentará H chain automáticamente)"
else
    echo "  Cerrado — necesita /mnt/browser/nettv/enable_debug_port o /tmp/enable_debug_port"
    echo "  Activar con: CDP download chain (A.6 en cdp_root.py) + reboot"
fi

# 5. Telnet (por si el root ya funciona)
echo ""
echo "[6] Telnet (:2323)..."
(echo "id" | nc -w 2 "$TV_IP" 2323 2>/dev/null) && echo "  ★★★ ¡YA TENEMOS ROOT! ★★★" || echo "  Cerrado (normal)"

# 6. SSH (por si hay root previo)
echo ""
echo "[7] SSH (:2222)..."
(echo "" | nc -w 2 "$TV_IP" 2222 2>/dev/null | head -c 50) && echo "  Puerto SSH abierto" || echo "  Cerrado (normal)"

echo ""
echo "=== Done ==="
