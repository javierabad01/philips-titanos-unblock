#!/bin/sh
# customer_env.sh v14 — root shell + Cactarium boot + ad/telemetry + OTA blocking
# v14: Disable IPv6 at T+0 (no ip6tables on this firmware; IPv6 bypassed all rules).
#      Block HbbTV ad domains (Google Ad Manager on broadcaster channels).
# v13: Block ALL outgoing DNS at T+0 (browser.out can't resolve app.titanos.tv).
#      Hardcode cdn.cookielaw.org IPs at T+0 (auto-dismisses OneTrust privacy popup).
#      At ~T+30s when network is ready: lift global DNS block, resolve domains,
#      add selective IP blocking with REJECT (instant failure, not DROP/timeout).
#      REJECT everywhere (DROP → timeout → launcher freeze, the original bug).
#      Renice cidclient instead of kill loop (kill → costly respawn cycle).
#      Audio watchdog carried from v12 (stuck-mute recovery via Cactarium PHI).
BB=/mtd_rwarea/apdat/busybox
BOARD=/mtd_apexe/board
LOG=/tmp/customer_env_log.txt
OPT=/mtd_rwarea/apdat/opt
CDIR=$OPT/cactarium
CUSTOM_HOSTS=/mtd_rwarea/apdat/hosts_custom
IPT=$BOARD/iptables

echo "=== customer_env.sh v14 START ===" > $LOG
id >> $LOG 2>&1
date >> $LOG 2>&1

# --- Build custom /etc/hosts and attempt bind-mount ---
# (Fails rc=255: SELinux source idtv_data_t vs required net_conf_t.
#  xt_string missing too, so DNS name-based iptables also impossible.)
cp /etc/hosts $CUSTOM_HOSTS 2>/dev/null
for d in app.titanos.tv \
         samba.tv samba-tv.com samba-cdn.com sambatv.com \
         pixel.samba.tv logs.samba.tv tags.samba.tv \
         sb.scorecardresearch.com \
         deu.tpv-tech.com smarttv-tpv.com \
         data.mistat.intl.xiaomi.com \
         ad.doubleclick.net pagead2.googlesyndication.com \
         ads.yahoo.com advertising.com \
         adsymptotic.com adnxs.com \
         ads.stickyadstv.com sync.smartadserver.com \
         cdn.cookielaw.org mobile-data.onetrust.io \
         securepubads.g.doubleclick.net pubads.g.doubleclick.net \
         pagead2.googlesyndication.com tpc.googlesyndication.com \
         googleads.g.doubleclick.net \
         fwup.tpvision.com fwupcheck.tpvision.com ota.tpvision.com \
         fwup-deu.tpv-tech.com fwup.tpv-tech.com; do
  echo "127.0.0.1 $d" >> $CUSTOM_HOSTS
done
mount --bind $CUSTOM_HOSTS /etc/hosts 2>>$LOG
echo "hosts bind-mount: rc=$?" >> $LOG

# --- PHI page bind-mount (Cactarium launcher hook) ---
PHI_SRC=/swdl/UI/page
PHI_DST=$BOARD/mframework/webui/PHI/page
if [ -d "$PHI_SRC" ] && [ -f "$PHI_SRC/index.html" ]; then
  mount --bind $PHI_SRC $PHI_DST 2>>$LOG
  echo "PHI page bind-mount: rc=$?" >> $LOG
fi

# --- iptables PATH fix ---
mkdir -p /mtd_rwarea/apdat/bin
[ -f $BOARD/iptables ] && [ ! -e /mtd_rwarea/apdat/bin/iptables ] && \
  ln -sf $BOARD/iptables /mtd_rwarea/apdat/bin/iptables
export PATH=/mtd_rwarea/apdat/bin:$PATH

# --- IMMEDIATE (T+0): open firewall + disable IPv6 + block outgoing DNS ---
$IPT -w 5 -F INPUT 2>/dev/null
$IPT -w 5 -P INPUT ACCEPT 2>/dev/null
$IPT -w 5 -I INPUT -p tcp -j ACCEPT 2>/dev/null

# Disable IPv6: no ip6tables binary on this firmware, so all IPv4 iptables
# rules were bypassed via IPv6. Disable it kernel-wide.
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null
echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6 2>/dev/null
echo "immediate: IPv6 disabled" >> $LOG

# Block ALL outgoing DNS: nothing can resolve hostnames until we lift this.
# browser.out gets instant REJECT instead of timing out on app.titanos.tv.
# OneTrust CMP can't fetch its banner data, so the privacy popup auto-closes.
$IPT -w 2 -I OUTPUT -p udp --dport 53 -j REJECT 2>/dev/null
$IPT -w 2 -I OUTPUT -p tcp --dport 53 -j REJECT 2>/dev/null
echo "immediate: firewall open, all DNS blocked" >> $LOG

# Hardcode cdn.cookielaw.org IPs (Cloudflare anycast — stable).
# If the hosts bind-mount failed AND DNS is blocked, the TitanOS OneTrust
# page can still reach these IPs from a cached resolve. REJECT them too.
for ip in 104.18.86.42 104.18.87.42; do
  $IPT -w 2 -I OUTPUT -d $ip -j REJECT 2>/dev/null
done
echo "immediate: cdn.cookielaw.org hardcoded" >> $LOG

killall errApp 2>/dev/null

# === DNS BLOCKING LOOP ===
# At ~T+30s when network is ready: lift global DNS block, resolve all blocked
# domains, add selective IP REJECT rules. Refresh every 5 min for CDN rotation.
(
  resolve_ipv4() {
    # grep-based parser: more robust than awk across busybox nslookup output variants
    $BB nslookup "$1" 2>/dev/null | \
      grep 'Address' | tail -n +2 | \
      $BB grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -4
  }

  block_ip() {
    $IPT -w 2 -C OUTPUT -d "$1" -j REJECT 2>/dev/null || \
      $IPT -w 2 -I OUTPUT -d "$1" -j REJECT 2>/dev/null
  }

  DOMAINS="app.titanos.tv cdn.cookielaw.org mobile-data.onetrust.io \
    samba.tv samba-tv.com samba-cdn.com sambatv.com \
    pixel.samba.tv logs.samba.tv tags.samba.tv \
    ad.doubleclick.net pagead2.googlesyndication.com \
    securepubads.g.doubleclick.net pubads.g.doubleclick.net \
    tpc.googlesyndication.com googleads.g.doubleclick.net \
    sb.scorecardresearch.com deu.tpv-tech.com smarttv-tpv.com \
    data.mistat.intl.xiaomi.com \
    fwup.tpvision.com fwupcheck.tpvision.com ota.tpvision.com"

  # Wait for network to come up
  sleep 30
  ROUND=0
  while [ $ROUND -lt 3 ]; do
    ROUND=$((ROUND + 1))

    # Lift DNS block
    $IPT -w 2 -D OUTPUT -p udp --dport 53 -j REJECT 2>/dev/null
    $IPT -w 2 -D OUTPUT -p tcp --dport 53 -j REJECT 2>/dev/null

    # Let resolver stabilize (critical — without this, queries fail silently)
    sleep 3

    # Resolve and block
    COUNT=0
    for h in $DOMAINS; do
      IPS=$(resolve_ipv4 "$h")
      for ip in $IPS; do
        block_ip "$ip"
        COUNT=$((COUNT + 1))
      done
      [ -n "$IPS" ] && echo "dns-block: $h -> $(echo $IPS)" >> $LOG
    done

    echo "dns-block: round $ROUND, $COUNT rules" >> $LOG

    # Need at least a few rules to consider it working
    if [ $COUNT -gt 3 ]; then
      break
    fi

    # Too few — re-block DNS and retry after 15s
    $IPT -w 2 -I OUTPUT -p udp --dport 53 -j REJECT 2>/dev/null
    $IPT -w 2 -I OUTPUT -p tcp --dport 53 -j REJECT 2>/dev/null
    echo "dns-block: too few rules, retrying in 15s" >> $LOG
    sleep 15
  done

  # Ensure DNS is unblocked
  $IPT -w 2 -D OUTPUT -p udp --dport 53 -j REJECT 2>/dev/null
  $IPT -w 2 -D OUTPUT -p tcp --dport 53 -j REJECT 2>/dev/null

  # Time sync via HTTP Date header (NTP/rdate not available on this firmware)
  # Format: "Fri, 20 Nov 2026 18:46:40 GMT" → "2026-11-20 18:46:40"
  TDATE=$(wget -q -S -O /dev/null http://google.com/ 2>&1 | \
    sed -n 's/.*Date: *//p' | head -1)
  if [ -n "$TDATE" ]; then
    set -- $TDATE
    MON=""
    case "$3" in
      Jan) MON=01;; Feb) MON=02;; Mar) MON=03;; Apr) MON=04;;
      May) MON=05;; Jun) MON=06;; Jul) MON=07;; Aug) MON=08;;
      Sep) MON=09;; Oct) MON=10;; Nov) MON=11;; Dec) MON=12;;
    esac
    if [ -n "$MON" ]; then
      date -u -s "$4-$MON-$2 $5" >> $LOG 2>&1
      echo "dns-block: time synced: $4-$MON-$2 $5" >> $LOG
    fi
  fi

  echo "dns-block: setup done" >> $LOG

  # Refresh loop: re-resolve every 5 min to track CDN IP rotation
  while true; do
    sleep 300
    for h in $DOMAINS; do
      IPS=$(resolve_ipv4 "$h")
      for ip in $IPS; do
        block_ip "$ip"
      done
    done
  done
) &
echo "dns-block-loop launched" >> $LOG

# === EARLY START (8s): Cactarium + shell + process management ===
(
  sleep 8
  echo "=== EARLY START ===" >> $LOG
  date >> $LOG 2>&1

  # Deprioritize heavy processes (renice, not kill — kill causes respawn cost)
  for proc in browser.out omi_worker_main netflix cidclient; do
    RPID=$(pidof $proc)
    [ -n "$RPID" ] && renice 19 -p $RPID >> $LOG 2>&1
  done
  killall errApp 2>/dev/null

  # Move staged Cactarium files if present (from CDP deploy)
  mkdir -p $CDIR/var
  for f in cactarium cactariumctl; do
    if [ -f /mtd_rwarea/apdat/$f ]; then
      echo "moving staged $f" >> $LOG
      mv /mtd_rwarea/apdat/$f $CDIR/$f
      chmod 755 $CDIR/$f
    fi
  done
  if [ -f /mtd_rwarea/apdat/config.json ] && [ ! -f $CDIR/config.json ]; then
    echo "moving staged config.json" >> $LOG
    mv /mtd_rwarea/apdat/config.json $CDIR/config.json
    chmod 600 $CDIR/config.json
  fi

  # Start Cactarium
  export PATH=/mtd_rwarea/apdat/bin:$PATH
  if [ -f $CDIR/cactariumctl ]; then
    echo "starting cactarium via cactariumctl boot" >> $LOG
    /bin/sh $CDIR/cactariumctl boot >> $LOG 2>&1 &
  fi

  # Shell listeners
  $BB telnetd -p 2323 -l /bin/sh 2>>$LOG &
  while true; do $BB nc -l -p 9999 -e /bin/sh 2>/dev/null; sleep 1; done &
  while true; do $BB nc -l -p 4444 -e /bin/sh 2>/dev/null; sleep 1; done &

  # Process watchdog: renice heavy processes every 30s
  while true; do
    sleep 30
    for proc in browser.out cidclient; do
      RPID=$(pidof $proc)
      [ -n "$RPID" ] && renice 19 -p $RPID >/dev/null 2>&1
    done
    killall errApp 2>/dev/null
  done &
  echo "process-watchdog pid: $!" >> $LOG

  echo "=== EARLY START DONE ===" >> $LOG
) &

# === AUDIO WATCHDOG (20s): detect stuck system mute ===
(
  sleep 20
  echo "=== AUDIO WATCHDOG ===" >> $LOG
  CACT=http://localhost:8090/api/tv/phi
  MUTE_COUNT=0
  while true; do
    sleep 5
    SPDIF=$(cat /proc/aud/opu_spdif 2>/dev/null | head -1)
    # UNMUTE first: "UNMUTE" contains "MUTE", so *MUTE* would false-positive
    case "$SPDIF" in
      *UNMUTE*)
        [ $MUTE_COUNT -gt 0 ] && echo "audio-wd: unmuted (was $MUTE_COUNT)" >> $LOG
        MUTE_COUNT=0
        ;;
      *MUTE*)
        MUTE_COUNT=$((MUTE_COUNT + 1))
        if [ $MUTE_COUNT -ge 3 ]; then
          echo "audio-wd: STUCK MUTE ($MUTE_COUNT), recovering" >> $LOG
          wget -q -O /dev/null --post-data='{"method":"RpcSoundSysMute","params":{"mute":0}}' $CACT 2>/dev/null
          wget -q -O /dev/null --post-data='{"method":"RpcSoundSysMute","params":{"mute":0,"type":1}}' $CACT 2>/dev/null
          wget -q -O /dev/null --post-data='{"method":"RpcSoundVolumeMute","params":{"mute":false}}' $CACT 2>/dev/null
          sleep 3
          SPDIF2=$(cat /proc/aud/opu_spdif 2>/dev/null | head -1)
          case "$SPDIF2" in
            *UNMUTE*) echo "audio-wd: RECOVERED — $SPDIF2" >> $LOG; MUTE_COUNT=0 ;;
            *) echo "audio-wd: still muted — $SPDIF2" >> $LOG ;;
          esac
        fi
        ;;
    esac
  done
) &
echo "audio-watchdog launched" >> $LOG

# === PORT WATCHDOG: re-open firewall every 5 min ===
(
  sleep 90
  while true; do
    $IPT -w 5 -F INPUT 2>/dev/null
    $IPT -w 5 -P INPUT ACCEPT 2>/dev/null
    $IPT -w 5 -I INPUT -p tcp -j ACCEPT 2>/dev/null
    sleep 300
  done
) &

echo "root_ok_v14" > /tmp/root_proof
echo "=== v14 IMMEDIATE DONE ===" >> $LOG
