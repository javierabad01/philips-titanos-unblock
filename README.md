# philips-titanos-unblock

Root exploit, ad/telemetry blocking and boot fixes for Philips TitanOS TVs
with the NT72690 SoC. Tested on 43PUS8118/12.

## Legal

This is security research on a device the author owns. Modifying your own
hardware is lawful in the EU under the interoperability exception
(Directive 2001/29/EC, Art. 6(2)(b)) and no Spanish law prohibits it.
These tools are published for educational purposes and personal use on your
own TV. Do not use them to access devices you do not own.

## How the root works

The TV's Chromium browser (`browser.out`) exposes a Chrome DevTools Protocol
(CDP) endpoint on port 7788 when a USB drive is present at boot. The exploit
chain:

1. Insert a USB drive and cold-boot the TV.
2. `cdp_root.py` connects to CDP on port 7788.
3. It uses `Page.setDownloadBehavior` to write `customer_env.sh` to
   `/mtd_rwarea/apdat/`, the persistent read-write area.
4. The TitanOS boot process sources `/mtd_rwarea/apdat/customer_env.sh` on
   every startup, giving persistent root.

An alternative path uses `cmd_sender.c`, which talks to the `cmd_daemon`
SysV message queue — the daemon executes the message via `system()` as root.

## What customer_env.sh does (v14)

- **DNS trampantojo**: blocks all outgoing DNS at T+0 so `browser.out` can't
  resolve `app.titanos.tv` (the cloud launcher that freezes the TV and shows
  ads). Uses REJECT for instant failure instead of DROP/timeout.
- **IPv6 disabled**: the firmware has no `ip6tables`, so IPv4 iptables rules
  are bypassed via IPv6 unless the stack is disabled kernel-wide.
- **Selective IP blocking**: after ~30 s when the network is ready, resolves
  blocked domains and adds per-IP REJECT rules, then refreshes every 5 min to
  track CDN rotation.
- **Privacy popup fix**: blocks `cdn.cookielaw.org` IPs at T+0 so the OneTrust
  CMP banner auto-closes.
- **HbbTV ad blocking**: blocks Google Ad Manager domains
  (`securepubads.g.doubleclick.net`, `pubads.g.doubleclick.net`) used by
  broadcaster HbbTV overlays.
- **OTA blocking**: blocks `fwup.tpvision.com` and related hosts to prevent
  unwanted firmware updates.
- **Process management**: renice `browser.out`, `cidclient` and other heavy
  processes to priority 19; kill `errApp`.
- **Audio watchdog**: detects stuck system mute (a TitanOS launcher bug) via
  `/proc/aud/opu_spdif` and recovers via
  [Cactarium](https://github.com/pedramteymoori/cactarium)'s PHI API.
- **Time sync**: NTP is unavailable during the DNS block period, so the clock
  is set from the HTTP `Date` header of a request to `google.com`.
- **Root shell**: telnet on 2323, netcat listeners on 9999 and 4444.

## Blocked domains

| Category | Domains |
|---|---|
| Cloud launcher | `app.titanos.tv` |
| Telemetry | `samba.tv`, `samba-tv.com`, `samba-cdn.com`, `sambatv.com`, `pixel.samba.tv`, `logs.samba.tv`, `tags.samba.tv`, `sb.scorecardresearch.com`, `deu.tpv-tech.com`, `smarttv-tpv.com`, `data.mistat.intl.xiaomi.com` |
| Ads | `ad.doubleclick.net`, `pagead2.googlesyndication.com`, `ads.yahoo.com`, `advertising.com`, `adsymptotic.com`, `adnxs.com`, `ads.stickyadstv.com`, `sync.smartadserver.com` |
| HbbTV ads | `securepubads.g.doubleclick.net`, `pubads.g.doubleclick.net`, `tpc.googlesyndication.com`, `googleads.g.doubleclick.net` |
| Privacy popup | `cdn.cookielaw.org`, `mobile-data.onetrust.io` |
| OTA updates | `fwup.tpvision.com`, `fwupcheck.tpvision.com`, `ota.tpvision.com`, `fwup-deu.tpv-tech.com`, `fwup.tpv-tech.com` |

## Files

### Root exploit

- `cdp_root.py` — the main exploit: connects to CDP, writes persistent root
  hook. Run with USB inserted at boot.
- `attack.py` — fast version: waits for CDP to appear and runs all attack
  chains.
- `fast_probe.py` — discovery tool: enumerates available RPC functions via CDP.
- `cmd_sender.c` — talks to `cmd_daemon`'s SysV message queue to execute
  commands as root. Cross-compile with
  `arm-linux-gnueabihf-gcc -static -o cmd_sender cmd_sender.c`.
- `quick_test.sh` — quick connectivity and status check.

### Boot script

- `customer_env.sh` — the boot script (v14). Once root is established, copy
  this to `/mtd_rwarea/apdat/customer_env.sh` on the TV.

### Deployment

- `cdp_deploy.py` — deploys updated files (binary, scripts, config) to the TV
  via CDP download. Requires USB at boot.

## Usage

### First root

```bash
# 1. Insert USB drive in the TV and cold-boot (unplug AC 10 s, plug back in)
# 2. Wait for the TV to start, open any browser-based app (TitanOS Store, etc.)
# 3. Run the exploit from your PC:
python3 cdp_root.py <tv-ip> <pc-ip>

# 4. After reboot, verify root:
echo 'id' | nc -w3 <tv-ip> 9999
# Should print: uid=0(root)
```

### Install the full boot script

```bash
# From your PC, serve the files:
python3 -m http.server 8098

# From the TV root shell:
wget -O /mtd_rwarea/apdat/customer_env.sh http://<pc-ip>:8098/customer_env.sh
chmod 755 /mtd_rwarea/apdat/customer_env.sh

# Cold reboot to apply
```

## Compatibility

Tested on 43PUS8118/12 (TPN23.6E LA, NT72690, firmware 236.006.169.001,
kernel 4.19.261). Should work on other NT72690-based Philips TitanOS TVs
but verify on your specific model. The CDP port 7788 requires a USB drive
present at boot.

## Related

- [philips-titanos-tools](https://github.com/abbguslof/philips-titanos-tools) — alternative USB autoroot method
- [Cactarium](https://github.com/pedramteymoori/cactarium) — replacement launcher and dashboard
- [Jailbreak guide](https://gulo.se/thoughts/philips-titan-os-jailbreak-guide/)
