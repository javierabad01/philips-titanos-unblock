# philips-titanos-unblock

Boot-time ad, telemetry and OTA blocking for rooted Philips TitanOS TVs
(NT72690 SoC, tested on 43PUS8118/12).

Requires a rooted TV via
[philips-titanos-tools](https://github.com/abbguslof/philips-titanos-tools).
The `customer_env.sh` script runs at every boot from
`/mtd_rwarea/apdat/customer_env.sh`.

## What it does

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

- `customer_env.sh` — the boot script (v14). Copy to
  `/mtd_rwarea/apdat/customer_env.sh` on the TV.
- `cdp_deploy.py` — deploys files to the TV via Chrome DevTools Protocol
  (requires the TV's browser to have CDP enabled on port 7788, which happens
  when a USB drive is present at boot). Adjust the default IPs to match your
  network.

## Install

```bash
# From a root shell on the TV:
# 1. Download customer_env.sh
wget -O /mtd_rwarea/apdat/customer_env.sh http://<pc-ip>:8098/customer_env.sh
chmod 755 /mtd_rwarea/apdat/customer_env.sh

# 2. Cold reboot (unplug AC 10 s, plug back in)
```

Or use `cdp_deploy.py` with a USB drive present at boot:

```bash
python3 cdp_deploy.py <tv-ip> <pc-ip>
```

## Compatibility

Tested on 43PUS8118/12 (TPN23.6E LA, NT72690, firmware 236.006.169.001,
kernel 4.19.261). The jailbreak and scripts should work on other NT72690-based
Philips TitanOS TVs but verify on your specific model.

## Related

- [philips-titanos-tools](https://github.com/abbguslof/philips-titanos-tools) — jailbreak and persistent root
- [Cactarium](https://github.com/pedramteymoori/cactarium) — replacement launcher and dashboard
- [Jailbreak guide](https://gulo.se/thoughts/philips-titan-os-jailbreak-guide/)
