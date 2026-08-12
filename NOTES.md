# Measurement notes

Background for [Unblock-ExpressVPN](README.md): what was measured, what the
numbers were, and which hypotheses turned out to be wrong. All figures come
from one filtered residential line in August 2026; re-measure before trusting
any absolute number.

## Diagnosis

Three separate things were tested; only one of them was actually broken.

| Layer | Status |
|---|---|
| DNS on port 53 | Poisoned. Any resolver (ISP, 1.1.1.1, 8.8.8.8) answers `10.10.34.35` for `www.expressvpn.com`. DoH over HTTPS returns the real records. |
| ExpressVPN **API** (`cp.expressapisv2.net`, behind Cloudflare) | **Blocked.** DPI sends a TCP RST ~0.2 s after the TLS ClientHello. Proven SNI-based, not IP-based: 77/120 random Cloudflare edges answer with SNI `www.cloudflare.com`, 0/120 answer with SNI `cp.expressapisv2.net`. ClientHello fragmentation (down to a 1-byte first segment) does not help — the DPI reassembles. |
| ExpressVPN **tunnel servers** (TCP 443) | Mostly fine. 28 of 208 locations answer normally from the raw connection. |

So the tunnel was never the problem. The client hung in `Connecting` because
`kp_sdk_instance_discovery` could not fetch `/ids2/locations/<id>/instances`,
so it never learned which server to dial.

## The fix

The ExpressVPN daemon uses two HTTP stacks. The Rust SDK inside
`expressvpn-sdklib.dll` is built on `reqwest`, which honours the standard proxy
environment variables. A per-service environment block was added so **only**
that service resolves and fetches its API through the already-working local
xray proxy:

```
HKLM\SYSTEM\CurrentControlSet\Services\ExpressVpnService
  Environment (REG_MULTI_SZ):
    HTTPS_PROXY=http://127.0.0.1:10808
    HTTP_PROXY=http://127.0.0.1:10808
    ALL_PROXY=http://127.0.0.1:10808
    NO_PROXY=127.0.0.1,localhost
```

Nothing else on the machine sees these variables. The system proxy, the hosts
file and the DNS settings are untouched.

Only the small API calls take the xray detour. The VPN tunnel itself dials the
ExpressVPN server directly, so throughput is unaffected (~2.6 MB/s measured on
Lightway UDP to `usa-columbus`).

## Operating notes

- **v2rayN must be running when ExpressVPN connects.** Bootstrap goes through
  `127.0.0.1:10808`. Once the tunnel is up it is self-sustaining — xray's own
  traffic then rides inside the VPN.
- Working protocols: `lightwayudp` (fastest) and `lightwaytcp`.
  `wireguard`, `openvpnudp` and `openvpntcp` never complete.
- Network Lock stays in `auto` mode and does not block during connect
  (`blockAll(IPv4): OFF` while `Connecting`), so it does not cut xray off
  mid-handshake.

## Reverting

```powershell
Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\ExpressVpnService' -Name Environment
Restart-Service ExpressVpnService -Force
```

## Does the VPN traffic burn the v2rayN quota?

No. Measured against xray's own byte counters (`http://127.0.0.1:10812/debug/vars`,
`stats.outbound.proxy`) with the VPN connected:

| test | xray counter delta |
|---|---|
| 50 MB downloaded through the ExpressVPN tunnel | **11 KB** |
| 10 MB downloaded through the v2rayN proxy (control) | 10.05 MB |

The 11 KB is the daemon's API polling — the only thing still routed through
xray. Bulk traffic goes app → ExpressVPN tunnel → server, with xray nowhere in
the path.

The one way to double-spend is to point an app at the proxy while the VPN is
up: that traffic goes app → xray → ExpressVPN tunnel and counts against both.
So with the VPN connected, turn the system proxy / per-app proxy off.

## Lightway UDP vs TCP

Both carry the same tunnel; the difference is what the tunnel rides on. UDP
mode wraps it in DTLS, TCP mode in TLS 1.3 over a TCP stream. TCP mode puts a
reliable stream inside a reliable stream, so the inner and outer congestion
control fight each other — the classic TCP-in-TCP meltdown, and it gets much
worse on a lossy link.

Measured here, interleaved UDP/TCP/UDP/TCP/UDP/TCP on `usa-columbus` with 15 s
windows so drift hits both equally:

| round | lightwayudp | lightwaytcp |
|---|---|---|
| 1 | 38.79 MB/s | 0.11 MB/s |
| 2 | 30.71 MB/s | 0.08 MB/s |
| 3 | 31.08 MB/s | 0.06 MB/s |

Roughly 300×. **Use `lightwayudp`.** Keep `lightwaytcp` only as a fallback if
UDP ever stops passing — it connects fine, it is just close to unusable for
bulk transfer.

## Upload is erratic — investigated, not fixable from here

Download is consistently 30–40 MB/s. Upload is not: on `slovenia`, within a
single session and against the same server IP `195.80.150.101`, four
back-to-back 10 MB uploads measured **2290, 35, 115 and 222 KB/s**. On the same
line in the same minutes, v2rayN uploaded at 393–8400 KB/s and completed every
transfer.

Ruled out, each by measurement:

| suspect | verdict |
|---|---|
| the line's uplink | no — v2rayN sustains MB/s on it |
| ExpressVPN server capacity | no — same server does 30–40 MB/s down, and 2.3 MB/s up on a good run |
| MTU | no — swept 1400/1350/1320/1280/1200, no relationship to upload speed |
| protocol | no — both Lightway modes affected, TCP worse |
| burst-then-throttle | no — no decay across consecutive runs |
| a bad server instance | no — the swing happens inside one session on one IP |

What is left is erratic policing of the **outbound** direction on the path to
ExpressVPN endpoints. The asymmetry is the tell: inbound is untouched while
outbound collapses and recovers on a scale of seconds. That is upstream
shaping, not congestion and not a capacity limit.

No client-side knob is left. For upload-heavy work use v2rayN directly; keep
ExpressVPN for downloads and browsing.

### Measurement traps hit along the way

Worth knowing before re-running any of this:

- **Cloudflare-fronted endpoints are useless as test targets here.**
  `speed.cloudflare.com` returns 403 to ExpressVPN exit IPs, and
  `postman-echo.com` (also Cloudflare, `162.159.142.41`) refuses TCP entirely.
  Both read as "upload is dead" when the network is fine.
  `speedtest.milkywan.fr` (`80.67.167.93`) is not behind Cloudflare and works.
- **Wait after the tunnel reports `Connected`.** Measuring immediately gives
  false zeros; the tunnel needs a few seconds and a warm-up request.
- **ICMP loss figures on this line are noise** — 17 % loss on 64-byte pings
  raw, 0 % on 1400-byte. Don't diagnose from `ping`.
- A real MTU mismatch does exist: the adapter is set to 1350 while the measured
  path MTU through the tunnel is 1327. `set-mtu.ps1` lowers it, but ExpressVPN
  resets it to 1350 on every reconnect, and the sweep showed it changes nothing.

## What the benchmarks could and could not settle

Throughput on this link swings enormously over time: `usa-columbus` on
`lightwayudp` measured 40.2 MB/s, then 15.3 MB/s, then 2.2 MB/s against the
same reference over about half an hour. That drift is larger than the gap
between locations, so **the per-location throughput numbers cannot be ranked
against each other** unless measured back to back.

Latency was stable and does separate them:

| exit | RTT |
|---|---|
| slovenia | 108 ms |
| monaco | 110 ms |
| uzbekistan | 111–120 ms |
| greece | 117 ms |
| malta | 118 ms |
| lithuania | 125 ms |
| usa-charlotte / usa-columbus | 209–213 ms |
| usa-charleston-sc / usa-nashville | 222–223 ms |
| usa-new-orleans / usa-little-rock | 242–247 ms |

Measured against a *nearby* reference in one window, the European exits gave
29.7 (slovenia), 30.9 (monaco) and 26.7 MB/s (uzbekistan) while `usa-columbus`
to a US reference gave 2.2 MB/s in that same window. Half the RTT and no worse
throughput, so a European exit is the better default.

Connect time is 2–7 s typically, with occasional 15–29 s outliers on any
region — no stable per-location pattern.

## Picking a region

28 of 208 locations were reachable. Membership in this list is what matters —
the probe score turned out to be a weak predictor of whether a connect
succeeds (`usa-billings` scored 2/8 and still connected in 5 s), while both
tested locations outside the list (`germany-frankfurt-1`, `uk-london`) time
out. All locations below were confirmed on `lightwayudp`; the probe itself was
a TLS handshake on TCP 443, i.e. the `lightwaytcp` path.

```
china            greece            malta             usa-charleston-west-virginia   usa-little-rock
lithuania        greenland         monaco            usa-charlotte                  usa-milwaukee
slovenia         jamaica           north-macedonia   usa-columbus                   usa-nashville
uzbekistan       jersey            nigeria           usa-billings                   usa-new-orleans
andorra          costa-rica        usa-birmingham    usa-charleston-south-carolina  usa-portland-oregon
armenia                            usa-indianapolis                                 usa-virginia-beach
```

Reachable regions drift as the filtering changes. Re-probe with:

```powershell
.\Unblock-ExpressVPN.ps1 -Action scan
```

Run it with the VPN **disconnected** — from inside the tunnel every server
answers and the list comes back uselessly complete.
