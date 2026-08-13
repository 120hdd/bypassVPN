# bypassVPN

**[راهنمای فارسی →](README.fa.md)**

ExpressVPN or Windscribe stuck on **Connecting** forever, on a network that
censors it? These PowerShell scripts usually fix it in about a minute.

They do *not* need a new VPN, a patched client, or a subscription you don't
already have. They need one thing: some local proxy that already works for you
(v2rayN, Clash, Nekoray, sing-box, Hiddify — anything with a local port).

| | |
|---|---|
| `Unblock-ExpressVPN.ps1` | ExpressVPN. Needs administrator once. |
| `Unblock-Windscribe.ps1` | Windscribe. No administrator at all. |
| `Run.cmd` | Double-click menu that drives both. |

Both clients break the same way and both fixes share one idea: the VPN client
cannot reach its own API, so lend it your proxy **for the API only**. The tunnel
still goes out directly — full speed, and none of your proxy's data allowance.
Measured on both: 50–100 MB pulled through the tunnel moved ~0 bytes through
the proxy.

## How to run it

**Double-click `Run.cmd`.** That is the whole answer for most people — it opens
a menu and does everything from there.

Do not double-click the `.ps1` file: Windows opens `.ps1` in an editor instead
of running it. That is a Windows default, not a problem with the script.

```
   Unblock VPN
   ===========

   Nothing here connects for you. Once a step reports OK, connect from
   the VPN app yourself.

   ExpressVPN
     1   Diagnose            what is broken (changes nothing)
     2   Apply the fix       asks for administrator
     3   List regions        which ones answer (disconnect the VPN first)
     4   Revert the fix      asks for administrator
     W   Why did it fail     read the last attempt out of the log
     A   Repair adapter      when W blames the network adapter

   Windscribe                no administrator needed
     5   Diagnose            what is broken (changes nothing)
     6   Start it fixed      relaunch with its API through the proxy
     7   List locations      which ones answer, for protocols you pick
     8   Desktop shortcut    always start it the right way
     T   Test protocols      which protocols work, and which uploads best
     R   Undo Windscribe     remove shortcut, start it normally

     0   Exit
```

Start your proxy first, then run `1` to see what is wrong and `2` to fix it.
Then open the ExpressVPN app and connect there — the tool never connects on
your behalf. `T` is the single exception, and it says so.

If you prefer the command line, open PowerShell in this folder:

```powershell
.\Unblock-ExpressVPN.ps1                 # diagnose
.\Unblock-ExpressVPN.ps1 -Action apply   # fix it
```

If PowerShell refuses with a script-execution error, run it as:

```powershell
powershell -ExecutionPolicy Bypass -File .\Unblock-ExpressVPN.ps1
```

`Run.cmd` already does this for you, and also clears the "downloaded from the
internet" flag that otherwise blocks the script.

## Why the client hangs

Three things get tested separately, and usually only one of them is broken:

| | |
|---|---|
| Tunnel servers | **fine.** Plenty of ExpressVPN servers still answer normally. |
| DNS | poisoned on port 53, but the client copes. |
| The client's API, `cp.expressapisv2.net` | **blocked.** DPI resets the TLS handshake the moment it sees that name in the ClientHello. |

Without the API the client can never fetch the server list for your chosen
region, so it never learns which server to dial — and sits in `Connecting`
until it gives up. The tunnel was never the problem.

## What the fix does

The Rust SDK inside `expressvpn-sdklib.dll` is built on `reqwest`, which honours
the standard proxy environment variables. The script writes a **per-service**
environment block so that only the ExpressVPN daemon takes the detour:

```
HKLM\SYSTEM\CurrentControlSet\Services\ExpressVpnService
  Environment (REG_MULTI_SZ):
    HTTPS_PROXY=http://127.0.0.1:10808
    HTTP_PROXY=http://127.0.0.1:10808
    ALL_PROXY=http://127.0.0.1:10808
    NO_PROXY=127.0.0.1,localhost
```

Nothing else on the machine sees these. Your system proxy, `hosts` file and DNS
settings are left exactly as they were.

**Only the tiny API calls go through your proxy.** The tunnel still dials the
VPN server directly, so full speed, and your proxy's data allowance is not
touched. Measured against xray's own byte counters: 50 MB pulled through the
ExpressVPN tunnel moved **11 KB** through the proxy.

## Commands

The `Run.cmd` menu entries map one-to-one onto these.

| Command | What it does |
|---|---|
| `.\Unblock-ExpressVPN.ps1` | Diagnose. Is the API blocked, is there a usable proxy, is the fix in place? Changes nothing. |
| `-Action apply` | Write the env block and restart the daemon. Needs admin. |
| `-Action revert` | Undo it completely. Needs admin. |
| `-Action scan` | List the regions whose servers still answer. Connects to nothing. |

Useful switches: `-Proxy http://127.0.0.1:1080` or `-Proxy socks5://...` to skip
auto-detection, `-ProbesPerLocation 5` for a more thorough scan.

## Windscribe

`Unblock-Windscribe.ps1` (menu entries 5–8) does the same job for Windscribe,
and it is gentler: **no administrator, no registry, nothing persistent.**

Windscribe breaks the same way — `api.windscribe.com` is unreachable, so the
client cannot fetch your session or the server list. Its engine can still build
a tunnel from cached data, which is why the CLI sometimes connects while the GUI
sits there with nothing to show and stale account figures.

Its networking layer is curl, so it honours proxy environment variables. The
script simply starts the client with them set. Because the tunnel is built by
separate processes (stunnel, openvpn, wireguard) that never see those variables,
it still goes out directly: **100 MB pulled through the tunnel moved 0 bytes
through the proxy.**

| Command | What it does |
|---|---|
| `.\Unblock-Windscribe.ps1` | Diagnose. |
| `-Action launch` | Restart the client with its API pointed at your proxy. |
| `-Action scan` | List the locations whose servers answer, grouped by country (~1 min). Add `-Protocols stealth,ikev2` to pick what it looks for. |
| `-Action protocols` | The one step that connects: tries each protocol, measures what each carries, reports which work and which uploads fastest. Add `-Location "Frankfurt"` to aim it. |
| `-Action shortcut` | Desktop shortcut that always starts it this way. |
| `-Action revert` | Remove the shortcut, start the client normally. |

Two things to know:

- **Do not use Windscribe's own Preferences → Proxy Settings.** That option is
  built to carry the VPN connection itself through the proxy, so every byte you
  transfer would come out of your proxy's data allowance. The environment
  variables this script sets reach only the API.
- **The environment lives as long as that client process.** Start Windscribe
  from the script or the shortcut, not the normal icon.

### Scanning cities

`-Action scan` reads the client's cached inventory out of the registry and
probes each city's Stealth endpoints — 1632 probes in about a minute, same
shape as the ExpressVPN scan. `-Thorough` probes every server and every port
instead of a sample: twice as long, roughly three more cities.

One detail matters more than it looks. Stealth is stunnel, and it has **eleven**
candidate ports. An earlier version of this scan probed only 443 and produced a
confident, wrong answer — it called Stockholm reachable when it would not
connect, and Frankfurt and Tokyo dead when they connected fine. Probing the
whole port set fixed it, and lifted the count of reachable servers from 36 to
208 out of 354.

Checked against real connections afterwards: **a city missing from the list
never connected** (6 of 6), while about one listed city in six still failed
(5 of 6 worked). Treat the list as a filter, not a promise — if one does not
come up, take the next.

### Scanning for a particular protocol

`-Protocols` picks what the scan looks for; the menu asks the same question
before running it. Ports come from the client's own `portMap` rather than a
copy here, so they follow Windscribe when it moves one. Each protocol is
probed the way it actually answers:

| Protocol | Address | Probe |
|---|---|---|
| `stealth` | `ip3` | TCP connect + TLS handshake — stunnel terminates real TLS |
| `wstunnel` | `ip` | TCP connect + TLS handshake |
| `tcp` | `ip2` | TCP connect — OpenVPN does not speak TLS on the wire |
| `ikev2` | `ip` | a real `IKE_SA_INIT`, requiring a reply that carries our own SPI back |
| `udp`, `wireguard` | — | **not possible**, see below |

One run against 126 cities: `tcp` answered in all 126, `ikev2` in 119,
`stealth` in 95, `wstunnel` in 67. A column that answers nearly everywhere
ranks nothing, and the scan says so rather than letting a full column read as a
list of good cities — it means that port is not filtered here at all, and
whatever stops a connection happens later in the handshake where a port scan
cannot see.

**`udp` and `wireguard` cannot be port-scanned by anyone.** OpenVPN UDP is
behind `tls-auth` and WireGuard requires a handshake signed with the server's
public key, which the client never caches; both silently drop anything else, so
silence means "blocked" and "working" equally. Asking for them prints that
instead of a fabricated column. `-Action protocols` answers them by connecting.

Two things this scan had to get right, both of which produced confidently wrong
answers first:

- **Hostnames are resolved to the server's own `ip` field, not through DNS.**
  IKEv2 and WStunnel are listed against a hostname, and DNS is one of the things
  being censored — `tr-022` and `uk-044` both resolved to `10.10.34.36` during
  testing. A scan built on that answers for a machine on the local network.
- **UDP probes run in their own pass, at a fraction of the width.** A lost
  datagram is simply gone, and thousands of concurrent TCP connects lose enough
  of them to invert the result: the same fleet that reported 119 reachable
  IKEv2 cities alone reported none at all when sharing a run. Retransmitting
  three times did not close that gap; not competing with the TCP flood did.

Protocols measured here: **stealth** and **ikev2** work reliably, `tcp` and
`wstunnel` are intermittent, `udp` and `wireguard` never connect.

### Which protocol, and how fast

`-Action protocols` connects with each one in turn and then pushes real traffic
through it, so the answer is measured rather than assumed. Roughly 60 MB per
protocol.

The gap is not small. On a 62 Mbps line, one run to Frankfurt:

| Protocol | Connects | Upload |
|---|---|---|
| `ikev2` | yes | 53–65 Mbps |
| `stealth` | yes | 3–4 Mbps |
| `tcp` | sometimes | 1.8 Mbps |
| `wstunnel`, `udp`, `wireguard` | no | — |

So Stealth costs roughly **fifteen times** the upload of IKEv2 here. It is the
one most likely to come up at all, which is why it is the fallback — but it is
the wrong default if IKEv2 connects.

Judge by the upload column. It is timed over a steady-state window, discarding
the first seconds where TCP slow start and a filling socket buffer would report
a rate the wire never carried, and it repeats to within a few percent. Download
is one short transfer and deliberately kept small: a line that bursts before it
throttles answers differently every run however it is measured, and a heavier
download test would spend the burst allowance the next protocol's turn needs.

**Aim it with `-Location`.** Left to itself the client connects to its own
"best", chosen on latency, which says nothing about whether that place is
reachable from here. When that pick is dead every protocol fails at once and
none of them is at fault — during testing `best` resolved to Manchester, which
answered every port in the scan and still refused all six protocols, while
Frankfurt and Istanbul connected on three. Take a city from `-Action scan`.

## Requirements

- Windows, ExpressVPN desktop app installed and signed in
- Windows PowerShell 5.1 (built in) — nothing to install
- A local proxy that works. Auto-detected on ports
  `10808, 10809, 7890, 7891, 2080, 2081, 1080, 1081, 8889, 8080, 20171, 12334`,
  over HTTP CONNECT or SOCKS5.

## Things worth knowing

- **Your proxy must be running whenever ExpressVPN connects.** Bootstrap goes
  through it. Once the tunnel is up it is self-sustaining — the proxy's own
  traffic then rides inside the VPN.
- **You never need to run the tool again.** The fix is a registry value under
  the service key; it survives reboots. Tested with every console window
  closed: waited 90 s, connected fine; restarted the service with nothing
  open, first attempt connected.
- **Connecting does fail intermittently, and a second attempt usually works.**
  Right after a failure run `-Action why`: it pulls that attempt out of the
  daemon log and says where it actually stalled, instead of guessing.

### What that intermittent failure actually is

Measured over one session: **62 connection attempts, 3 failures — about 5%.**
All three failed at the same 12.9 seconds, and all three for the same reason:

```
lightway: "Nudging Lightway..."      x7, backing off 0.2s 0.4s 0.8s 1.6s 3.2s 6.4s
lightway: he_client_nudge error: HE_CONNECTION_TIMED_OUT
Attempt failed, duration: 12911 ms
```

Lightway sent its handshake to the server, retried with a widening backoff and
gave up. The server list had already arrived, so the proxy and this fix were
working — the packets to that particular server just did not make it there and
back. On a filtered line that happens now and then. **Hit Connect again.** If
one region keeps doing it, take another from `-Action scan`.

Two things in that log look like causes and are not:

- **`wintun_run_...` / `wintun_set_...` and "Failed to update DNS servers".**
  These appear *below* the failure line — they are the tunnel being torn down
  afterwards. `Error retrieving interface with GetIpInterfaceEntry: code: 1168`
  is likewise normal; it shows up in successful connections too, right before
  the daemon recreates the adapter. `-Action why` only counts adapter evidence
  found *before* the failure, and only the wintun errors that mean the device
  would not open at all. If it does blame the adapter, `-Action repair`
  disconnects, restarts the daemon so it releases the device, and bounces any
  ExpressVPN adapter still present.
- **Decoy-domain errors** — `cheddar-chute.com`, `happy-bean-roastery.com` and
  friends are ExpressVPN's own anti-censorship IP probes. They fail here
  constantly by design. `-Action why` labels them as background noise.

And no, keeping a console window open makes no difference. Six disconnect and
reconnect cycles with nothing open connected six times, in 3–6 seconds each.
What looks like "it works when cmd is running" is the retry, not the window.
- **Use Lightway UDP.** On a filtered line Lightway TCP puts a reliable stream
  inside a reliable stream and collapses: measured interleaved on one region,
  UDP did 31–39 MB/s while TCP did 0.06–0.11 MB/s. Same tunnel, ~300× apart.
  Keep TCP as a fallback only.
- **Not every region works.** Run `-Action scan`. Membership in the list is what
  matters; the probe score is noisy and does not predict which will be fastest.
- **Scan with the VPN disconnected.** From inside the tunnel every server looks
  reachable and you get a confident, completely wrong list. The script refuses
  to scan while connected.
- **Upload may be poor and erratic** — that part is *not* fixable from the
  client. See [NOTES.md](NOTES.md) for what was measured and ruled out.

## Undo

```powershell
.\Unblock-ExpressVPN.ps1 -Action revert
```

or by hand:

```powershell
Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\ExpressVpnService' -Name Environment
Restart-Service ExpressVpnService -Force
```

## Is this safe?

It writes one registry value under the ExpressVPN service key and restarts that
service. No files are patched, no certificates installed, no traffic
intercepted, nothing sent anywhere. The whole script is one readable file —
read it before running it, as you should with anything asking for admin.

[NOTES.md](NOTES.md) documents the full diagnosis, the benchmarks, and the
hypotheses that turned out to be wrong (MTU, packet-size-dependent loss),
including measurement traps that produce convincing but false results.
