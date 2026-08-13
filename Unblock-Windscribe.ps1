<#
.SYNOPSIS
    Gets the Windscribe client usable again on networks that block its API.

.DESCRIPTION
    Windscribe fails here the same way ExpressVPN does: api.windscribe.com is
    unreachable, so the client cannot fetch your session or the server list.
    The engine can still build a tunnel from whatever it cached, which is why
    the CLI sometimes connects, but the GUI is left with nothing to show and
    stale account data.

    Windscribe's networking layer is curl, and it honours the standard proxy
    environment variables. This script starts the client with those set, so its
    API calls travel through a local proxy you already have working.

    Two things make this easier than the ExpressVPN fix:

      * The API calls come from the GUI process, not the LocalSystem service,
        so no administrator rights and no registry changes are needed.
      * Only curl inside the client sees the proxy. The tunnel is built by
        separate processes (stunnel, openvpn, wireguard) that ignore it, so it
        goes out directly and spends none of your proxy's data allowance.
        Measured: 100 MB pulled through the tunnel moved 0 bytes through the
        proxy.

    Do NOT use Windscribe's own Preferences -> Proxy Settings for this. That one
    is meant to carry the VPN connection itself through the proxy, which would
    spend your data allowance on every byte.

.PARAMETER Action
    diagnose   Report what is broken and whether a usable proxy exists (default).
    launch     Restart the Windscribe client with the proxy environment set.
    scan       Probe the cached server list and list locations that answer,
               for whichever protocols -Protocols names.
    protocols  Connect with each protocol in turn, then measure what each one
               carries, and report which are usable and which uploads fastest.
    shortcut   Put a desktop shortcut that always launches it the right way.
    revert     Remove that shortcut and start the client normally again.

.PARAMETER Proxy
    Proxy URL, e.g. http://127.0.0.1:10808. Omitted means auto-detect.

.PARAMETER Location
    City for -Action protocols to test against, e.g. "Frankfurt". Omitted, the
    client picks its own "best", which is chosen on latency and is regularly
    somewhere unreachable - and then every protocol fails and none of them is
    at fault. Take a city that answered -Action scan.

.PARAMETER Protocols
    Which protocols -Action scan should look for: stealth, tcp, wstunnel,
    ikev2, udp, wireguard. Omitted it probes Stealth alone.

    udp and wireguard cannot be port-scanned by anyone: both drop any packet
    that is not already signed with a key the client does not cache, so silence
    means "blocked" and "working" equally. Ask for them and the scan says so
    rather than guessing. -Action protocols answers those by connecting.

.PARAMETER Thorough
    Probe every server and port during -Action scan rather than a sample.

.EXAMPLE
    .\Unblock-Windscribe.ps1
    .\Unblock-Windscribe.ps1 -Action launch
    .\Unblock-Windscribe.ps1 -Action scan
    .\Unblock-Windscribe.ps1 -Action scan -Protocols stealth,ikev2
    .\Unblock-Windscribe.ps1 -Action protocols -Location "Frankfurt"
    .\Unblock-Windscribe.ps1 -Action shortcut

.NOTES
    The environment only lives as long as that client process, so start
    Windscribe through this script (or the shortcut it makes), not from the
    normal icon.

    Part of bypassVPN by @120hdd.

.LINK
    https://github.com/120hdd/bypassVPN
#>
[CmdletBinding()]
param(
    [ValidateSet('diagnose', 'launch', 'scan', 'protocols', 'shortcut', 'revert')]
    [string] $Action = 'diagnose',

    [string] $Proxy,

    # Which location -Action protocols should test against. Left empty it uses
    # the client's own "best", which is chosen for latency and says nothing
    # about whether it is reachable from here - a dead best makes every single
    # protocol look broken. Take a city from -Action scan instead.
    [string] $Location,

    # Which protocols -Action scan should probe for, e.g. stealth,ikev2.
    # Omitted it probes Stealth only, which is what this scan has always done.
    [string[]] $Protocols,

    # Probe every server and every port instead of a representative sample.
    # Roughly 3900 probes rather than 1600; finds about three more locations.
    [switch] $Thorough
)

$ErrorActionPreference = 'Stop'

$ApiHost     = 'api.windscribe.com'
$ServiceName = 'WindscribeService'
$RegKey      = 'HKCU:\Software\Windscribe\Windscribe2'
$ShortcutName = 'Windscribe (via proxy).lnk'

# Every protocol the client offers, best-behaved-under-censorship first.
$AllProtocols = 'stealth', 'tcp', 'ikev2', 'wstunnel', 'udp', 'wireguard'

$ProxyPorts = 10808, 10809, 7890, 7891, 2080, 2081, 1080, 1081, 8889, 8080, 20171, 12334


#--------------------------------------------------------------------- output

function Write-Head { param($t) Write-Host ''; Write-Host "  $t" -ForegroundColor Cyan; Write-Host "  $('-' * $t.Length)" -ForegroundColor DarkCyan }
function Write-Ok   { param($t) Write-Host '  [ ok ] ' -ForegroundColor Green  -NoNewline; Write-Host $t }
function Write-Bad  { param($t) Write-Host '  [fail] ' -ForegroundColor Red    -NoNewline; Write-Host $t }
function Write-Warn { param($t) Write-Host '  [warn] ' -ForegroundColor Yellow -NoNewline; Write-Host $t }
function Write-Info { param($t) Write-Host '         ' -NoNewline; Write-Host $t -ForegroundColor Gray }


#---------------------------------------------------------------- environment

function Get-Windscribe {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if (-not $svc) { throw "The $ServiceName service was not found. Is the Windscribe Windows app installed?" }

    $dir = Split-Path ($svc.PathName -replace '^"|"$', '')
    [pscustomobject]@{
        Dir     = $dir
        Gui     = Join-Path $dir 'Windscribe.exe'
        Cli     = Join-Path $dir 'windscribe-cli.exe'
        Running = $svc.State -eq 'Running'
    }
}

# Everything here exists because windscribe-cli starts Windscribe.exe when the
# client is not already up, and that GUI then lives for hours holding whatever
# handles it inherited.
#
#   * Never `& $cli status`. The call operator waits for the output pipe to
#     close rather than for the process to exit, and the GUI is holding that
#     pipe - so it never returns, and the script dies before reporting a thing.
#     That is the whole bug: the client appeared, nothing else ever printed.
#
#   * Redirecting to a file is not enough either. Start-Process with any
#     redirection creates the child with handle inheritance on, which hands it
#     every inheritable handle this process owns - our own stdout among them,
#     whatever it was pointed at. The CLI passes those to the GUI, and now
#     anything reading our output waits on the GUI instead. It moves the hang
#     one level up rather than removing it.
#
# So launch through the shell, which does not inherit handles at all, and let
# cmd do the redirection on the far side of that boundary.
function Invoke-WsCli {
    param($Ws, [string[]] $CliArgs, [int] $TimeoutSec = 30)

    if (-not (Test-Path $Ws.Cli)) { return $null }
    $out = [IO.Path]::GetTempFileName()
    try {
        $quoted = $CliArgs | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }
        $line = '/c ""{0}" {1} > "{2}" 2>&1"' -f $Ws.Cli, ($quoted -join ' '), $out
        $p = Start-Process -FilePath $env:ComSpec -ArgumentList $line -WindowStyle Hidden -PassThru
        if (-not $p.WaitForExit($TimeoutSec * 1000)) {
            try { $p.Kill() } catch { }
            return $null
        }
        # The GUI it may have spawned still holds this file open, so ask for a
        # share-anything read rather than letting Get-Content fail on it.
        $fs = [IO.File]::Open($out, 'Open', 'Read', 'ReadWrite')
        try { return (New-Object IO.StreamReader($fs)).ReadToEnd() -split "`r?`n" }
        finally { $fs.Dispose() }
    }
    catch { return $null }
    finally { Remove-Item $out -Force -ErrorAction SilentlyContinue }
}

function Get-CliStatus {
    param($Ws, [int] $TimeoutSec = 30)
    $out = Invoke-WsCli $Ws @('status') -TimeoutSec $TimeoutSec
    if (-not $out) { return $null }
    $h = @{}
    foreach ($line in $out) {
        if ($line -match '^\s*([^:]+):\s*(.+?)\s*$') { $h[$Matches[1].Trim()] = $Matches[2].Trim() }
    }
    if ($h.Count -eq 0) { return $null }
    $h
}

function Test-GuiRunning { [bool](Get-Process Windscribe -ErrorAction SilentlyContinue) }


#------------------------------------------------------------------- probing

function Test-TlsPath {
    param([string] $Target, [int] $Port = 443, [int] $TimeoutMs = 6000)
    $client = New-Object Net.Sockets.TcpClient
    try {
        if (-not $client.ConnectAsync($Target, $Port).Wait($TimeoutMs)) { return 'timeout' }
        $ssl = New-Object Net.Security.SslStream($client.GetStream(), $false, { $true })
        try {
            if ($ssl.AuthenticateAsClientAsync($Target).Wait($TimeoutMs)) { return 'ok' }
            return 'timeout'
        }
        catch {
            if ($_.Exception.ToString() -match 'forcibly closed|reset|aborted') { return 'reset' }
            return 'ok'
        }
        finally { $ssl.Dispose() }
    }
    catch { return 'timeout' }
    finally { $client.Close() }
}

function Test-HttpProxy {
    param([string] $ProxyHost, [int] $ProxyPort, [int] $TimeoutMs = 6000)
    $client = New-Object Net.Sockets.TcpClient
    try {
        if (-not $client.ConnectAsync($ProxyHost, $ProxyPort).Wait(2000)) { return $false }
        $s = $client.GetStream()
        $s.ReadTimeout = $TimeoutMs; $s.WriteTimeout = $TimeoutMs
        $req = "CONNECT ${ApiHost}:443 HTTP/1.1`r`nHost: ${ApiHost}:443`r`n`r`n"
        $b = [Text.Encoding]::ASCII.GetBytes($req)
        $s.Write($b, 0, $b.Length)
        $buf = New-Object byte[] 256
        $n = $s.Read($buf, 0, $buf.Length)
        if ($n -le 0) { return $false }
        return ([Text.Encoding]::ASCII.GetString($buf, 0, $n) -match '^HTTP/1\.[01] 200')
    }
    catch { return $false }
    finally { $client.Close() }
}

function Test-Socks5Proxy {
    param([string] $ProxyHost, [int] $ProxyPort, [int] $TimeoutMs = 6000)
    $client = New-Object Net.Sockets.TcpClient
    try {
        if (-not $client.ConnectAsync($ProxyHost, $ProxyPort).Wait(2000)) { return $false }
        $s = $client.GetStream()
        $s.ReadTimeout = $TimeoutMs; $s.WriteTimeout = $TimeoutMs
        $s.Write([byte[]](5, 1, 0), 0, 3)
        $r = New-Object byte[] 2
        if ($s.Read($r, 0, 2) -ne 2 -or $r[0] -ne 5 -or $r[1] -ne 0) { return $false }
        $name = [Text.Encoding]::ASCII.GetBytes($ApiHost)
        $req = [byte[]](5, 1, 0, 3) + [byte] $name.Length + $name + [byte[]](1, 187)
        $s.Write($req, 0, $req.Length)
        $r2 = New-Object byte[] 4
        if ($s.Read($r2, 0, 4) -ne 4) { return $false }
        return ($r2[1] -eq 0)
    }
    catch { return $false }
    finally { $client.Close() }
}

function Find-Proxy {
    param([string] $Explicit)
    $candidates = @()
    if ($Explicit) {
        if ($Explicit -notmatch '^(https?|socks5)://([^:/]+):(\d+)') {
            throw "Could not parse -Proxy '$Explicit'. Use http://host:port or socks5://host:port."
        }
        $candidates += [pscustomobject]@{ Scheme = $Matches[1]; Host = $Matches[2]; Port = [int]$Matches[3] }
    }
    else {
        foreach ($p in $ProxyPorts) { $candidates += [pscustomobject]@{ Scheme = $null; Host = '127.0.0.1'; Port = $p } }
    }
    foreach ($c in $candidates) {
        if ($c.Scheme -ne 'socks5' -and (Test-HttpProxy $c.Host $c.Port)) {
            return [pscustomobject]@{ Url = "http://$($c.Host):$($c.Port)"; Kind = 'http' }
        }
        if ($c.Scheme -notin 'http', 'https' -and (Test-Socks5Proxy $c.Host $c.Port)) {
            return [pscustomobject]@{ Url = "socks5://$($c.Host):$($c.Port)"; Kind = 'socks5' }
        }
    }
    return $null
}


#------------------------------------------------------------------ the fix

# The client keeps its server inventory in memory and only writes it to the
# registry on a clean shutdown, so force-killing it throws that away and the
# next -Action scan has nothing to read. Ask the window to close first and keep
# the kill for a client that will not go.
function Stop-WindscribeGui {
    $p = Get-Process Windscribe -ErrorAction SilentlyContinue
    if (-not $p) { return }
    foreach ($proc in $p) { try { [void] $proc.CloseMainWindow() } catch { } }
    for ($i = 0; $i -lt 20; $i++) {
        Start-Sleep -Milliseconds 500
        if (-not (Get-Process Windscribe -ErrorAction SilentlyContinue)) { return }
    }
    Get-Process Windscribe -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 2
}

function Start-WindscribeProxied {
    param($Ws, [string] $ProxyUrl)

    Stop-WindscribeGui
    Start-Sleep -Seconds 2

    # curl reads these; the tunnel processes do not, which is the whole point.
    # Set them on ourselves and let the child inherit: starting it with
    # UseShellExecute=false would hand it our console handles, and the pipe
    # would then never close for whoever ran this script.
    foreach ($n in 'ALL_PROXY', 'HTTP_PROXY', 'HTTPS_PROXY') {
        Set-Item -Path "env:$n" -Value $ProxyUrl
    }
    $env:NO_PROXY = '127.0.0.1,localhost'
    Start-Process -FilePath $Ws.Gui
}

function Get-EgressIp {
    foreach ($attempt in 1..3) {
        Start-Sleep -Seconds 4
        foreach ($url in 'https://api.ipify.org', 'http://ip-api.com/line/?fields=query') {
            try { return (Invoke-WebRequest $url -UseBasicParsing -TimeoutSec 12).Content.Trim() } catch { }
        }
    }
    return $null
}

# Throughput, measured over whatever the default route is - which is the tunnel
# once a protocol is up. Proxy is pinned to $null so a proxy left in the
# environment cannot quietly carry the test and flatter every protocol equally.

# Both directions are timed over a steady-state window, not over the whole
# transfer. The opening seconds measure TCP slow start and a socket buffer
# filling up rather than the link - on the upload side especially, the first
# writes return instantly into kernel memory and would report a rate the wire
# never carried. So: transfer for $WarmSec, note the position, and rate only
# what moves after that. Nothing is waited on to completion, which also keeps a
# crawling protocol from holding the run for minutes.
function Measure-Rate {
    param([scriptblock] $Pump, [int] $WarmSec = 3, [int] $WindowSec = 8)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $moved = 0; $markBytes = -1; $markSec = 0; $lastSec = 0
    while ($sw.Elapsed.TotalSeconds -lt ($WarmSec + $WindowSec)) {
        $n = & $Pump
        if ($n -le 0) { break }
        $moved += $n
        # Rate against the last byte that actually arrived, not against the
        # clock when the loop gave up. A run that ends on a refused reconnect
        # spends its final second transferring nothing, and charging the window
        # for that time reported a slow link as a dead one.
        $lastSec = $sw.Elapsed.TotalSeconds
        if ($markBytes -lt 0 -and $lastSec -ge $WarmSec) {
            $markBytes = $moved; $markSec = $lastSec
        }
    }
    $sw.Stop()
    if ($markBytes -lt 0) { return $null }
    $sec = $lastSec - $markSec
    if ($sec -le 0.5) { return $null }
    [math]::Round(($moved - $markBytes) * 8 / $sec / 1e6, 1)
}

# Upload is the headline number and the one worth trusting: measured over a
# steady-state window it repeats to within a few percent. Download is reported
# but deliberately small and single-shot, because a line that bursts before it
# throttles - very common here - gives a different answer every run no matter
# how it is measured, and a heavy download test would also spend the burst
# allowance that the next protocol's turn needs.
function Measure-Throughput {
    param([int] $WarmSec = 2, [int] $WindowSec = 5)

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    [Net.ServicePointManager]::Expect100Continue = $false
    $chunk = New-Object byte[] 65536

    $up = $null
    $req = $null
    try {
        $req = [Net.HttpWebRequest]::Create('https://speed.cloudflare.com/__up')
        $req.Method = 'POST'; $req.Proxy = $null
        $req.Timeout = 15000; $req.ReadWriteTimeout = 20000
        $req.ContentType = 'application/octet-stream'
        $req.AllowWriteStreamBuffering = $false
        $req.SendChunked = $true
        $s = $req.GetRequestStream()
        $up = Measure-Rate { $s.Write($chunk, 0, $chunk.Length); $chunk.Length } $WarmSec $WindowSec
    }
    catch { }
    # Abort rather than Close: the upload is deliberately unfinished, and
    # closing would block until the tail of it drains.
    finally { if ($req) { try { $req.Abort() } catch { } } }

    # One fixed transfer, timed end to end. Chaining bigger ones to fill a
    # steady-state window was tried and is worse here: the traffic pushes the
    # line past its burst allowance into throttling, and the endpoint meters
    # what it will serve - a size it answered happily earlier in a session
    # starts coming back 403 later. Hence stepping down until one is served
    # rather than treating the first refusal as a dead link.
    $down = $null
    foreach ($bytes in 16777216, 8388608, 4194304, 2097152) {
        $resp = $null
        try {
            $r = [Net.HttpWebRequest]::Create("https://speed.cloudflare.com/__down?bytes=$bytes")
            $r.Proxy = $null
            $r.Timeout = 15000; $r.ReadWriteTimeout = 20000
            $buf = New-Object byte[] 262144
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $resp = $r.GetResponse(); $rs = $resp.GetResponseStream()
            $got = 0
            while (($k = $rs.Read($buf, 0, $buf.Length)) -gt 0) { $got += $k }
            $sw.Stop()
            if ($got -gt 0 -and $sw.Elapsed.TotalSeconds -gt 0) {
                $down = [math]::Round($got * 8 / $sw.Elapsed.TotalSeconds / 1e6, 1)
                break
            }
        }
        catch { }
        finally { if ($resp) { try { $resp.Close() } catch { } } }
    }

    [pscustomobject]@{ Up = $up; Down = $down }
}

function Connect-Windscribe {
    param($Ws, [string] $Target, [string] $Protocol, [int] $TimeoutSec = 70)
    $cliArgs = @('connect')
    if ($Target) { $cliArgs += $Target } else { $cliArgs += 'best' }
    if ($Protocol) { $cliArgs += $Protocol }

    $out = Invoke-WsCli $Ws $cliArgs -TimeoutSec $TimeoutSec
    $last = @($out) | Where-Object { $_ -and $_ -notmatch 'spdlog init failed' } | Select-Object -Last 1
    [pscustomobject]@{
        Connected = ("$last" -match '^\s*\*?Connected')
        Message   = if ($last) { "$last" } else { 'no answer within the timeout' }
    }
}

function Disconnect-Windscribe {
    param($Ws)
    [void] (Invoke-WsCli $Ws @('disconnect') -TimeoutSec 45)
}


#------------------------------------------------------------- region scan

$ServersPerCity = 3

# What each protocol actually listens on comes out of the client's own portMap,
# so this follows the server list rather than a copy of it that goes stale.
# Only the fast-mode port subsets and how to speak to each one live here.
#
# 'Use' in the portMap names the address field: ip3 for stunnel and WireGuard,
# ip2 for the OpenVPN modes, and hostname for IKEv2 and WStunnel. Hostname is
# resolved here to the server's own ip field rather than through DNS, because
# DNS is one of the things being censored - during testing tr-022 and uk-044
# both resolved to 10.10.34.36, and a scan built on that answers for a machine
# on the local network instead of for Windscribe.
#
# Kind is how a port is tested:
#   tls  connect and complete a TLS handshake - stunnel and WStunnel both
#        terminate real TLS, so a handshake distinguishes a server from a
#        blackhole that merely accepts connections
#   tcp  connect only - OpenVPN TCP does not speak TLS on the wire
#   ike  send an IKE_SA_INIT and require a matching reply
#   ''   cannot be probed at all, see below
$ProtocolProbes = [ordered]@{
    stealth   = @{ Map = 'stunnel';  Kind = 'tls'; Fast = 443, 22, 123, 587, 8443, 21 }
    tcp       = @{ Map = 'tcp';      Kind = 'tcp'; Fast = 443, 80, 22, 587, 1194, 21 }
    wstunnel  = @{ Map = 'wstunnel'; Kind = 'tls'; Fast = 443 }
    ikev2     = @{ Map = 'ikev2';    Kind = 'ike'; Fast = 500 }
    udp       = @{ Map = 'udp';      Kind = ''
                   Why = 'OpenVPN UDP is behind tls-auth, so the server drops any packet without a valid HMAC and answers nothing. Silence would mean "blocked" and "working" equally.' }
    wireguard = @{ Map = 'wg';       Kind = ''
                   Why = 'A WireGuard handshake has to be signed with that server''s public key, which the client never caches. Without it the server stays silent by design.' }
}

function Resolve-Protocols {
    param([string[]] $Wanted)
    # Accept "stealth,ikev2", "stealth ikev2" and -Protocols stealth,ikev2 alike.
    $names = ($Wanted -join ',') -split '[,\s]+' | Where-Object { $_ } | ForEach-Object { $_.ToLower() }
    $out = @()
    foreach ($n in $names) {
        $key = switch ($n) {
            'stunnel'   { 'stealth' }
            'wg'        { 'wireguard' }
            'openvpn'   { 'udp' }
            default     { $n }
        }
        if (-not $ProtocolProbes.Contains($key)) {
            throw "Unknown protocol '$n'. Pick from: $(($ProtocolProbes.Keys) -join ', ')."
        }
        if ($out -notcontains $key) { $out += $key }
    }
    $out
}

# Probing from inside any tunnel makes every server look reachable. Windscribe
# is not the only client that could be up, so look at the actual default route
# rather than asking one vendor's CLI.
function Assert-NoTunnel {
    $vpn = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
        Sort-Object RouteMetric |
        ForEach-Object { (Get-NetAdapter -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue).InterfaceDescription } |
        Where-Object { $_ -match 'ExpressVPN|Windscribe|WireGuard|TAP-Windows|WinTun|OpenVPN' } |
        Select-Object -First 1
    if (-not $vpn) { return }
    Write-Host ''
    Write-Bad "A VPN adapter is carrying the default route ($vpn)."
    Write-Info 'Every probe would travel through that tunnel and every city would'
    Write-Info 'look reachable. Disconnect the VPN, then run this again.'
    Write-Host ''
    exit 1
}

function Get-WsInventory {
    $raw = (Get-ItemProperty $RegKey -Name wsnetSettings -ErrorAction SilentlyContinue).wsnetSettings
    if (-not $raw) {
        # The client holds this in memory and writes it out when it shuts down
        # cleanly, so killing it outright loses the lot. Hence the graceful
        # close in Stop-WindscribeGui - and hence this wording, which used to
        # blame the client for not having loaded yet.
        throw 'No cached server inventory found. Start the client through -Action launch, let it load the location list, then close it from its own menu and retry.'
    }
    # Not ConvertFrom-Json: this blob carries one empty-string key, and turning
    # that into a PSObject property throws. JavaScriptSerializer hands back
    # plain dictionaries and does not care.
    Add-Type -AssemblyName System.Web.Extensions
    $js = New-Object Web.Script.Serialization.JavaScriptSerializer
    $js.MaxJsonLength = [int]::MaxValue

    $root = $js.DeserializeObject($raw)
    $servers = $js.DeserializeObject($root['invServers'])['servers']
    $locs = $js.DeserializeObject($root['invLocations'])['data']['locations']
    if (-not $servers -or -not $locs) { throw 'The cached inventory is empty; run -Action launch first.' }

    # Ports per protocol, straight from the client's own map rather than a
    # hardcoded copy that would drift the next time Windscribe moves a port.
    $portMap = @{}
    $pmRoot = $js.DeserializeObject($root['portMap'])
    foreach ($e in $pmRoot['data']['portmap']) {
        $portMap[[string]$e['protocol']] = [pscustomobject]@{
            Use   = [string]$e['use']
            Ports = @($e['ports'] | ForEach-Object { [int]$_ })
        }
    }

    $dcCity = @{}
    $cityCountry = @{}
    foreach ($L in $locs) {
        foreach ($dc in $L['datacenters']) {
            if ($dc['city']) {
                $dcCity[[string]$dc['id']] = [string]$dc['city']
                $cityCountry[[string]$dc['city']] = [string]$L['name']
            }
        }
    }

    # Keep all three addresses: which one a probe wants depends on the protocol.
    $byCity = @{}
    foreach ($s in $servers) {
        $city = $dcCity[[string]$s['dc_id']]
        if (-not $city) { continue }
        if (-not $s['ip']) { continue }
        if (-not $byCity.ContainsKey($city)) { $byCity[$city] = New-Object Collections.ArrayList }
        [void] $byCity[$city].Add([pscustomobject]@{
            ip  = [string]$s['ip']
            ip2 = if ($s['ip2']) { [string]$s['ip2'] } else { [string]$s['ip'] }
            ip3 = if ($s['ip3']) { [string]$s['ip3'] } else { [string]$s['ip'] }
        })
    }
    [pscustomobject]@{ ByCity = $byCity; Country = $cityCountry; PortMap = $portMap }
}

# One scriptblock for all three probe kinds, because runspaces get no functions
# from here - whatever they need has to travel with them.
$WsProbe = {
    param($Ip, $Port, $Kind)

    if ($Kind -eq 'ike') {
        # An IKE_SA_INIT is the only honest way to ask a UDP port whether
        # anything is home: a bare datagram gets no answer from an open port or
        # a blackholed one alike. The proposal and the key exchange value do not
        # have to be acceptable - a responder that dislikes either still replies,
        # with INVALID_KE_PAYLOAD or NO_PROPOSAL_CHOSEN, and any reply carrying
        # our own initiator SPI back proves an IKE responder is listening.
        function BE16([int] $v) { [byte[]]@([byte](($v -shr 8) -band 0xFF), [byte]($v -band 0xFF)) }
        $rand = New-Object Random
        $spi = New-Object byte[] 8; $rand.NextBytes($spi)

        $tf = New-Object IO.MemoryStream
        # ENCR AES-CBC-256, PRF HMAC-SHA2-256, INTEG HMAC-SHA2-256-128, DH MODP-2048
        $tf.Write([byte[]]@(3,0),0,2); $tf.Write((BE16 12),0,2)
        $tf.Write([byte[]]@(1,0),0,2); $tf.Write((BE16 12),0,2)
        $tf.Write([byte[]]@(0x80,0x0E),0,2); $tf.Write((BE16 256),0,2)
        $tf.Write([byte[]]@(3,0),0,2); $tf.Write((BE16 8),0,2)
        $tf.Write([byte[]]@(2,0),0,2); $tf.Write((BE16 5),0,2)
        $tf.Write([byte[]]@(3,0),0,2); $tf.Write((BE16 8),0,2)
        $tf.Write([byte[]]@(3,0),0,2); $tf.Write((BE16 12),0,2)
        $tf.Write([byte[]]@(0,0),0,2); $tf.Write((BE16 8),0,2)
        $tf.Write([byte[]]@(4,0),0,2); $tf.Write((BE16 14),0,2)
        $tfb = $tf.ToArray()

        $prop = New-Object IO.MemoryStream
        $prop.Write([byte[]]@(0,0),0,2); $prop.Write((BE16 (8 + $tfb.Length)),0,2)
        $prop.Write([byte[]]@(1,1,0,4),0,4)
        $prop.Write($tfb,0,$tfb.Length)
        $propb = $prop.ToArray()

        $sa = New-Object IO.MemoryStream
        $sa.Write([byte[]]@(34,0),0,2); $sa.Write((BE16 (4 + $propb.Length)),0,2)
        $sa.Write($propb,0,$propb.Length)

        $kedata = New-Object byte[] 256; $rand.NextBytes($kedata)
        $ke = New-Object IO.MemoryStream
        $ke.Write([byte[]]@(40,0),0,2); $ke.Write((BE16 264),0,2)
        $ke.Write((BE16 14),0,2); $ke.Write([byte[]]@(0,0),0,2)
        $ke.Write($kedata,0,256)

        $ndata = New-Object byte[] 32; $rand.NextBytes($ndata)
        $no = New-Object IO.MemoryStream
        $no.Write([byte[]]@(0,0),0,2); $no.Write((BE16 36),0,2)
        $no.Write($ndata,0,32)

        $body = $sa.ToArray() + $ke.ToArray() + $no.ToArray()
        $total = 28 + $body.Length
        $h = New-Object IO.MemoryStream
        $h.Write($spi,0,8)
        $h.Write((New-Object byte[] 8),0,8)          # responder SPI, zero
        $h.Write([byte[]]@(33,0x20,34,0x08),0,4)     # SA, v2.0, IKE_SA_INIT, initiator
        $h.Write([byte[]]@(0,0,0,0),0,4)             # message id
        $h.Write([byte[]]@([byte](($total -shr 24) -band 0xFF), [byte](($total -shr 16) -band 0xFF),
                           [byte](($total -shr 8) -band 0xFF), [byte]($total -band 0xFF)),0,4)
        $pkt = $h.ToArray() + $body

        # Retransmit like a real initiator would. UDP recovers nothing on its
        # own, and a scan running thousands of probes at once loses datagrams to
        # its own load - a single shot marked most of the fleet dead in one run
        # and alive in another. Same SPI and same message each time, which is
        # what a retransmission is.
        $ep = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        foreach ($attempt in 1..3) {
            $u = New-Object Net.Sockets.UdpClient
            try {
                $u.Client.ReceiveTimeout = 2500
                [void] $u.Send($pkt, $pkt.Length, $Ip, $Port)
                $r = $u.Receive([ref] $ep)
                if ($r.Length -lt 28) { continue }
                $match = $true
                for ($i = 0; $i -lt 8; $i++) { if ($r[$i] -ne $spi[$i]) { $match = $false; break } }
                if ($match -and $r[18] -eq 34) { return 1 }
            }
            catch { }
            finally { $u.Close() }
        }
        return 0
    }

    $c = New-Object Net.Sockets.TcpClient
    try {
        if (-not $c.ConnectAsync($Ip, $Port).Wait(4000)) { return 0 }
        if ($Kind -eq 'tcp') { return 1 }
        $ssl = New-Object Net.Security.SslStream($c.GetStream(), $false, { $true })
        try {
            if ($ssl.AuthenticateAsClientAsync('www.microsoft.com').Wait(5000)) { return 1 }
            return 0
        }
        catch {
            if ($_.Exception.ToString() -match 'forcibly closed|reset|aborted') { return 0 }
            return 1
        }
        finally { $ssl.Dispose() }
    }
    catch { return 0 }
    finally { $c.Close() }
}

function Invoke-WsScan {
    param($Inventory, [string[]] $Protocols, [switch] $All)

    $byCity = $Inventory.ByCity
    $take   = if ($All) { 99 } else { $ServersPerCity }

    $plan = foreach ($name in $Protocols) {
        $spec = $ProtocolProbes[$name]
        if (-not $spec.Kind) { continue }
        $map = $Inventory.PortMap[$spec.Map]
        if (-not $map) { Write-Warn "the client's port map lists nothing for $name; skipping."; continue }
        $ports = if ($All) { $map.Ports } else { @($map.Ports | Where-Object { $spec.Fast -contains $_ }) }
        if (-not $ports) { $ports = @($map.Ports | Select-Object -First 1) }
        [pscustomobject]@{
            Name  = $name
            Kind  = $spec.Kind
            Field = switch ($map.Use) { 'ip2' { 'ip2' } 'ip3' { 'ip3' } default { 'ip' } }
            Ports = $ports
        }
    }
    if (-not $plan) { return @() }

    $tasks = foreach ($city in $byCity.Keys) {
        foreach ($srv in ($byCity[$city] | Select-Object -First $take)) {
            foreach ($pr in $plan) {
                foreach ($p in $pr.Ports) {
                    [pscustomobject]@{ City = $city; Ip = $srv.($pr.Field); Port = $p
                                       Kind = $pr.Kind; Protocol = $pr.Name }
                }
            }
        }
    }

    foreach ($pr in $plan) { Write-Info ("{0,-9} -> {1} on ports {2}" -f $pr.Name, $pr.Field, ($pr.Ports -join ', ')) }
    Write-Info "$($byCity.Count) cities, $(@($tasks).Count) probes."
    Write-Info 'Nothing connects - this only opens a handshake and closes it again.'
    Write-Host ''

    # UDP goes in its own pass, at a fraction of the width. A datagram that is
    # lost is simply gone, and thousands of concurrent TCP connects lose enough
    # of them to change the answer: the same fleet that reported 119 reachable
    # IKEv2 cities on its own reported none at all when it shared a run with the
    # TCP probes. Retransmission alone did not close that gap; not competing
    # with the TCP flood does.
    $total = @($tasks).Count
    $spin  = '|', '/', '-', '\'
    $i = 0
    $before = 0
    $hit = @{}

    foreach ($phase in @(
        @{ Tasks = @($tasks | Where-Object { $_.Kind -ne 'ike' }); Width = 64 },
        @{ Tasks = @($tasks | Where-Object { $_.Kind -eq 'ike' }); Width = 12 })) {

        if (-not $phase.Tasks) { continue }
        $pool = [RunspaceFactory]::CreateRunspacePool(1, $phase.Width)
        $pool.Open()
        $jobs = foreach ($t in $phase.Tasks) {
            $ps = [PowerShell]::Create()
            $ps.RunspacePool = $pool
            [void] $ps.AddScript($WsProbe).AddArgument($t.Ip).AddArgument($t.Port).AddArgument($t.Kind)
            [pscustomobject]@{ City = $t.City; Port = $t.Port; Protocol = $t.Protocol
                               Shell = $ps; Handle = $ps.BeginInvoke() }
        }

        while ($true) {
            $done = @($jobs | Where-Object { $_.Handle.IsCompleted }).Count
            $pct = [int](100 * ($before + $done) / $total)
            Write-Progress -Activity 'Probing Windscribe servers' -Status "$($before + $done) of $total probes done" -PercentComplete $pct
            Write-Host ("`r         $($spin[$i % 4])  $($before + $done) / $total probes   $pct%   ") -NoNewline -ForegroundColor DarkGray
            if ($done -eq @($jobs).Count) { break }
            $i++
            Start-Sleep -Milliseconds 250
        }

        foreach ($j in $jobs) {
            $ok = 0
            try { $ok = [int](@($j.Shell.EndInvoke($j.Handle))[0]) } catch { }
            $j.Shell.Dispose()
            if ($ok) {
                if (-not $hit.ContainsKey($j.City)) { $hit[$j.City] = @{} }
                if (-not $hit[$j.City].ContainsKey($j.Protocol)) {
                    $hit[$j.City][$j.Protocol] = New-Object Collections.Generic.HashSet[int]
                }
                [void] $hit[$j.City][$j.Protocol].Add($j.Port)
            }
        }
        $pool.Close(); $pool.Dispose()
        $before += @($phase.Tasks).Count
    }
    Write-Progress -Activity 'Probing Windscribe servers' -Completed
    Write-Host "`r         done - $total probes finished.                    " -ForegroundColor DarkGray

    $probed = @($plan.Name)
    $hit.GetEnumerator() | ForEach-Object {
        $c = $Inventory.Country[$_.Key]
        $row = [ordered]@{
            Country = if ($c) { $c } else { '?' }
            City    = $_.Key
        }
        $open = $_.Value
        foreach ($n in $probed) {
            $row[$n] = if ($open.ContainsKey($n)) { (($open[$n] | Sort-Object) -join ',') } else { '-' }
        }
        [pscustomobject] $row
    } | Sort-Object Country, City
}


#--------------------------------------------------------------- diagnostics

function Show-Diagnosis {
    param($Ws)

    Write-Head 'Windscribe'
    Write-Ok "installed at $($Ws.Dir)"
    if ($Ws.Running) { Write-Ok 'service is running' } else { Write-Warn 'service is not running' }

    if (-not (Test-GuiRunning)) {
        Write-Info 'client is not running - asking the CLI starts it, a few seconds'
    }
    $st = Get-CliStatus $Ws
    if ($st) {
        if ($st['Login state'] -eq 'Logged in') { Write-Ok 'signed in' }
        else { Write-Bad "not signed in ($($st['Login state']))" }
        if ($st['Connect state']) { Write-Info "connection: $($st['Connect state'])" }
        if ($st['Data usage'])    { Write-Info "data usage: $($st['Data usage'])" }
    }
    else { Write-Warn 'the CLI did not answer; is the client running?' }

    Write-Head 'Is the API actually blocked?'
    # Only a real "Connected: <place>" counts. The CLI also parks error text in
    # this field, and treating that as connected made the check lie.
    $vpnUp = $st -and $st['Connect state'] -match '^\s*\*?Connected'
    $direct = Test-TlsPath -Target $ApiHost
    switch ($direct) {
        'ok'      { Write-Ok  "$ApiHost is reachable." }
        'reset'   { Write-Bad "$ApiHost is reset during the TLS handshake." }
        'timeout' { Write-Bad "$ApiHost does not answer (timeout)." }
    }
    if ($vpnUp) {
        Write-Warn 'A VPN is connected, so that test went through the tunnel.'
        Write-Info 'Disconnect and re-run to see what your real network does.'
        $direct = 'unknown'
    }

    Write-Head 'Local proxy'
    Write-Info 'The client needs one to reach its API. Only the API travels'
    Write-Info 'through it - the tunnel goes out directly.'
    $found = Find-Proxy $Proxy
    if ($found) { Write-Ok "$($found.Url) reaches $ApiHost ($($found.Kind))" }
    else {
        Write-Bad 'No working local proxy found.'
        Write-Host ''
        Write-Info 'What to do:'
        Write-Info '  1. Open your proxy client - v2rayN, Clash, Nekoray, sing-box, Hiddify...'
        Write-Info '  2. Connect it and check a blocked site opens in your browser.'
        Write-Info '  3. Run this again.'
        Write-Host ''
        Write-Info 'On an unusual port, name it:  -Proxy http://127.0.0.1:PORT'
        Write-Info "Tried: $($ProxyPorts -join ', ')"
    }

    Write-Host ''
    $me = Split-Path $PSCommandPath -Leaf
    if     ($direct -eq 'ok')      { Write-Info 'The API is reachable - you probably do not need this.' }
    elseif ($direct -eq 'unknown') { Write-Info "Disconnect the VPN, then: .\$me" }
    elseif (-not $found)           { Write-Info 'Next: get a local proxy working, then run this again.' }
    else                           { Write-Info "Next: .\$me -Action launch" }
    Write-Host ''
    [pscustomobject]@{ Direct = $direct; Proxy = $found; Status = $st }
}


#----------------------------------------------------------------------- main

try {
    Write-Host ''
    Write-Host '  Unblock-Windscribe' -ForegroundColor White
    Write-Host '  starts the Windscribe client so its API calls can reach home' -ForegroundColor DarkGray
    Write-Host '  bypassVPN by @120hdd - github.com/120hdd/bypassVPN' -ForegroundColor DarkGray

    if ($Action -in 'diagnose', 'launch') {
        Write-Host ''
        Write-Host '  Before you start' -ForegroundColor White
        Write-Host '    - turn your proxy on and check it opens a blocked site' -ForegroundColor DarkGray
        Write-Host '    - do NOT set a proxy inside Windscribe Preferences: that one carries' -ForegroundColor DarkGray
        Write-Host '      the whole tunnel and would eat your proxy data' -ForegroundColor DarkGray
    }

    $ws = Get-Windscribe

    switch ($Action) {

        'diagnose' { [void] (Show-Diagnosis $ws) }

        'launch' {
            $d = Show-Diagnosis $ws
            if (-not $d.Proxy) { throw 'Cannot launch without a working local proxy.' }

            Write-Head 'Restarting the client with the proxy environment'
            Write-Info "ALL_PROXY / HTTP_PROXY / HTTPS_PROXY = $($d.Proxy.Url)"
            Start-WindscribeProxied $ws $d.Proxy.Url
            Write-Info 'waiting for it to talk to the API...'
            Start-Sleep -Seconds 25

            $after = Get-CliStatus $ws
            if ($after) {
                Write-Ok 'client is up'
                if ($after['Public IP'])  { Write-Info "public IP it now reports: $($after['Public IP'])" }
                if ($after['Data usage']) { Write-Info "data usage: $($after['Data usage'])" }
                Write-Info 'If those look current rather than stale, the API went through.'
            }
            else { Write-Warn 'the CLI did not answer yet; give the client a moment' }

            Write-Host ''
            Write-Head 'Done - what now'
            Write-Info 'Pick a location in the client and connect. Stealth is the one'
            Write-Info 'most likely to come up at all, but it wraps everything in TLS and'
            Write-Info 'pays for that in speed, so try IKEv2 first and keep Stealth for'
            Write-Info 'when nothing else connects.'
            Write-Info 'To measure that here rather than guess:  -Action protocols'
            Write-Host ''
            Write-Info 'This environment lives only as long as this client process, so'
            Write-Info 'start Windscribe from this script next time too. To get a desktop'
            Write-Info "shortcut that does it for you:  -Action shortcut"
            Write-Host ''
        }

        'scan' {
            Assert-NoTunnel
            $want = if ($Protocols) { Resolve-Protocols $Protocols } else { @('stealth') }

            # Say up front which of the chosen protocols a port scan cannot
            # answer for, rather than leaving them out of the table silently.
            $blind = @($want | Where-Object { -not $ProtocolProbes[$_].Kind })
            $probe = @($want | Where-Object { $ProtocolProbes[$_].Kind })
            if ($blind) {
                Write-Head 'Not scannable'
                foreach ($b in $blind) {
                    Write-Warn "$b cannot be port-scanned."
                    Write-Info $ProtocolProbes[$b].Why
                }
                Write-Host ''
                Write-Info 'These two can only be answered by connecting for real:'
                Write-Info "  .\$(Split-Path $PSCommandPath -Leaf) -Action protocols -Location `"Frankfurt`""
            }
            if (-not $probe) { Write-Host ''; break }

            Write-Head "Scanning cached server IPs for $($probe -join ', ')"
            $results = Invoke-WsScan (Get-WsInventory) -Protocols $probe -All:$Thorough
            Write-Host ''
            if (-not $results) {
                Write-Bad 'No city answered on any port.'
                Write-Info 'Try again later, or from another connection - mobile data often'
                Write-Info 'behaves differently from home internet.'
            }
            else {
                $cols = @('Country', 'City') + $probe
                $results | Format-Table $cols -AutoSize
                $total = @($results).Count
                Write-Info "$total locations answered, in $(@($results | Select-Object -ExpandProperty Country -Unique).Count) countries."
                $flat = @()
                foreach ($p in $probe) {
                    $n = @($results | Where-Object { $_.$p -ne '-' }).Count
                    Write-Info ("{0,-9} answered in {1} of them." -f $p, $n)
                    if ($total -gt 10 -and $n -ge [int]($total * 0.95)) { $flat += $p }
                }
                Write-Host ''
                # A column that says yes everywhere has ranked nothing. Better to
                # say so than to let a full column read as a list of good cities.
                if ($flat) {
                    Write-Warn "$($flat -join ', ') answered nearly everywhere, so that column cannot pick a city for you."
                    Write-Info 'It means the port is not filtered on this connection at all -'
                    Write-Info 'useful to know, but whatever stops a connection is happening'
                    Write-Info 'later in the handshake, where a port scan cannot see.'
                    Write-Host ''
                }
                Write-Info 'Each column lists the ports that answered for that protocol, and'
                Write-Info 'a dash means none did. Type a city name into the client and set'
                Write-Info 'the protocol to one its row still shows.'
                Write-Host ''
                Write-Info 'Read this as a filter, not a promise. A city missing from the list'
                Write-Info 'never connected, but a listed one still can fail - Manchester'
                Write-Info 'answered on every port here and refused all six protocols. More'
                Write-Info 'open ports is a mild sign of a healthier route, nothing more.'
                if (-not $Thorough) {
                    Write-Info 'This was the fast sample. Add -Thorough to probe every server'
                    Write-Info 'and port - it finds roughly three more cities and takes 2x longer.'
                }
            }
            Write-Host ''
        }

        'protocols' {
            Write-Head 'Testing every protocol'
            Write-Info 'Each one is a real connection, then a real transfer, so this'
            Write-Info 'takes several minutes and moves roughly 60 MB per protocol.'
            Write-Info 'Anything connected now will be dropped.'
            Write-Host ''

            if (-not (Test-GuiRunning)) {
                Write-Info 'client is not running - starting it, a few seconds'
            }
            $pre = Get-CliStatus $ws
            if ($pre -and $pre['Login state'] -ne 'Logged in') {
                Write-Warn "not signed in ($($pre['Login state'])) - connections will fail."
                Write-Info 'Run -Action launch first so the client can reach its API.'
                Write-Host ''
            }

            Write-Info 'measuring the line with no VPN first, as a yardstick'
            Disconnect-Windscribe $ws
            Start-Sleep -Seconds 3
            $base = Measure-Throughput
            Write-Info ("direct: up {0} Mbps, down {1} Mbps" -f $base.Up, $base.Down)
            Write-Host ''

            $where = if ($Location) { $Location } else { 'best' }
            Write-Info "location: $where"
            Write-Host ''

            $results = foreach ($p in $AllProtocols) {
                Write-Host ("         {0,-10} " -f $p) -NoNewline -ForegroundColor DarkGray
                $r = Connect-Windscribe $ws $Location $p
                if (-not $r.Connected) {
                    Write-Host 'failed' -ForegroundColor Red
                    [pscustomobject]@{ Protocol = $p; Works = $false; Up = $null; Down = $null; Detail = $r.Message }
                }
                else {
                    Write-Host 'connected' -NoNewline -ForegroundColor Green
                    Write-Host ' - measuring...' -NoNewline -ForegroundColor DarkGray
                    Start-Sleep -Seconds 3
                    $t = Measure-Throughput
                    Write-Host ("`r         {0,-10} " -f $p) -NoNewline -ForegroundColor DarkGray
                    Write-Host 'connected' -NoNewline -ForegroundColor Green
                    Write-Host ("   up {0,6} Mbps   down {1,6} Mbps          " -f
                        $(if ($null -ne $t.Up) { $t.Up } else { '-' }),
                        $(if ($null -ne $t.Down) { $t.Down } else { '-' })) -ForegroundColor Gray
                    [pscustomobject]@{ Protocol = $p; Works = $true; Up = $t.Up; Down = $t.Down; Detail = $r.Message }
                }
                Disconnect-Windscribe $ws
                Start-Sleep -Seconds 3
            }

            Write-Host ''
            $results | Format-Table `
                Protocol,
                @{ N = 'works'; E = { if ($_.Works) { 'yes' } else { 'no' } } },
                @{ N = 'up Mbps';   E = { if ($null -ne $_.Up)   { $_.Up }   else { '-' } }; A = 'right' },
                @{ N = 'down Mbps'; E = { if ($null -ne $_.Down) { $_.Down } else { '-' } }; A = 'right' } -AutoSize

            $good = @($results | Where-Object Works)
            if ($good) {
                Write-Ok "usable here: $(($good.Protocol) -join ', ')"
                $fastUp = @($good | Where-Object { $null -ne $_.Up } | Sort-Object Up -Descending)
                if ($fastUp) {
                    Write-Info ("best upload: {0} at {1} Mbps, against {2} Mbps on the bare line." -f
                        $fastUp[0].Protocol, $fastUp[0].Up, $base.Up)
                }
                Write-Info 'Set that one in Preferences -> Connection -> Connection Mode -> Manual.'
                Write-Host ''
                Write-Info 'Judge by the upload column. It is measured over a steady window'
                Write-Info 'and repeats closely. Download is one short transfer and a line'
                Write-Info 'that bursts before it throttles will swing it wildly, so read it'
                Write-Info 'as a rough sign of life rather than a ranking.'
                Write-Info 'One reading each, on one server, at one moment - treat a small gap'
                Write-Info 'between two protocols as noise and a large one as real.'
            }
            else {
                Write-Bad "Nothing connected at $where."
                Write-Info 'Six protocols failing together points at the location, not at any'
                Write-Info 'one of them. A location can pass the port scan and still refuse to'
                Write-Info 'come up, and the client picks "best" on latency alone.'
                Write-Host ''
                Write-Info 'Take a city from -Action scan and name it:'
                Write-Info "  .\$(Split-Path $PSCommandPath -Leaf) -Action protocols -Location `"Frankfurt`""
                Write-Host ''
                Write-Info 'If it still fails everywhere, run -Action launch first so the client'
                Write-Info 'can reach its API.'
                foreach ($r in $results) { Write-Info "$($r.Protocol): $($r.Detail)" }
            }
            Write-Host ''
        }

        'shortcut' {
            $d = Show-Diagnosis $ws
            if (-not $d.Proxy) { throw 'Cannot make the shortcut without a working local proxy.' }

            $lnk = Join-Path ([Environment]::GetFolderPath('Desktop')) $ShortcutName
            $shell = New-Object -ComObject WScript.Shell
            $sc = $shell.CreateShortcut($lnk)
            $sc.TargetPath = 'powershell.exe'
            $sc.Arguments = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Action launch"
            $sc.WorkingDirectory = Split-Path $PSCommandPath
            $sc.IconLocation = $ws.Gui
            $sc.Description = 'Start Windscribe with its API pointed at your local proxy'
            $sc.Save()

            Write-Head 'Shortcut'
            Write-Ok "created: $lnk"
            Write-Info 'Use it instead of the normal Windscribe icon from now on.'
            Write-Host ''
        }

        'revert' {
            Write-Head 'Reverting'
            $lnk = Join-Path ([Environment]::GetFolderPath('Desktop')) $ShortcutName
            if (Test-Path $lnk) { Remove-Item $lnk -Force; Write-Ok 'shortcut removed' }
            else { Write-Info 'no shortcut to remove' }

            Stop-WindscribeGui
            Start-Process $ws.Gui
            Write-Ok 'client restarted without the proxy environment'
            Write-Info 'Nothing else was ever changed - no registry, no admin, no settings.'
            Write-Host ''
        }
    }
}
catch {
    Write-Host ''
    Write-Bad $_.Exception.Message
    Write-Host ''
    exit 1
}
