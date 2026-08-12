<#
.SYNOPSIS
    Gets the ExpressVPN client connecting again on networks that block its API.

.DESCRIPTION
    On some filtered networks the ExpressVPN tunnel servers are still reachable
    but the client's API host (cp.expressapisv2.net) is not: DPI resets the TLS
    handshake on sight of the SNI. The client can then never fetch the server
    list, so it hangs in "Connecting" forever.

    The Rust SDK inside expressvpn-sdklib.dll is built on reqwest, which honours
    the standard proxy environment variables. This script points *only* the
    ExpressVPN service at a local proxy you already have working (v2rayN, Clash,
    Nekoray, sing-box, Hiddify, ...) by writing a per-service environment block.
    Nothing else on the machine is affected: system proxy, hosts file and DNS
    settings are left alone.

    Only the small API calls take the detour. The tunnel still dials the VPN
    server directly, so throughput and your proxy's data allowance are untouched.

.PARAMETER Action
    diagnose  Report what is broken and whether a usable proxy exists (default).
    apply     Write the per-service proxy env block and restart the service.
    revert    Remove it and restart the service.
    scan      Probe every cached server IP and list reachable regions.
    test      Connect to a region and report the exit IP.

.PARAMETER Proxy
    Proxy URL to use, e.g. http://127.0.0.1:10808 or socks5://127.0.0.1:1080.
    Omit to auto-detect from the usual local ports.

.PARAMETER Region
    Region slug for -Action test. Defaults to the first region that scans clean.

.EXAMPLE
    .\Unblock-ExpressVPN.ps1
    .\Unblock-ExpressVPN.ps1 -Action apply
    .\Unblock-ExpressVPN.ps1 -Action scan
    .\Unblock-ExpressVPN.ps1 -Action test -Region slovenia
    .\Unblock-ExpressVPN.ps1 -Action revert

.NOTES
    Your proxy must be running whenever ExpressVPN *connects*. Once the tunnel
    is up it is self-sustaining.

    Part of bypassVPN by @120hdd.

.LINK
    https://github.com/120hdd/bypassVPN
#>
[CmdletBinding()]
param(
    [ValidateSet('diagnose', 'apply', 'revert', 'scan', 'test')]
    [string] $Action = 'diagnose',

    [string] $Proxy,
    [string] $Region,

    [ValidateRange(1, 10)]
    [int] $ProbesPerLocation = 3,

    [switch] $Elevated,

    # Set on the elevated child so its output can be replayed in the console the
    # user is actually looking at; the UAC window closes too fast to read.
    [string] $ResultFile
)

$ErrorActionPreference = 'Stop'

$ApiHost     = 'cp.expressapisv2.net'
$ServiceName = 'ExpressVpnService'
$RegKey      = "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName"

# Local proxy ports worth trying, in rough order of popularity.
$ProxyPorts = 10808, 10809, 7890, 7891, 2080, 2081, 1080, 1081, 8889, 8080, 20171, 12334


#--------------------------------------------------------------------- output

function Add-Result { param($t) if ($ResultFile) { Add-Content -LiteralPath $ResultFile -Value $t -Encoding UTF8 } }

function Write-Head { param($t) Write-Host ''; Write-Host "  $t" -ForegroundColor Cyan; Write-Host "  $('-' * $t.Length)" -ForegroundColor DarkCyan; Add-Result ''; Add-Result "  $t"; Add-Result "  $('-' * $t.Length)" }
function Write-Ok   { param($t) Write-Host '  [ ok ] ' -ForegroundColor Green  -NoNewline; Write-Host $t; Add-Result "  [ ok ] $t" }
function Write-Bad  { param($t) Write-Host '  [fail] ' -ForegroundColor Red    -NoNewline; Write-Host $t; Add-Result "  [fail] $t" }
function Write-Warn { param($t) Write-Host '  [warn] ' -ForegroundColor Yellow -NoNewline; Write-Host $t; Add-Result "  [warn] $t" }
function Write-Info { param($t) Write-Host '         ' -NoNewline; Write-Host $t -ForegroundColor Gray; Add-Result "         $t" }


#---------------------------------------------------------------- environment

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Admin {
    if (Test-Admin) { return }
    if ($Elevated) { throw 'Elevation was requested but the new process is still not admin.' }

    Write-Info 'This action needs administrator rights - accept the UAC prompt.'
    $relay = Join-Path ([IO.Path]::GetTempPath()) "unblock-xv-$PID.log"
    Remove-Item $relay -ErrorAction SilentlyContinue

    $argv = @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', "`"$PSCommandPath`"",
        '-Action', $Action, '-Elevated',
        '-ResultFile', "`"$relay`""
    )
    if ($Proxy)  { $argv += @('-Proxy', $Proxy) }
    if ($Region) { $argv += @('-Region', $Region) }

    try {
        $p = Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList $argv -PassThru -Wait
    }
    catch {
        Write-Bad 'UAC was declined, so nothing was changed.'
        exit 1
    }

    if (Test-Path $relay) {
        Get-Content $relay | ForEach-Object {
            if    ($_ -match '^\s*\[ ok \]')  { Write-Host $_ -ForegroundColor Green }
            elseif ($_ -match '^\s*\[fail\]') { Write-Host $_ -ForegroundColor Red }
            elseif ($_ -match '^\s*\[warn\]') { Write-Host $_ -ForegroundColor Yellow }
            else                              { Write-Host $_ -ForegroundColor Gray }
        }
        Remove-Item $relay -ErrorAction SilentlyContinue
    }
    Write-Host ''
    exit $p.ExitCode
}

function Get-ExpressVpn {
    $svc = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'" -ErrorAction SilentlyContinue
    if (-not $svc) { throw "The $ServiceName service was not found. Is the ExpressVPN Windows app installed?" }

    $dir = Split-Path ($svc.PathName -replace '^"|"$', '')
    [pscustomobject]@{
        Dir     = $dir
        Ctl     = Join-Path $dir 'expressvpnctl.exe'
        SdkLog   = Join-Path $dir 'data\csdk.log'
        DataJson = Join-Path $dir 'data\data.json'
        Running = $svc.State -eq 'Running'
    }
}


#------------------------------------------------------------------- probing

# TCP connect + TLS handshake. On a filtered path the SYN usually gets through
# and the reset arrives on the ClientHello, so a bare connect proves nothing.
function Test-TlsPath {
    param(
        [string] $Target,                 # ip or hostname to dial
        [string] $Sni = $null,            # name to put in the ClientHello
        [int]    $Port = 443,
        [int]    $TimeoutMs = 6000
    )
    if (-not $Sni) { $Sni = $Target }
    $client = New-Object Net.Sockets.TcpClient
    try {
        if (-not $client.ConnectAsync($Target, $Port).Wait($TimeoutMs)) { return 'timeout' }
        $ssl = New-Object Net.Security.SslStream(
            $client.GetStream(), $false, { $true })
        try {
            if ($ssl.AuthenticateAsClientAsync($Sni).Wait($TimeoutMs)) { return 'ok' }
            return 'timeout'
        }
        catch {
            # An alert or a reset both mean bytes came back; only a reset with
            # nothing behind it counts as filtered.
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

        $s.Write([byte[]](5, 1, 0), 0, 3)                 # greet, no auth
        $r = New-Object byte[] 2
        if ($s.Read($r, 0, 2) -ne 2 -or $r[0] -ne 5 -or $r[1] -ne 0) { return $false }

        $name = [Text.Encoding]::ASCII.GetBytes($ApiHost)
        $req  = [byte[]](5, 1, 0, 3) + [byte] $name.Length + $name + [byte[]](1, 187)
        $s.Write($req, 0, $req.Length)                    # CONNECT host:443
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
        foreach ($p in $ProxyPorts) {
            $candidates += [pscustomobject]@{ Scheme = $null; Host = '127.0.0.1'; Port = $p }
        }
    }

    foreach ($c in $candidates) {
        if ($c.Scheme -ne 'socks5' -and (Test-HttpProxy $c.Host $c.Port)) {
            return [pscustomobject]@{ Url = "http://$($c.Host):$($c.Port)"; Kind = 'http' }
        }
        if ($c.Scheme -ne 'http' -and $c.Scheme -ne 'https' -and (Test-Socks5Proxy $c.Host $c.Port)) {
            return [pscustomobject]@{ Url = "socks5://$($c.Host):$($c.Port)"; Kind = 'socks5' }
        }
    }
    return $null
}


#--------------------------------------------------------------- the registry

function Get-ServiceProxy {
    (Get-ItemProperty $RegKey -Name Environment -ErrorAction SilentlyContinue).Environment
}

function Set-ServiceProxy {
    param([string] $Url)
    $values = if ($Url -like 'socks5://*') {
        @("ALL_PROXY=$Url", "HTTPS_PROXY=$Url", "HTTP_PROXY=$Url", 'NO_PROXY=127.0.0.1,localhost')
    }
    else {
        @("HTTPS_PROXY=$Url", "HTTP_PROXY=$Url", "ALL_PROXY=$Url", 'NO_PROXY=127.0.0.1,localhost')
    }
    New-ItemProperty -Path $RegKey -Name Environment -PropertyType MultiString -Value $values -Force | Out-Null
    $values
}

# The daemon often refuses a polite stop while the GUI client is attached, so
# poll for it, then take the process down by hand rather than give up with the
# new environment written but never loaded.
function Restart-Daemon {
    $svc = Get-Service $ServiceName

    if ($svc.Status -ne 'Stopped') {
        try { Stop-Service $ServiceName -Force -ErrorAction SilentlyContinue } catch { }
        for ($i = 0; $i -lt 30 -and (Get-Service $ServiceName).Status -ne 'Stopped'; $i++) {
            Start-Sleep -Seconds 1
        }
    }

    if ((Get-Service $ServiceName).Status -ne 'Stopped') {
        Write-Warn 'the service would not stop on request; ending its process directly'
        $svcPid = (Get-CimInstance Win32_Service -Filter "Name='$ServiceName'").ProcessId
        if ($svcPid) { Stop-Process -Id $svcPid -Force -ErrorAction SilentlyContinue }
        for ($i = 0; $i -lt 20 -and (Get-Service $ServiceName).Status -ne 'Stopped'; $i++) {
            Start-Sleep -Seconds 1
        }
    }

    try { Start-Service $ServiceName -ErrorAction SilentlyContinue } catch { }
    for ($i = 0; $i -lt 30 -and (Get-Service $ServiceName).Status -ne 'Running'; $i++) {
        Start-Sleep -Seconds 1
    }
    Start-Sleep -Seconds 3
    (Get-Service $ServiceName).Status
}


#---------------------------------------------------------------- region scan

function Read-SharedText {
    # These files are held open by the daemon, so the handle has to be shared.
    param([string] $Path)
    $fs = New-Object IO.FileStream($Path, [IO.FileMode]::Open,
        [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try { (New-Object IO.StreamReader($fs)).ReadToEnd() } finally { $fs.Dispose() }
}

# Preferred source: the client's own persistent region cache, which carries the
# official slug for each region. The SDK log is only a fallback -- it rotates,
# so it can hold anything from the full list to a handful of entries.
function Get-CachedLocations {
    param($Xv)

    if (Test-Path $Xv.DataJson) {
        try {
            $regions = (Read-SharedText $Xv.DataJson | ConvertFrom-Json).cachedModernRegionsList.regions
            $list = foreach ($r in $regions) {
                if ($r.test_ips -and -not $r.offline) {
                    [pscustomobject]@{ Slug = $r.slug; Name = $r.name; Ips = @($r.test_ips) }
                }
            }
            if ($list) { return @($list) }
        }
        catch { Write-Warn "could not read $($Xv.DataJson): $($_.Exception.Message)" }
    }

    if (-not (Test-Path $Xv.SdkLog)) {
        throw 'No cached region data found. Open the ExpressVPN app, let it load the location list, then retry.'
    }
    Write-Warn 'Falling back to the SDK log; it may only hold part of the region list.'
    $rx = [regex]::new('"name":\s*"([^"]+)",(.{0,900}?)"test_ips":\s*\[(.*?)\]', 'Singleline')
    $map = @{}
    foreach ($m in $rx.Matches((Read-SharedText $Xv.SdkLog))) {
        $ips = [regex]::Matches($m.Groups[3].Value, '"([0-9.]+)"') | ForEach-Object { $_.Groups[1].Value }
        if ($ips) {
            $name = $m.Groups[1].Value
            if (-not $map.ContainsKey($name)) { $map[$name] = New-Object Collections.Generic.HashSet[string] }
            foreach ($ip in $ips) { [void] $map[$name].Add($ip) }
        }
    }
    @(foreach ($k in $map.Keys) {
        [pscustomobject]@{ Slug = (ConvertTo-Slug $k); Name = $k; Ips = @($map[$k]) }
    })
}

function Get-VpnState {
    param($Xv)
    if (-not (Test-Path $Xv.Ctl)) { return $null }
    & $Xv.Ctl get connectionstate 2>$null | Select-Object -First 1
}

# Probing from inside the tunnel makes every server look reachable, which is
# worse than useless - it produces a confident, completely wrong list.
function Assert-Disconnected {
    param($Xv)
    if ((Get-VpnState $Xv) -ne 'Connected') { return }
    Write-Host ''
    Write-Bad 'The VPN is connected, so every probe would travel through the tunnel'
    Write-Info 'and every region would look reachable. Disconnect first:'
    Write-Info "  & '$($Xv.Ctl)' disconnect"
    Write-Host ''
    exit 1
}

function ConvertTo-Slug {
    param([string] $Name)
    ($Name.ToLower() -replace '\s*-\s*', '-' -replace '\s+', '-' -replace '-+', '-').Trim('-')
}

function Invoke-Scan {
    param([array] $Locations, [int] $Probes)

    $tasks = foreach ($loc in $Locations) {
        foreach ($ip in ($loc.Ips | Select-Object -First $Probes)) {
            [pscustomobject]@{ Slug = $loc.Slug; Name = $loc.Name; Ip = $ip }
        }
    }
    Write-Info "$($Locations.Count) locations, $($tasks.Count) probes."
    Write-Info 'Each probe opens a TLS handshake to one ExpressVPN server and watches'
    Write-Info 'whether it is answered or reset. Expect one to two minutes.'
    Write-Host ''

    $probe = {
        param($Ip)
        $c = New-Object Net.Sockets.TcpClient
        try {
            if (-not $c.ConnectAsync($Ip, 443).Wait(5000)) { return 0 }
            $ssl = New-Object Net.Security.SslStream($c.GetStream(), $false, { $true })
            try {
                if ($ssl.AuthenticateAsClientAsync('www.microsoft.com').Wait(6000)) { return 1 }
                return 0
            }
            catch {
                if ($_.Exception.ToString() -match 'forcibly closed|reset|aborted') { return 0 }
                return 1        # the server answered, even if it answered badly
            }
            finally { $ssl.Dispose() }
        }
        catch { return 0 }
        finally { $c.Close() }
    }

    $pool = [RunspaceFactory]::CreateRunspacePool(1, 48)
    $pool.Open()
    $jobs = foreach ($t in $tasks) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void] $ps.AddScript($probe).AddArgument($t.Ip)
        [pscustomobject]@{ Slug = $t.Slug; Name = $t.Name; Shell = $ps; Handle = $ps.BeginInvoke() }
    }

    # Nothing is collected until every probe finishes, so without this the user
    # stares at a frozen console for a minute and assumes it crashed.
    $total = $jobs.Count
    $spin = '|', '/', '-', '\'
    $i = 0
    while ($true) {
        $done = @($jobs | Where-Object { $_.Handle.IsCompleted }).Count
        $pct = [int](100 * $done / $total)
        Write-Progress -Activity 'Probing ExpressVPN servers' `
            -Status "$done of $total probes done" -PercentComplete $pct
        Write-Host ("`r         $($spin[$i % 4])  $done / $total probes   $pct%   ") -NoNewline -ForegroundColor DarkGray
        if ($done -eq $total) { break }
        $i++
        Start-Sleep -Milliseconds 250
    }
    Write-Progress -Activity 'Probing ExpressVPN servers' -Completed
    Write-Host "`r         done - $total probes finished.                    " -ForegroundColor DarkGray

    $score = @{}
    foreach ($j in $jobs) {
        $ok = 0
        try { $ok = [int](@($j.Shell.EndInvoke($j.Handle))[0]) } catch { }
        $j.Shell.Dispose()
        if (-not $score.ContainsKey($j.Slug)) { $score[$j.Slug] = @{ Ok = 0; Total = 0; Name = $j.Name } }
        $score[$j.Slug].Ok += $ok
        $score[$j.Slug].Total++
    }
    $pool.Close(); $pool.Dispose()

    $score.GetEnumerator() |
        Where-Object { $_.Value.Ok -gt 0 } |
        ForEach-Object {
            [pscustomobject]@{
                Region   = $_.Key
                Location = $_.Value.Name
                Ok       = $_.Value.Ok
                Total    = $_.Value.Total
            }
        } | Sort-Object @{E = { $_.Ok / $_.Total }; D = $true }, Region
}


#--------------------------------------------------------------------- checks

function Show-Diagnosis {
    param($Xv)

    Write-Head 'ExpressVPN'
    Write-Ok "installed at $($Xv.Dir)"
    if ($Xv.Running) { Write-Ok 'daemon service is running' } else { Write-Warn 'daemon service is not running' }

    Write-Head 'Is the API actually blocked?'
    $vpnState = if (Test-Path $Xv.Ctl) { & $Xv.Ctl get connectionstate 2>$null | Select-Object -First 1 } else { $null }
    $direct = Test-TlsPath -Target $ApiHost
    switch ($direct) {
        'ok'      { Write-Ok  "$ApiHost is reachable." }
        'reset'   { Write-Bad "$ApiHost is reset during the TLS handshake (DPI blocking the SNI)." }
        'timeout' { Write-Bad "$ApiHost does not answer (timeout)." }
    }
    if ($vpnState -eq 'Connected') {
        # Everything is riding the tunnel right now, so this says nothing about
        # the underlying network.
        Write-Warn 'The VPN is connected, so that test went through the tunnel.'
        Write-Info 'Disconnect and re-run to see what your real network does.'
        $direct = 'unknown'
    }

    Write-Head 'Local proxy'
    Write-Info 'This fix works by lending ExpressVPN your existing proxy for its API'
    Write-Info 'calls only, so one has to be running and actually working.'
    $found = Find-Proxy $Proxy
    if ($found) {
        Write-Ok "$($found.Url) reaches $ApiHost ($($found.Kind))"
    }
    else {
        Write-Bad 'No working local proxy found.'
        Write-Host ''
        Write-Info 'What to do:'
        Write-Info '  1. Open your proxy client - v2rayN, Clash, Nekoray, sing-box, Hiddify...'
        Write-Info '  2. Connect it and check a blocked site opens in your browser.'
        Write-Info '     A client that is running but not connected will not help.'
        Write-Info '  3. Run this again.'
        Write-Host ''
        Write-Info 'If your proxy listens on an unusual port, name it yourself:'
        Write-Info '     -Proxy http://127.0.0.1:PORT     (or socks5://127.0.0.1:PORT)'
        Write-Info "Ports tried automatically: $($ProxyPorts -join ', ')"
    }

    Write-Head 'Fix status'
    $cur = Get-ServiceProxy
    if ($cur) {
        Write-Ok 'already applied:'
        $cur | ForEach-Object { Write-Info "  $_" }
    }
    else { Write-Info 'not applied yet' }

    Write-Host ''
    $me = Split-Path $PSCommandPath -Leaf
    if ($direct -eq 'ok') {
        Write-Info 'Nothing to do - this network reaches the API fine.'
    }
    elseif ($direct -eq 'unknown') {
        Write-Info "Disconnect the VPN, then: .\$me"
    }
    elseif (-not $found) {
        Write-Info 'Next: get a local proxy working, then re-run this script.'
    }
    elseif ($cur -and ($cur -join ' ') -match [regex]::Escape($found.Url)) {
        Write-Info 'The fix is in place and the proxy it points at is working.'
        Write-Info "Just connect from the app, or:  .\$me -Action test"
    }
    elseif ($cur) {
        Write-Info "The fix points at a different proxy than the one found."
        Write-Info "Re-point it with:  .\$me -Action apply"
    }
    else {
        Write-Info "Next: .\$me -Action apply"
    }
    Write-Host ''
    return [pscustomobject]@{ Direct = $direct; Proxy = $found; Applied = [bool]$cur }
}


#----------------------------------------------------------------------- main

try {
    Write-Host ''
    Write-Host '  Unblock-ExpressVPN' -ForegroundColor White
    Write-Host '  points the ExpressVPN daemon at a local proxy so it can reach its API' -ForegroundColor DarkGray
    Write-Host '  bypassVPN by @120hdd - github.com/120hdd/bypassVPN' -ForegroundColor DarkGray

    if ($Action -in 'diagnose', 'apply') {
        Write-Host ''
        Write-Host '  Before you start' -ForegroundColor White
        Write-Host '    - turn your proxy on (v2rayN / Clash / Nekoray / Hiddify / sing-box)' -ForegroundColor DarkGray
        Write-Host '      and make sure it actually opens a blocked site in your browser' -ForegroundColor DarkGray
        Write-Host '    - sign in to the ExpressVPN app at least once' -ForegroundColor DarkGray
        Write-Host '    - keep the proxy running whenever you connect ExpressVPN later' -ForegroundColor DarkGray
    }

    $xv = Get-ExpressVpn

    switch ($Action) {

        'diagnose' { [void] (Show-Diagnosis $xv) }

        'apply' {
            $d = Show-Diagnosis $xv
            if (-not $d.Proxy) { throw 'Cannot apply without a working local proxy.' }
            Assert-Admin

            Write-Head 'Applying'
            $vals = Set-ServiceProxy $d.Proxy.Url
            $vals | ForEach-Object { Write-Info $_ }
            Write-Ok "written to $RegKey\Environment"

            Write-Info 'restarting the daemon...'
            $state = Restart-Daemon
            if ($state -eq 'Running') { Write-Ok "service restarted ($state)" } else { Write-Bad "service is $state" }

            Write-Host ''
            Write-Head 'Done - what now'
            Write-Info 'Open the ExpressVPN app and connect. It should stop hanging on'
            Write-Info '"Connecting" and come up within a few seconds.'
            Write-Host ''
            Write-Info 'If it still hangs, the region you picked is probably blocked.'
            Write-Info 'Disconnect, then find one that works:'
            Write-Info "     menu option 3, or  -Action scan"
            Write-Host ''
            Write-Info 'Three things to remember:'
            Write-Info '  - keep your proxy running whenever ExpressVPN connects. Afterwards'
            Write-Info '    the tunnel stands on its own, and it does not spend your proxy'
            Write-Info '    data - only the tiny API calls go that way.'
            Write-Info '  - use the Lightway UDP protocol. On a censored line Lightway TCP'
            Write-Info '    connects but crawls; WireGuard and OpenVPN do not connect at all.'
            Write-Info '  - after a reboot, give the daemon about a minute before you hit'
            Write-Info '    Connect. It pulls its region list through the proxy first, and'
            Write-Info '    every attempt before that finishes just fails. You never need to'
            Write-Info '    run this tool again - the fix is permanent.'
            Write-Host ''
        }

        'revert' {
            Assert-Admin
            Write-Head 'Reverting'
            if (Get-ServiceProxy) {
                Remove-ItemProperty -Path $RegKey -Name Environment -Force
                Write-Ok 'removed the per-service proxy environment'
            }
            else { Write-Info 'nothing was applied' }
            $state = Restart-Daemon
            Write-Ok "service restarted ($state)"
            Write-Host ''
        }

        'scan' {
            Assert-Disconnected $xv
            Write-Head 'Scanning cached server IPs'
            $results = Invoke-Scan (Get-CachedLocations $xv) $ProbesPerLocation
            Write-Host ''
            if (-not $results) {
                Write-Bad 'No region answered. Every tunnel endpoint looks blocked right now.'
                Write-Host ''
                Write-Info 'This happens on the harshest days of filtering. Worth trying:'
                Write-Info '  - run it again in a few hours, or on another connection'
                Write-Info '    (mobile data often behaves differently from home internet)'
                Write-Info '  - open the ExpressVPN app once so it refreshes its server list'
            }
            else {
                $results | Format-Table Region, @{ N = 'probes'; E = { "$($_.Ok)/$($_.Total)" } }, Location -AutoSize
                Write-Info "$(@($results).Count) regions answered and should be usable."
                Write-Host ''
                Write-Info 'Being on this list is what matters. The probe score is noisy - a'
                Write-Info '1/3 region often connects perfectly, and a 3/3 one is not faster.'
                Write-Info 'Pick a nearby country for lower latency.'
                Write-Host ''
                Write-Info 'Set one in the ExpressVPN app, or from here:'
                Write-Info "     menu option 4, or  -Action test -Region $($results[0].Region)"
            }
            Write-Host ''
        }

        'test' {
            if (-not (Test-Path $xv.Ctl)) { throw "expressvpnctl.exe not found at $($xv.Ctl)" }
            if (-not $Region) {
                Assert-Disconnected $xv
                Write-Head 'No -Region given, scanning for one'
                $r = Invoke-Scan (Get-CachedLocations $xv) 2
                if (-not $r) { throw 'No reachable region found.' }
                $Region = $r[0].Region
                Write-Ok "picked $Region"
            }

            Write-Head "Connecting to $Region"
            & $xv.Ctl set protocol lightwayudp | Out-Null

            # A daemon that started moments ago has not pulled its region data
            # through the proxy yet, and every connect until it does just fails.
            # One quiet retry covers that instead of reporting a false problem.
            $state = $null
            foreach ($attempt in 1, 2) {
                & $xv.Ctl connect $Region | Out-Null
                for ($i = 0; $i -lt 25 -and $state -ne 'Connected'; $i++) {
                    Start-Sleep -Seconds 2
                    $state = (& $xv.Ctl get connectionstate 2>$null | Select-Object -First 1)
                }
                if ($state -eq 'Connected') { break }
                if ($attempt -eq 1) {
                    Write-Info 'no luck yet - the daemon may still be starting up, waiting 30s'
                    Start-Sleep -Seconds 30
                    $state = $null
                }
            }

            if ($state -ne 'Connected') {
                Write-Bad "still $state after two attempts."
                Write-Host ''
                Write-Info 'Usual reasons, in order of likelihood:'
                Write-Info "  - $Region is blocked here. Run a scan and pick another."
                Write-Info '  - your proxy is off, so the client cannot fetch the server list.'
                Write-Info '  - the fix is not applied yet - run the diagnose step and check.'
            }
            else {
                Write-Ok "connected ($state), protocol LightwayUdp"

                # A freshly established tunnel needs a few seconds before it
                # carries traffic; one failed lookup here means nothing.
                $ip = $null
                foreach ($attempt in 1..3) {
                    Start-Sleep -Seconds 5
                    try {
                        $ip = (Invoke-WebRequest 'https://api.ipify.org' -UseBasicParsing -TimeoutSec 15).Content.Trim()
                        break
                    }
                    catch { }
                }
                if ($ip) {
                    Write-Ok "exit IP: $ip"
                    Write-Info 'If that is not your real IP, you are through the tunnel.'
                }
                else {
                    Write-Warn 'connected, but the exit IP check did not answer.'
                    Write-Info 'Not necessarily broken - open a website and see. If nothing'
                    Write-Info 'loads, reconnect or pick another region.'
                }
            }
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
