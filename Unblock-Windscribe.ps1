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
    protocols  Connect with each protocol in turn and report which ones work.
    locations  Connect-test several locations and report which ones come up.
    shortcut   Put a desktop shortcut that always launches it the right way.
    revert     Remove that shortcut and start the client normally again.

.PARAMETER Proxy
    Proxy URL, e.g. http://127.0.0.1:10808. Omitted means auto-detect.

.PARAMETER Count
    How many locations -Action locations should try. Default 8.

.EXAMPLE
    .\Unblock-Windscribe.ps1
    .\Unblock-Windscribe.ps1 -Action launch
    .\Unblock-Windscribe.ps1 -Action protocols
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
    [ValidateSet('diagnose', 'launch', 'scan', 'protocols', 'locations', 'shortcut', 'revert')]
    [string] $Action = 'diagnose',

    [string] $Proxy,

    [ValidateRange(1, 40)]
    [int] $Count = 8,

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

function Get-CliStatus {
    param($Ws)
    if (-not (Test-Path $Ws.Cli)) { return $null }
    $out = & $Ws.Cli status 2>$null
    if (-not $out) { return $null }
    $h = @{}
    foreach ($line in $out) {
        if ($line -match '^\s*([^:]+):\s*(.+?)\s*$') { $h[$Matches[1].Trim()] = $Matches[2].Trim() }
    }
    $h
}


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

function Start-WindscribeProxied {
    param($Ws, [string] $ProxyUrl)

    Get-Process Windscribe -ErrorAction SilentlyContinue | Stop-Process -Force
    Start-Sleep -Seconds 4

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

function Connect-Windscribe {
    param($Ws, [string] $Target, [string] $Protocol, [int] $TimeoutSec = 70)
    $cliArgs = @('connect')
    if ($Target) { $cliArgs += $Target } else { $cliArgs += 'best' }
    if ($Protocol) { $cliArgs += $Protocol }

    $job = Start-Job { param($exe, $a) & $exe @a 2>&1 } -ArgumentList $Ws.Cli, $cliArgs
    $ok = Wait-Job $job -Timeout $TimeoutSec
    $out = if ($ok) { Receive-Job $job } else { $null }
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    $last = @($out) | Where-Object { $_ } | Select-Object -Last 1
    [pscustomobject]@{
        Connected = ("$last" -match '^\s*\*?Connected')
        Message   = "$last"
    }
}


#------------------------------------------------------------- region scan

# Stealth is stunnel, so every one of these ports terminates a real TLS server
# on the address in the server's ip3 field. Probing one port is not enough:
# a location can be dead on 443 and perfectly usable on 22 or 8443, which is
# exactly how an earlier single-port version of this scan produced a confident
# and wrong answer.
$StealthPorts     = 443, 587, 21, 22, 80, 123, 143, 3306, 8080, 54783, 8443
$StealthPortsFast = 443, 22, 123, 587, 8443, 21
$ServersPerCity   = 3

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
        throw 'No cached server inventory found. Start the client through -Action launch, let it load, then retry.'
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

    $dcCity = @{}
    foreach ($L in $locs) {
        foreach ($dc in $L['datacenters']) {
            if ($dc['city']) { $dcCity[[string]$dc['id']] = [string]$dc['city'] }
        }
    }

    $byCity = @{}
    foreach ($s in $servers) {
        $city = $dcCity[[string]$s['dc_id']]
        if (-not $city) { continue }
        $ip = if ($s['ip3']) { $s['ip3'] } else { $s['ip'] }
        if (-not $ip) { continue }
        if (-not $byCity.ContainsKey($city)) { $byCity[$city] = New-Object Collections.ArrayList }
        [void] $byCity[$city].Add([string]$ip)
    }
    $byCity
}

function Invoke-WsScan {
    param([hashtable] $ByCity, [switch] $All)

    $ports = if ($All) { $StealthPorts } else { $StealthPortsFast }
    $take  = if ($All) { 99 } else { $ServersPerCity }

    $tasks = foreach ($city in $ByCity.Keys) {
        foreach ($ip in ($ByCity[$city] | Select-Object -First $take)) {
            foreach ($p in $ports) { [pscustomobject]@{ City = $city; Ip = $ip; Port = $p } }
        }
    }
    Write-Info "$($ByCity.Count) cities, $($tasks.Count) probes on Stealth ports $($ports -join ', ')."
    Write-Info 'A city counts as usable if any one of its servers answers on any port.'
    Write-Host ''

    $probe = {
        param($Ip, $Port)
        $c = New-Object Net.Sockets.TcpClient
        try {
            if (-not $c.ConnectAsync($Ip, $Port).Wait(4000)) { return 0 }
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

    $pool = [RunspaceFactory]::CreateRunspacePool(1, 64)
    $pool.Open()
    $jobs = foreach ($t in $tasks) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void] $ps.AddScript($probe).AddArgument($t.Ip).AddArgument($t.Port)
        [pscustomobject]@{ City = $t.City; Port = $t.Port; Shell = $ps; Handle = $ps.BeginInvoke() }
    }

    $total = $jobs.Count
    $spin = '|', '/', '-', '\'
    $i = 0
    while ($true) {
        $done = @($jobs | Where-Object { $_.Handle.IsCompleted }).Count
        $pct = [int](100 * $done / $total)
        Write-Progress -Activity 'Probing Windscribe servers' -Status "$done of $total probes done" -PercentComplete $pct
        Write-Host ("`r         $($spin[$i % 4])  $done / $total probes   $pct%   ") -NoNewline -ForegroundColor DarkGray
        if ($done -eq $total) { break }
        $i++
        Start-Sleep -Milliseconds 250
    }
    Write-Progress -Activity 'Probing Windscribe servers' -Completed
    Write-Host "`r         done - $total probes finished.                    " -ForegroundColor DarkGray

    $hit = @{}
    foreach ($j in $jobs) {
        $ok = 0
        try { $ok = [int](@($j.Shell.EndInvoke($j.Handle))[0]) } catch { }
        $j.Shell.Dispose()
        if ($ok) {
            if (-not $hit.ContainsKey($j.City)) { $hit[$j.City] = New-Object Collections.Generic.HashSet[int] }
            [void] $hit[$j.City].Add($j.Port)
        }
    }
    $pool.Close(); $pool.Dispose()

    $hit.GetEnumerator() | ForEach-Object {
        [pscustomobject]@{
            City  = $_.Key
            Ports = (($_.Value | Sort-Object) -join ',')
        }
    } | Sort-Object City
}


#--------------------------------------------------------------- diagnostics

function Show-Diagnosis {
    param($Ws)

    Write-Head 'Windscribe'
    Write-Ok "installed at $($Ws.Dir)"
    if ($Ws.Running) { Write-Ok 'service is running' } else { Write-Warn 'service is not running' }

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
            Write-Info 'Pick a location in the client and connect. Set the protocol to'
            Write-Info 'Stealth if you are not sure - it survives censorship best here.'
            Write-Host ''
            Write-Info 'This environment lives only as long as this client process, so'
            Write-Info 'start Windscribe from this script next time too. To get a desktop'
            Write-Info "shortcut that does it for you:  -Action shortcut"
            Write-Host ''
        }

        'scan' {
            Assert-NoTunnel
            Write-Head 'Scanning cached server IPs'
            $results = Invoke-WsScan (Get-WsInventory) -All:$Thorough
            Write-Host ''
            if (-not $results) {
                Write-Bad 'No city answered on any Stealth port.'
                Write-Info 'Try again later, or from another connection - mobile data often'
                Write-Info 'behaves differently from home internet.'
            }
            else {
                $results | Format-Table City, @{ N = 'open stealth ports'; E = { $_.Ports } } -AutoSize
                Write-Info "$(@($results).Count) cities answered."
                Write-Host ''
                Write-Info 'Type one of these city names into the client and set the protocol'
                Write-Info 'to Stealth. Checked against real connections, a city missing from'
                Write-Info 'this list never worked, while roughly one listed city in six still'
                Write-Info 'fails to come up - so if one does not connect, take the next.'
                Write-Info 'More open ports is a mild sign of a healthier route, nothing more.'
                if (-not $Thorough) {
                    Write-Info 'This was the fast sample. Add -Thorough to probe every server'
                    Write-Info 'and port - it finds roughly three more cities and takes 2x longer.'
                }
            }
            Write-Host ''
        }

        'protocols' {
            Write-Head 'Testing every protocol'
            Write-Info 'Each one is a real connection attempt, so this takes a few minutes.'
            Write-Info 'Anything already connected will be dropped and reconnected.'
            Write-Host ''

            $results = foreach ($p in $AllProtocols) {
                Write-Host ("         trying {0,-10} " -f $p) -NoNewline -ForegroundColor DarkGray
                $r = Connect-Windscribe $ws $null $p
                if ($r.Connected) { Write-Host 'connected' -ForegroundColor Green }
                else              { Write-Host 'failed'    -ForegroundColor Red }
                [pscustomobject]@{ Protocol = $p; Works = $r.Connected; Detail = $r.Message }
                Start-Sleep -Seconds 2
            }

            & $ws.Cli disconnect 2>$null | Out-Null
            Write-Host ''
            $results | Format-Table Protocol, @{ N = 'works'; E = { if ($_.Works) { 'yes' } else { 'no' } } }, Detail -AutoSize

            $good = @($results | Where-Object Works | Select-Object -ExpandProperty Protocol)
            if ($good) {
                Write-Ok "usable here: $($good -join ', ')"
                Write-Info "Set one of these in the client. '$($good[0])' is the first that worked."
            }
            else {
                Write-Bad 'None connected.'
                Write-Info 'Launch the client through this script first so it can reach the API,'
                Write-Info 'then try again.'
            }
            Write-Host ''
        }

        'locations' {
            Write-Head "Connect-testing locations"
            Write-Info 'Probing server IPs turned out not to predict anything for Windscribe -'
            Write-Info 'the client fails over across many servers and ports by itself, so the'
            Write-Info 'only honest test is to actually connect. That makes this slow.'
            Write-Host ''

            $names = @(& $ws.Cli locations 2>$null | Where-Object { $_ -match '\S' })
            if (-not $names) {
                Write-Bad 'The client returned no locations.'
                Write-Info 'That itself means the API is not reachable - run -Action launch first.'
                break
            }
            $pick = $names | Select-Object -First $Count
            Write-Info "$($names.Count) locations known, trying the first $($pick.Count)."
            Write-Host ''

            $results = foreach ($n in $pick) {
                $short = ($n -split '\s{2,}')[0].Trim()
                Write-Host ("         {0,-24} " -f $short) -NoNewline -ForegroundColor DarkGray
                $r = Connect-Windscribe $ws $short 'stealth'
                if ($r.Connected) { Write-Host 'connected' -ForegroundColor Green }
                else              { Write-Host 'failed'    -ForegroundColor Red }
                [pscustomobject]@{ Location = $short; Works = $r.Connected }
                Start-Sleep -Seconds 2
            }

            & $ws.Cli disconnect 2>$null | Out-Null
            Write-Host ''
            $results | Format-Table Location, @{ N = 'works'; E = { if ($_.Works) { 'yes' } else { 'no' } } } -AutoSize
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

            Get-Process Windscribe -ErrorAction SilentlyContinue | Stop-Process -Force
            Start-Sleep -Seconds 3
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
