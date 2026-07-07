# dig-dns runtime acceptance for Windows (PowerShell 7+).
#
# Starts `dig-dns serve` (gateway + DNS) unprivileged on high loopback ports and proves the
# runtime end-to-end, no installer / OS config needed:
#   - `dig-dns doctor` reports a live path (exit 0);
#   - the /.dig/ control endpoints answer (resolve-probe 204, proxy.pac PROXY line, health 200);
#   - an absolute-form proxy to a non-.dig target is refused with 403 (never an open proxy);
#   - a syntactically invalid .dig host is a fast 404;
#   - the DNS responder answers (via `dig-dns doctor`'s dns_direct check).
#
# CONTENT + pinned-vs-latest need a live dig-node with the store (set $env:STORE_LABEL / NODE).
# The Rust tests prove all of it deterministically.
#
# For the REAL :53 install, verify DNS with:  Resolve-DnsName -Server 127.0.0.5 <label>.dig
#
# Env: PORT (default 18080), DNS_PORT (default 15353), NODE, STORE_LABEL, ROOT_LABEL,
#      TLD (default dig), DIG_DNS_BIN.

$ErrorActionPreference = 'Stop'
$Tld     = if ($env:TLD)      { $env:TLD }      else { 'dig' }
$Port    = if ($env:PORT)     { $env:PORT }     else { '18080' }
$DnsPort = if ($env:DNS_PORT) { $env:DNS_PORT } else { '15353' }
$Ip      = '127.0.0.1'
$Gateway = "http://127.0.0.1:$Port"
$script:Pass = 0
$script:Fail = 0

function Ok  ($m) { $script:Pass++; Write-Host "  PASS  $m" }
function Bad ($m) { $script:Fail++; Write-Host "  FAIL  $m" }

# HTTP status for a request (optionally through the gateway as a proxy, with a Host override).
function StatusCode {
    param([string]$Url, [string]$ProxyUrl, [hashtable]$Headers)
    try {
        $p = @{ Uri = $Url; Method = 'GET'; SkipHttpErrorCheck = $true; TimeoutSec = 5 }
        if ($ProxyUrl) { $p.Proxy = $ProxyUrl }
        if ($Headers)  { $p.Headers = $Headers }
        return (Invoke-WebRequest @p).StatusCode
    } catch { return -1 }
}

$Bin = if ($env:DIG_DNS_BIN) { $env:DIG_DNS_BIN } else { 'target\debug\dig-dns.exe' }
if (-not (Test-Path $Bin)) {
    Write-Host 'building dig-dns…'
    cargo build --quiet
    $Bin = 'target\debug\dig-dns.exe'
}

Write-Host "starting: $Bin serve on $Ip (gateway :$Port, dns :$DnsPort)"
$env:DIG_DNS_IP = $Ip
$env:DIG_DNS_HTTP_PORT = $Port
$env:DIG_DNS_HTTP_FALLBACK_PORT = $Port
$env:DIG_DNS_DNS_PORT = $DnsPort
$env:DIG_DNS_TLD = $Tld
$serveArgs = @('serve')
if ($env:NODE) { $serveArgs += @('--node', $env:NODE) }
$srv = Start-Process -FilePath $Bin -ArgumentList $serveArgs -PassThru -WindowStyle Hidden

try {
    # Wait for the gateway liveness probe.
    for ($i = 0; $i -lt 60; $i++) {
        if ((StatusCode "$Gateway/.dig/resolve-probe") -eq 204) { break }
        Start-Sleep -Milliseconds 100
    }

    Write-Host "`n== doctor =="
    & $Bin doctor
    if ($LASTEXITCODE -eq 0) { Ok 'doctor: a .dig URL can load (exit 0)' }
    else { Bad "doctor reports no live path (exit $LASTEXITCODE)" }

    Write-Host "`n== control + open-proxy safety =="
    if ((StatusCode "$Gateway/.dig/resolve-probe") -eq 204) { Ok '/.dig/resolve-probe -> 204' } else { Bad 'resolve-probe not 204' }
    # Use RawContent (always a string) — .Content is bytes for the PAC's non-text content-type.
    $pac = (Invoke-WebRequest "$Gateway/.dig/proxy.pac" -SkipHttpErrorCheck).RawContent
    if ($pac -match 'PROXY ') { Ok '/.dig/proxy.pac advertises a PROXY line' } else { Bad 'proxy.pac missing PROXY' }
    if ((StatusCode "$Gateway/.dig/health") -eq 200) { Ok '/.dig/health -> 200' } else { Bad 'health not 200' }
    if ((StatusCode 'http://example.com/' $Gateway) -eq 403) { Ok 'proxy http://example.com/ -> 403' } else { Bad 'non-.dig proxy not 403' }
    if ((StatusCode "$Gateway/" $null @{ Host = "not-a-valid-label.$Tld" }) -eq 404) { Ok "invalid .$Tld host -> 404" } else { Bad 'invalid host not 404' }

    Write-Host "`n== content + pinned-vs-latest (needs a live dig-node with the store) =="
    if (-not $env:STORE_LABEL) {
        Write-Host "  SKIP  set `$env:STORE_LABEL (+ NODE) to run these. Commands:"
        Write-Host "        origin: curl -H 'Host: <STORE_LABEL>.$Tld' $Gateway/"
        Write-Host "        proxy:  curl -x $Gateway http://<STORE_LABEL>.$Tld/"
    } else {
        $h = "$($env:STORE_LABEL).$Tld"
        if ((StatusCode "$Gateway/" $null @{ Host = $h }) -eq 200) { Ok 'origin-form GET / -> 200' } else { Bad 'origin fetch not 200' }
        if ((StatusCode "http://$h/" $Gateway) -eq 200) { Ok 'proxy-form GET / -> 200' } else { Bad 'proxy fetch not 200' }
        if ($env:ROOT_LABEL) {
            $latest = (Invoke-WebRequest "$Gateway/" -Headers @{ Host = $h } -SkipHttpErrorCheck).Content
            $ph = "$($env:ROOT_LABEL).$($env:STORE_LABEL).$Tld"
            $pinned = (Invoke-WebRequest "$Gateway/" -Headers @{ Host = $ph } -SkipHttpErrorCheck).Content
            if ($pinned -and ($latest -ne $pinned)) { Ok 'pinned root differs from latest' } else { Bad 'pinned did not differ from latest' }
        }
    }
}
finally {
    if ($srv -and -not $srv.HasExited) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }
}

Write-Host "`nresult: $script:Pass passed, $script:Fail failed"
if ($script:Fail -ne 0) { exit 1 }
