<#
.SYNOPSIS
  OpenSSL test matrix for schgroups. Prints expected vs. observed per test and an overall PASS/FAIL.

.DESCRIPTION
  Start the server first (OS default list assumed to include all 7 groups):
    .\schgroups.exe --port 8443 --enable SecP384r1_MLKEM1024 --port 9443 --enable curve25519,NistP256,NistP384 --port 10443 --port 11443 --enable MLKEM1024

  Ports:
    PqPort      (8443)  only SecP384r1_MLKEM1024
    ClassicPort (9443)  only curve25519, NistP256, NistP384
    DefaultPort (10443) OS defaults
    MlKemPort   (11443) only MLKEM1024 (pure ML-KEM, no classical component)

.EXAMPLE
  .\run-tests.ps1
  .\run-tests.ps1 -OpenSsl 'C:\Program Files\OpenSSL-Win64\bin\openssl.exe'
#>
[CmdletBinding()]
param(
    [string] $Server      = 'localhost',
    [int]    $PqPort      = 8443,
    [int]    $ClassicPort = 9443,
    [int]    $DefaultPort = 10443,
    [int]    $MlKemPort   = 11443,
    [string] $OpenSsl     = 'openssl'
)

# --- test matrix -------------------------------------------------------------------------------
# Expect: a group name (handshake must negotiate exactly that group) or 'REFUSED' (either kind).
$tests = @(
    # PQ-only port
    @{ Port = $PqPort;      Offer = 'SecP384r1MLKEM1024';        Expect = 'SecP384r1MLKEM1024' }
    @{ Port = $PqPort;      Offer = 'SecP384r1MLKEM1024';        Expect = 'SecP384r1MLKEM1024'; KeyUpdate = $true }
    @{ Port = $PqPort;      Offer = 'X25519:SecP384r1MLKEM1024'; Expect = 'SecP384r1MLKEM1024'; Hrr = $true }
    @{ Port = $PqPort;      Offer = 'X25519MLKEM768';            Expect = 'REFUSED'; Why = "${PqPort}: only SecP384r1_MLKEM1024 enabled" }
    @{ Port = $PqPort;      Offer = 'MLKEM1024';                 Expect = 'REFUSED'; Why = "${PqPort}: only SecP384r1_MLKEM1024 enabled" }
    @{ Port = $PqPort;      Offer = 'X25519';                    Expect = 'REFUSED'; Why = "${PqPort}: only SecP384r1_MLKEM1024 enabled" }
    @{ Port = $PqPort;      Offer = 'secp256r1';                 Expect = 'REFUSED'; Why = "${PqPort}: only SecP384r1_MLKEM1024 enabled" }
    # classic-only port
    @{ Port = $ClassicPort; Offer = 'X25519';                    Expect = 'X25519' }
    @{ Port = $ClassicPort; Offer = 'secp256r1';                 Expect = 'secp256r1' }
    @{ Port = $ClassicPort; Offer = 'secp384r1';                 Expect = 'secp384r1' }
    @{ Port = $ClassicPort; Offer = 'secp521r1';                 Expect = 'REFUSED'; Why = "${ClassicPort}: NistP521 not in enable list" }
    @{ Port = $ClassicPort; Offer = 'X25519MLKEM768';            Expect = 'REFUSED'; Why = "${ClassicPort}: classic only, no PQ" }
    @{ Port = $ClassicPort; Offer = 'SecP384r1MLKEM1024';        Expect = 'REFUSED'; Why = "${ClassicPort}: classic only, no PQ" }
    @{ Port = $ClassicPort; Offer = 'MLKEM1024';                 Expect = 'REFUSED'; Why = "${ClassicPort}: classic only, no PQ" }
    # OS-defaults port
    @{ Port = $DefaultPort; Offer = 'SecP384r1MLKEM1024';        Expect = 'SecP384r1MLKEM1024' }
    @{ Port = $DefaultPort; Offer = 'X25519MLKEM768';            Expect = 'X25519MLKEM768' }
    @{ Port = $DefaultPort; Offer = 'MLKEM1024';                 Expect = 'MLKEM1024' }
    @{ Port = $DefaultPort; Offer = 'X25519';                    Expect = 'X25519' }
    @{ Port = $DefaultPort; Offer = 'secp256r1';                 Expect = 'secp256r1' }
    @{ Port = $DefaultPort; Offer = 'secp384r1';                 Expect = 'secp384r1' }
    @{ Port = $DefaultPort; Offer = 'secp521r1';                 Expect = 'secp521r1' }
    # pure ML-KEM port
    @{ Port = $MlKemPort;   Offer = 'MLKEM1024';                 Expect = 'MLKEM1024' }
    @{ Port = $MlKemPort;   Offer = 'SecP384r1MLKEM1024';        Expect = 'REFUSED'; Why = "${MlKemPort}: only MLKEM1024 enabled" }
    @{ Port = $MlKemPort;   Offer = 'X25519MLKEM768';            Expect = 'REFUSED'; Why = "${MlKemPort}: only MLKEM1024 enabled" }
    @{ Port = $MlKemPort;   Offer = 'X25519';                    Expect = 'REFUSED'; Why = "${MlKemPort}: only MLKEM1024 enabled" }
)

# --- helpers -----------------------------------------------------------------------------------
function Get-NegotiatedGroup([string] $out) {
    if ($out -match 'Negotiated TLS1\.3 group:\s*(\S+)') { return $Matches[1] }
    if ($out -match 'Peer Temp Key:\s*([^\r\n]+)') {           # classic groups on some builds
        $k = $Matches[1]
        if ($k -match '^X25519')        { return 'X25519' }
        if ($k -match '^X448')          { return 'X448' }
        if ($k -match 'prime256v1|P-256') { return 'secp256r1' }
        if ($k -match 'secp384r1|P-384')  { return 'secp384r1' }
        if ($k -match 'secp521r1|P-521')  { return 'secp521r1' }
        return $k.Trim()
    }
    return $null
}

function Invoke-KeyUpdateProbe([int] $port, [string] $group) {
    if ($Server -match '[\s"\\]') { throw 'Expected a server hostname or IP address' }
    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = (Get-Command $OpenSsl -CommandType Application -ErrorAction Stop).Source
    $start.Arguments = "s_client -connect ${Server}:$port -servername $Server -tls1_3 -groups $group -brief -msg -adv"
    $start.UseShellExecute = $false
    $start.RedirectStandardInput = $start.RedirectStandardOutput = $start.RedirectStandardError = $true
    $p = [Diagnostics.Process]::Start($start)
    try {
        $stdout = $p.StandardOutput.ReadToEndAsync()
        $stderr = $p.StandardError.ReadToEndAsync()
        # Keep stdin open: EOF can close s_client before the server replies; -ign_eof disables commands.
        $p.StandardInput.WriteLine('{keyup:req}GET / HTTP/1.1')
        $p.StandardInput.Flush()
        if (!$p.WaitForExit(15000)) { return @{ Kind = 'FAILED'; Text = 'timed out after KeyUpdate' } }
        $out = $stdout.GetAwaiter().GetResult() + "`n" + $stderr.GetAwaiter().GetResult()
        if ($p.ExitCode -ne 0 -or $out -notmatch '>>>[^\r\n]*KeyUpdate' -or $out -notmatch '<<<[^\r\n]*KeyUpdate' -or
            $out -notmatch 'HTTP/1\.1 200 OK' -or $out -notmatch "key exchange group:\s+\S+ / $([regex]::Escape($group)) ") {
            return @{ Kind = 'FAILED'; Text = 'missing KeyUpdate exchange or expected HTTP response' }
        }
        return @{ Kind = 'OK'; Group = (Get-NegotiatedGroup $out); Text = 'KeyUpdate and HTTP response' }
    } finally {
        if (!$p.HasExited) { $p.Kill(); $p.WaitForExit() }
        $p.Dispose()
    }
}

function Invoke-Probe([int] $port, [string] $groups, [bool] $hrr) {
    $sargs = @('s_client', '-connect', "${Server}:$port", '-servername', $Server, '-tls1_3', '-groups', $groups, '-brief')
    if ($hrr) { $sargs += '-msg' }
    $ErrorActionPreference = 'Continue'
    $out = '' | & $OpenSsl @sargs 2>&1 | Out-String
    $neg = Get-NegotiatedGroup $out
    $helloCount = ([regex]::Matches($out, 'ClientHello')).Count

    if ($out -match 'Call to SSL_CONF_cmd|Failed to set groups|unknown group|Error with command') {
        return @{ Kind = 'NA';        Text = 'n/a (OpenSSL lacks group)' }
    }
    if ($out -match 'connect:errno|Connection refused|connect error|No connection could be made') {
        return @{ Kind = 'NOCONN';    Text = 'no connection (server running?)' }
    }
    if ($neg -and $out -match 'alert number 40|alert handshake failure|unexpected eof') {
        return @{ Kind = 'REFUSED';   Text = "REFUSED after handshake ($neg)" }
    }
    if ($neg) {
        $t = "negotiated $neg"
        if ($hrr) { $t += $(if ($helloCount -ge 2) { ' (via HRR)' } else { ' (no HRR seen)' }) }
        return @{ Kind = 'OK'; Group = $neg; Hrr = ($helloCount -ge 2); Text = $t }
    }
    if ($out -match 'unexpected eof') { return @{ Kind = 'REFUSED'; Text = 'REFUSED by Schannel (EOF, no alert)' } }
    if ($out -match 'alert ([a-z ]+)') { return @{ Kind = 'REFUSED'; Text = "REFUSED (alert $($Matches[1].Trim()))" } }
    return @{ Kind = 'FAILED'; Text = 'FAILED (unrecognized output)' }
}

# --- run ---------------------------------------------------------------------------------------
$ver = (& $OpenSsl version) 2>&1 | Out-String
Write-Host "OpenSSL : $($ver.Trim())"
Write-Host "Target  : $Server  PQ=$PqPort  Classic=$ClassicPort  Defaults=$DefaultPort  ML-KEM=$MlKemPort`n"
if ($ver -match 'OpenSSL (\d+)\.(\d+)' -and ([int]$Matches[1] -lt 3 -or ([int]$Matches[1] -eq 3 -and [int]$Matches[2] -lt 5))) {
    Write-Warning 'OpenSSL < 3.5 -- ML-KEM tests will be n/a and count as FAIL.'
}

$fmt = '{0,2}  {1,-6} {2,-26} {3,-48} {4,-26} {5}'
Write-Host ($fmt -f '#', 'Port', 'Offered', 'Expected', 'Observed', 'Result') -ForegroundColor Cyan
Write-Host ($fmt -f '--', '----', '-------', '--------', '--------', '------') -ForegroundColor Cyan

$results = @()
$i = 0
foreach ($t in $tests) {
    $i++
    $hrr = [bool]$t.Hrr
    $r = if ($t.KeyUpdate) { Invoke-KeyUpdateProbe $t.Port $t.Offer } else { Invoke-Probe $t.Port $t.Offer $hrr }

    $pass = switch ($t.Expect) {
        'REFUSED' { $r.Kind -eq 'REFUSED' }
        default   { $r.Kind -eq 'OK' -and $r.Group -ieq $t.Expect -and (-not $hrr -or $r.Hrr) }
    }
    $expectText = if ($t.Expect -eq 'REFUSED') { "Refused ($($t.Why))" } else { "Negotiated $($t.Expect)$(if ($hrr) { ' via HRR' })" }
    if ($t.KeyUpdate) { $expectText += ' + KeyUpdate' }

    # Observed: just Negotiated / Refused. Detail only when it explains a FAIL.
    $observed = switch ($r.Kind) {
        'OK' {
            if ($t.Expect -ne 'REFUSED' -and $r.Group -ine $t.Expect) { "Negotiated $($r.Group)" }
            elseif ($hrr -and -not $r.Hrr) { 'Negotiated (no HRR)' }
            else { 'Negotiated' }
        }
        'REFUSED' { 'Refused' }
        'NA'      { 'n/a (OpenSSL lacks group)' }
        'NOCONN'  { 'No connection' }
        default   { if ($t.KeyUpdate) { $r.Text } else { 'Error' } }
    }

    $results += [pscustomobject]@{
        '#'      = $i
        Port     = $t.Port
        Offered  = $t.Offer
        Expected = $expectText
        Observed = $observed
        Result   = if ($pass) { 'PASS' } else { 'FAIL' }
    }
    $color = if ($pass) { 'Green' } else { 'Red' }
    Write-Host ($fmt -f $i, $t.Port, $t.Offer, $expectText, $observed, '') -NoNewline
    Write-Host $(if ($pass) { 'PASS' } else { 'FAIL' }) -ForegroundColor $color
}

$failed = @($results | Where-Object Result -eq 'FAIL')
Write-Host ''
if ($failed.Count -eq 0) {
    Write-Host "OVERALL: PASS  ($($results.Count)/$($results.Count))" -ForegroundColor Green
    exit 0
} else {
    Write-Host "OVERALL: FAIL  ($($results.Count - $failed.Count)/$($results.Count) passed; failed: $(($failed.'#') -join ', '))" -ForegroundColor Red
    exit 1
}