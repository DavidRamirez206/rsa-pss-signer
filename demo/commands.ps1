# Live demos for the presentation, on Windows (PowerShell 5.1 or 7).
#
#   .\demo\commands.ps1 setup      once, the day before: keys, signatures, certificates
#   .\demo\commands.ps1 1 ... 9    one demo
#   .\demo\commands.ps1 all        every demo in order
#   .\demo\commands.ps1 tsa        the time authority as a service, in a second window (demo 8)
#
# Run from a real console (the program reads passwords from it). Every password
# prompt takes the same long demo password. Needs `mvn package` first. Demo 5 and the
# RFC 3161 part of demo 8 need openssl, which Git for Windows includes.
param([string]$Demo = "")

$Root = Split-Path -Parent $PSScriptRoot
$Work = Join-Path $Root "demo\work"
$Jar = Join-Path $Root "target\rsa-pss-signer.jar"
$ClassPath = "$Jar;" + (Join-Path $Root "target\lib\*")
$Tools = Join-Path $Root "demo\DemoTools.java"
$NoBom = New-Object System.Text.UTF8Encoding $false

function Signer { & java -jar $Jar @args }
function Tools { & java -cp $ClassPath $Tools @args }
function Say([string]$Text) { Write-Host "`n# $Text" -ForegroundColor White }
function Step([scriptblock]$Command) {
    Write-Host "`n> $Command" -ForegroundColor Red
    & $Command
    Write-Host "(exit code $LASTEXITCODE)" -ForegroundColor DarkGray
}
function Pause-Demo { if (-not $env:DEMO_NO_PAUSE) { Read-Host "-- Enter to continue --" | Out-Null } }
# Each demo gets its own local state, as if it ran on its own machine
function Use-State([string]$Name) { $env:RSA_PSS_SIGNER_HOME = Join-Path $Work "state-$Name" }
function Write-Text([string]$Path, [string]$Text) {
    [System.IO.File]::WriteAllText((Join-Path (Get-Location) $Path), $Text, $NoBom)
}
function Replace-Text([string]$From, [string]$To, [string]$Old, [string]$New) {
    Write-Text $To ((Get-Content -Raw $From).Replace($Old, $New))
}
function Check { if ($LASTEXITCODE -ne 0) { throw "The last command failed" } }

function Setup {
    if (-not (Test-Path $Jar)) { Push-Location $Root; mvn -q -DskipTests package; Pop-Location; Check }
    if (Test-Path $Work) { throw "$Work already exists; delete it to prepare again." }
    New-Item -ItemType Directory -Force "$Work\mallory", "$Work\replay" | Out-Null
    Set-Location $Work
    Use-State "setup"

    Write-Text "contract.txt" "Ana Perez sells her car to Bob Diaz for 20,000,000 COP, paid on delivery.`n"
    $bytes = [System.IO.File]::ReadAllBytes((Join-Path $Work "contract.txt"))
    $bytes[40] = [byte][char]'3'
    [System.IO.File]::WriteAllBytes((Join-Path $Work "contract_tampered.txt"), $bytes)

    Say "Keys for Ana and Mallory"
    Signer keygen --out ana; Check
    Signer keygen --out mallory; Check
    Say "Keys for the brute-force demo: 1,000 and 600,000 PBKDF2 iterations"
    Tools keys weak 1000; Check
    Tools keys strong 600000; Check

    Say "Ana signs the contract"
    Signer sign contract.txt --key ana.key --signer "Ana Perez"; Check
    $line = Signer verify contract.txt --sig contract.txt.sig --pub ana.pub | Select-String '^Key fingerprint: (.*)$'
    Write-Text "ana.fingerprint" ($line.Matches[0].Groups[1].Value + "`n")

    Say "Mallory edits the contract and signs it as Ana, with her own key"
    Replace-Text "contract.txt" "mallory\contract.txt" "20,000,000" "2,000,000"
    Signer sign mallory\contract.txt --key mallory.key --signer "Ana Perez"; Check

    Say "Two versions of a document, the second chained to the first"
    Write-Text "replay\v1.txt" "Price: 20,000,000 COP.`n"
    Write-Text "replay\v2.txt" "Price: 25,000,000 COP.`n"
    Copy-Item replay\v1.txt replay\contract.txt -Force
    Signer sign replay\contract.txt --key ana.key --signer "Ana Perez" --out replay\v1.sig; Check
    Copy-Item replay\v2.txt replay\contract.txt -Force
    Signer sign replay\contract.txt --key ana.key --signer "Ana Perez" --out replay\v2.sig --previous replay\v1.sig; Check

    Say "Certificate authority, certificates for Ana and Mallory, and a time authority"
    Signer ca init --out ca --name "ICESI Demo CA"; Check
    Signer ca issue --ca ca --pub ana.pub --name "Ana Perez" --out ana.crt; Check
    Signer ca issue --ca ca --pub mallory.pub --name "Mallory" --out mallory.crt; Check
    Signer ca crl --ca ca; Check
    Copy-Item ca.crl ca-empty.crl -Force
    Signer keygen --out tsa; Check
    Signer tsa stamp contract.txt.sig --key tsa.key; Check

    Write-Text "invoice.pdf" "%PDF-1.7`n% demo`n"
    Remove-Item -Recurse -Force (Join-Path $Work "state-setup")
    Say "Ready in $Work"
}

function Demo1 {
    Say "Demo 1: public key substitution. The cryptography is right; the identity is not"
    Use-State "1-ana"
    Step { Signer verify contract.txt --sig contract.txt.sig --pub ana.pub }
    Pause-Demo
    Say "Mallory edited the contract, signed it as Ana with HER key, and sends her .pub to Bob"
    Say "Bob has never seen Ana's key before"
    Use-State "1"
    Step { Compare-Object (Get-Content contract.txt) (Get-Content mallory\contract.txt) }
    Step { Signer verify mallory\contract.txt --sig mallory\contract.txt.sig --pub mallory.pub }
    Say "VALID. Compare the fingerprint with the one Ana gave us in person:"
    Step { Get-Content ana.fingerprint }
}

function Demo2 {
    Say "Demo 2: one changed character"
    Use-State "2"
    Step { Compare-Object (Get-Content contract.txt) (Get-Content contract_tampered.txt) }
    Step { Signer verify contract_tampered.txt --sig contract.txt.sig --pub ana.pub }
}

function Demo3 {
    Say "Demo 3: editing the signer name inside the .sig"
    Use-State "3"
    Replace-Text "contract.txt.sig" "forged.sig" '"Ana Perez"' '"Professor X"'
    Step { Select-String signerName forged.sig }
    Step { Signer verify contract.txt --sig forged.sig --pub ana.pub }
}

function Demo4 {
    Say "Demo 4: brute force against the .key, 10 seconds each"
    Step { Tools bruteforce weak.key 10 }
    Step { Tools bruteforce strong.key 10 }
}

function Demo5 {
    Say "Demo 5: OpenSSL verifies our signature, so it is standard RSA-PSS"
    Step { Tools export contract.txt contract.txt.sig openssl }
    Step { openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:32 -sigopt rsa_mgf1_md:sha256 -verify ana.pub -signature openssl\signature.bin openssl\m.bin }
}

function Demo6 {
    Say "Demo 6: replaying an old version"
    Use-State "6"
    Copy-Item replay\v2.txt replay\contract.txt -Force
    Step { Signer verify replay\contract.txt --sig replay\v2.sig --pub ana.pub --previous replay\v1.sig }
    Pause-Demo
    Say "Someone presents version 1 again, with its genuine signature"
    Copy-Item replay\v1.txt replay\contract.txt -Force
    Step { Signer verify replay\contract.txt --sig replay\v1.sig --pub ana.pub }
    Pause-Demo
    Say "The limit: on a machine that never saw version 2, it is valid"
    Use-State "6-elsewhere"
    Step { Signer verify replay\contract.txt --sig replay\v1.sig --pub ana.pub }
}

function Demo7 {
    Say "Demo 7: trust on first use, like SSH. Mallory again"
    Use-State "7"
    Step { Signer verify contract.txt --sig contract.txt.sig --pub ana.pub }
    Step { Signer verify mallory\contract.txt --sig mallory\contract.txt.sig --pub mallory.pub }
    Pause-Demo
    Say "Level a: the fingerprint Ana gave us in person"
    $expected = (Get-Content ana.fingerprint).Trim()
    Step { Signer verify mallory\contract.txt --sig mallory\contract.txt.sig --pub mallory.pub --expect-fingerprint $expected }
    Pause-Demo
    Say "The limit: if Mallory comes first, her key is the one pinned"
    Use-State "7-mallory-first"
    Step { Signer verify mallory\contract.txt --sig mallory\contract.txt.sig --pub mallory.pub }
    Step { Signer verify contract.txt --sig contract.txt.sig --pub ana.pub }
}

function Demo8 {
    Say "Demo 8: a certificate authority vouches for the key"
    Use-State "8"
    Step { Signer verify contract.txt --sig contract.txt.sig --cert ana.crt --ca ca.crt }
    Step { Signer verify mallory\contract.txt --sig mallory\contract.txt.sig --cert mallory.crt --ca ca.crt }
    Pause-Demo
    Say "Ana's laptop is stolen: the authority revokes her certificate"
    Copy-Item ca-empty.crl ca.crl -Force
    Step { Signer verify contract.txt --sig contract.txt.sig --cert ana.crt --ca ca.crt --crl ca.crl }
    Step { Signer ca revoke --ca ca --cert ana.crt }
    Step { Signer verify contract.txt --sig contract.txt.sig --cert ana.crt --ca ca.crt --crl ca.crl }
    Say "The limit: whoever does not get the new list still accepts the key"
    Step { Signer verify contract.txt --sig contract.txt.sig --cert ana.crt --ca ca.crt --crl ca-empty.crl }
    Pause-Demo
    Say "Time stamp from the time authority: the date no longer comes from Ana alone"
    Step { Signer verify contract.txt --sig contract.txt.sig --pub ana.pub --timestamp contract.txt.sig.tst --tsa-pub tsa.pub }
    Say "The same from the authority as a service (.\demo\commands.ps1 tsa in another window)"
    Remove-Item -ErrorAction SilentlyContinue contract.txt.sig.live.tst
    Step { Signer tsa request contract.txt.sig --url http://127.0.0.1:8318 --out contract.txt.sig.live.tst }
    Step { Signer verify contract.txt --sig contract.txt.sig --pub ana.pub --timestamp contract.txt.sig.live.tst --tsa-pub tsa.pub }
    Pause-Demo
    Say "Real RFC 3161 time stamp from a public authority (needs internet)"
    New-Item -ItemType Directory -Force rfc3161 | Out-Null
    Step { openssl ts -query -data contract.txt.sig -sha256 -cert -out rfc3161\request.tsq }
    Step { curl.exe -sS -H "Content-Type: application/timestamp-query" --data-binary "@rfc3161\request.tsq" -o rfc3161\response.tsr https://freetsa.org/tsr }
    curl.exe -sS -o rfc3161\cacert.pem https://freetsa.org/files/cacert.pem
    curl.exe -sS -o rfc3161\tsa.crt https://freetsa.org/files/tsa.crt
    Step { openssl ts -verify -data contract.txt.sig -in rfc3161\response.tsr -CAfile rfc3161\cacert.pem -untrusted rfc3161\tsa.crt }
    openssl ts -reply -in rfc3161\response.tsr -text | Select-String 'Time stamp:'
}

function Demo9 {
    Say "Demo 9: what you see is not necessarily what you sign"
    Use-State "9"
    Remove-Item -ErrorAction SilentlyContinue invoice.pdf.sig
    Step { Signer sign invoice.pdf --key ana.key --signer "Ana Perez" }
}

if ($Demo -eq "setup") {
    Setup
} elseif ($Demo -eq "tsa") {
    if (-not (Test-Path $Work)) { throw "Run: .\demo\commands.ps1 setup" }
    Set-Location $Work
    Signer tsa serve --key tsa.key
} elseif ($Demo -match '^[1-9]$' -or $Demo -eq "all") {
    if (-not (Test-Path $Work)) { throw "Run: .\demo\commands.ps1 setup" }
    Set-Location $Work
    if ($Demo -eq "all") {
        foreach ($n in 1..9) { & "Demo$n"; Pause-Demo }
    } else {
        & "Demo$Demo"
    }
} else {
    Get-Content $PSCommandPath | Select-Object -Skip 1 -First 9
    exit 2
}
