param(
    [Parameter(Mandatory = $true)][string]$ServerIp,
    [Parameter(Mandatory = $true)][string]$OutputDirectory
)

$ErrorActionPreference = 'Stop'
$keytool = (Get-Command keytool.exe -ErrorAction Stop).Source
$out = [IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $out) {
    if (Get-ChildItem -LiteralPath $out -Force | Select-Object -First 1) {
        throw "Output directory is not empty: $out"
    }
} else {
    New-Item -ItemType Directory -Path $out | Out-Null
}

function Read-HiddenValue([string]$Prompt) {
    $secureValue = Read-Host $Prompt -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer); $secureValue.Dispose() }
}

$serverPassword = Read-HiddenValue 'Choose a temporary PKCS12 password for Computer A'
$clientPassword = Read-HiddenValue 'Choose a temporary PKCS12 password for Computer B'
if ($serverPassword.Length -lt 10 -or $clientPassword.Length -lt 10) { throw 'Use at least 10 characters for both temporary certificate-store passwords.' }
$serverPasswordVariable = "VAULTIQ_LAB_SERVER_PASSWORD_$PID"
$clientPasswordVariable = "VAULTIQ_LAB_CLIENT_PASSWORD_$PID"
[Environment]::SetEnvironmentVariable($serverPasswordVariable, $serverPassword, 'Process')
[Environment]::SetEnvironmentVariable($clientPasswordVariable, $clientPassword, 'Process')
$serverSubject = "CN=$ServerIp, OU=VaultIQ Authorized Lab, O=Local Project, C=IN"
$clientSubject = 'CN=VaultIQ Authorized Test Client, OU=VaultIQ Authorized Lab, O=Local Project, C=IN'
$serverStore = Join-Path $out 'server-keystore.p12'
$clientStore = Join-Path $out 'client-keystore.p12'
$serverTrust = Join-Path $out 'server-truststore.p12'
$clientTrust = Join-Path $out 'client-truststore.p12'
$serverCertificate = Join-Path $out 'server-certificate.cer'
$clientCertificate = Join-Path $out 'client-certificate.cer'

& $keytool -genkeypair -alias vault-server -keyalg RSA -keysize 3072 -validity 30 `
    -storetype PKCS12 -keystore $serverStore -storepass:env $serverPasswordVariable -keypass:env $serverPasswordVariable `
    -dname $serverSubject -ext "SAN=ip:$ServerIp" -ext 'EKU=serverAuth' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not create the server certificate.' }
& $keytool -genkeypair -alias vault-lab-client -keyalg RSA -keysize 3072 -validity 30 `
    -storetype PKCS12 -keystore $clientStore -storepass:env $clientPasswordVariable -keypass:env $clientPasswordVariable `
    -dname $clientSubject -ext 'EKU=clientAuth' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not create the lab-client certificate.' }
& $keytool -exportcert -rfc -alias vault-server -keystore $serverStore -storepass:env $serverPasswordVariable -file $serverCertificate | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not export the server certificate.' }
& $keytool -exportcert -rfc -alias vault-lab-client -keystore $clientStore -storepass:env $clientPasswordVariable -file $clientCertificate | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not export the lab-client certificate.' }
& $keytool -importcert -noprompt -alias vault-lab-client -file $clientCertificate -storetype PKCS12 `
    -keystore $serverTrust -storepass:env $serverPasswordVariable | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not create the server truststore.' }
& $keytool -importcert -noprompt -alias vault-server -file $serverCertificate -storetype PKCS12 `
    -keystore $clientTrust -storepass:env $clientPasswordVariable | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not create the client truststore.' }

$random = [byte[]]::new(48)
$rng = New-Object Security.Cryptography.RNGCryptoServiceProvider
try { $rng.GetBytes($random) }
finally { $rng.Dispose() }
$token = [Convert]::ToBase64String($random).TrimEnd('=').Replace('+', '-').Replace('/', '_')
[IO.File]::WriteAllText((Join-Path $out 'lab-token.txt'), $token, [Text.Encoding]::ASCII)
[Array]::Clear($random, 0, $random.Length)
[Environment]::SetEnvironmentVariable($serverPasswordVariable, $null, 'Process')
[Environment]::SetEnvironmentVariable($clientPasswordVariable, $null, 'Process')
$serverPassword = $null
$clientPassword = $null

Write-Host "Created short-lived self-signed lab credentials in $out"
Write-Host 'Computer A files: server-keystore.p12, server-truststore.p12, server password, lab-token.txt'
Write-Host 'Computer B files: client-keystore.p12, client-truststore.p12, client password, same lab-token.txt'
Write-Host 'Transfer the B files and token privately. Delete the certificate directory after the demo.'
Write-Host 'Remember the two passwords you entered; re-enter them as Computer A/B environment variables.'
