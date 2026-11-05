param(
    [Parameter(Mandatory = $true)][ValidateSet('server', 'client')][string]$Role,
    [string]$PrivateAddress,
    [string]$AllowedClientAddress,
    [string]$VaultRoot = 'data/vault',
    [string]$ServerAddress,
    [ValidateRange(1, 65535)][int]$Port = 8090,
    [ValidateSet('initial', 'repeat')][string]$Purpose = 'initial'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root

function Read-HiddenValue([string]$Prompt) {
    $secureValue = Read-Host $Prompt -AsSecureString
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secureValue)
    try { [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer); $secureValue.Dispose() }
}

if ($Role -eq 'server') {
    if (-not $PrivateAddress -or -not $AllowedClientAddress) { throw 'Supply -PrivateAddress and -AllowedClientAddress.' }
    $env:VAULT_LAB_TOKEN = Read-HiddenValue 'Computer A: paste the generated lab token'
    $env:VAULT_LAB_CLIENT_ADDRESS = $AllowedClientAddress
    $env:VAULT_TLS_KEYSTORE = Read-Host 'Path to server-keystore.p12'
    $env:VAULT_TLS_KEYSTORE_PASSWORD = Read-HiddenValue 'Computer A keystore password'
    $env:VAULT_TLS_TRUSTSTORE = Read-Host 'Path to server-truststore.p12'
    $env:VAULT_TLS_TRUSTSTORE_PASSWORD = Read-HiddenValue 'Computer A truststore password'
    try {
        & javac backend\Server.java backend\VaultService.java
        if ($LASTEXITCODE -ne 0) { throw 'Java server compilation failed.' }
        & java "-Dserver.port=$Port" "-Dvault.root=$VaultRoot" '-Dvault.lab.remote=true' "-Dvault.bindAddress=$PrivateAddress" -cp backend Server
        if ($LASTEXITCODE -ne 0) { throw 'Vault server stopped with an error.' }
    } finally {
        @('VAULT_LAB_TOKEN','VAULT_LAB_CLIENT_ADDRESS','VAULT_TLS_KEYSTORE','VAULT_TLS_KEYSTORE_PASSWORD','VAULT_TLS_TRUSTSTORE','VAULT_TLS_TRUSTSTORE_PASSWORD') | ForEach-Object { Remove-Item -Path "Env:$_" -ErrorAction SilentlyContinue }
    }
} else {
    if (-not $ServerAddress -or $Port -lt 1 -or $Port -gt 65535) { throw 'Supply a valid -ServerAddress and -Port.' }
    $env:VAULT_TARGET_HOST = $ServerAddress
    $env:VAULT_TARGET_PORT = [string]$Port
    $env:VAULT_LAB_TOKEN = Read-HiddenValue 'Computer B: paste the same generated lab token'
    $env:VAULT_TLS_CLIENT_KEYSTORE = Read-Host 'Path to client-keystore.p12'
    $env:VAULT_TLS_CLIENT_KEYSTORE_PASSWORD = Read-HiddenValue 'Computer B keystore password'
    $env:VAULT_TLS_TRUSTSTORE = Read-Host 'Path to client-truststore.p12'
    $env:VAULT_TLS_TRUSTSTORE_PASSWORD = Read-HiddenValue 'Computer B truststore password'
    $clientSource = Join-Path $PSScriptRoot 'AttackLabClient.java'
    if (-not (Test-Path -LiteralPath $clientSource)) {
        $clientSource = Join-Path $PSScriptRoot '..\backend\AttackLabClient.java'
    }
    if (-not (Test-Path -LiteralPath $clientSource)) { throw 'Copy backend\AttackLabClient.java and this project tools folder to Computer B.' }
    $classOutput = Join-Path ([IO.Path]::GetTempPath()) 'vaultiq-authorized-client-classes'
    New-Item -ItemType Directory -Force -Path $classOutput | Out-Null
    try {
        & javac -d $classOutput $clientSource
        if ($LASTEXITCODE -ne 0) { throw 'Authorized lab client compilation failed.' }
        & java -cp $classOutput AttackLabClient $Purpose
        if ($LASTEXITCODE -ne 0) { throw 'Authorized lab client was rejected or failed.' }
    } finally {
        @('VAULT_TARGET_HOST','VAULT_TARGET_PORT','VAULT_LAB_TOKEN','VAULT_TLS_CLIENT_KEYSTORE','VAULT_TLS_CLIENT_KEYSTORE_PASSWORD','VAULT_TLS_TRUSTSTORE','VAULT_TLS_TRUSTSTORE_PASSWORD') | ForEach-Object { Remove-Item -Path "Env:$_" -ErrorAction SilentlyContinue }
    }
}
