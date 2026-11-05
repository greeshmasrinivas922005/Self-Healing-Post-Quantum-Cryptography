param(
    [string]$BaseUrl = "http://localhost:8090"
)

$ErrorActionPreference = "Stop"
$BaseUrl = $BaseUrl.TrimEnd("/")

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

$status = Invoke-RestMethod "$BaseUrl/api/status"
Assert-True ($status.kem -eq "ML-KEM-768") "ML-KEM-768 provider is unavailable."
Assert-True ($status.signature -eq "ML-DSA-65") "ML-DSA-65 provider is unavailable."

$message = "PQC Recovery Lab smoke test: secure note 123"
$package = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/protect" `
    -ContentType "application/x-www-form-urlencoded" -Body @{ message = $message }
Assert-True (-not [string]::IsNullOrWhiteSpace($package.id)) "Protect did not return a record ID."
Assert-True ($package.ciphertext -ne $message) "The returned ciphertext looks like plaintext."

$tamper = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/tamper" `
    -ContentType "application/x-www-form-urlencoded" -Body @{ id = $package.id }
Assert-True ($tamper.blocked) "AES-GCM did not reject modified ciphertext."

$restored = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/recover" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body @{ id = $package.id; simulateIncident = "false" }
Assert-True ($restored.message -ceq $message) "Recovered plaintext does not match the input."
Assert-True ($restored.signatureValid) "ML-DSA signature verification failed."
Assert-True (-not $restored.rotated) "A normal restore unexpectedly rotated the key."

$rotation = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/recover" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body @{ id = $package.id; simulateIncident = "true" }
Assert-True ($rotation.rotated -and $rotation.version -eq 2) "Recovery drill did not rotate to version 2."

$lock = [char]::ConvertFromUtf32(0x1F510)
$longMessage = $lock * 4000
$largePackage = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/protect" `
    -ContentType "application/x-www-form-urlencoded" -Body @{ message = $longMessage }
Assert-True ($largePackage.ciphertextBytes -eq 16016) "16 KB UTF-8 payload size did not match the expected encrypted size."

$benchmark = Invoke-RestMethod -Method Post -Uri "$BaseUrl/api/benchmark" `
    -ContentType "application/x-www-form-urlencoded" -Body @{}
Assert-True ($benchmark.rounds -eq 3) "Benchmark did not complete three rounds."
Assert-True ($benchmark.mlKem.encapsulationBytes -gt 0) "ML-KEM benchmark data is missing."
Assert-True ($benchmark.mlDsa.signatureBytes -gt 0) "ML-DSA benchmark data is missing."
Assert-True ($benchmark.rsa.averageMs -ge 0) "RSA benchmark data is missing."

$page = Invoke-WebRequest -UseBasicParsing "$BaseUrl/"
Assert-True ($page.StatusCode -eq 200) "The workbench page did not load."
Assert-True ($page.Content.Contains("PQC Recovery Lab")) "The expected workbench HTML was not served."

Write-Host "PASS: JDK $($status.javaVersion), $($status.kem), $($status.signature)"
Write-Host "PASS: protect, tamper rejection, verified restore, rotation to v$($rotation.version)"
Write-Host "PASS: 16 KB UTF-8 input, benchmark ($($benchmark.rounds) rounds), workbench page"
