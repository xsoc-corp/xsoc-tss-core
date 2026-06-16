# Fails if real stub markers appear in src. Honest documentation that mentions
# the words mock or stub is fine; this checks for placeholder macros only.
$ErrorActionPreference = "Stop"
$hits = Get-ChildItem -Path src -Recurse -Filter *.rs |
    Select-String -Pattern "unimplemented!\(|todo!\(|compile_error!\("
if ($hits) {
    $hits | ForEach-Object { Write-Host ($_.Path + ":" + $_.LineNumber + "  " + $_.Line.Trim()) }
    Write-Error "no-stub gate failed: placeholder macros present"
}
Write-Host "no-stub gate passed" -ForegroundColor Green