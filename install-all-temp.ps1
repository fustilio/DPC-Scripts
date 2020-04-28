#Version 1.0.0

$tempFilePath = $PSScriptRoot + "/install-all.ps1"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/fustilio/DPC-Scripts/master/install-all.ps1?token=AFRXBM5J4K4PTCX3SEQEV5S6WFZJ2" -OutFile $tempFilePath

if (Test-Path ($PSScriptRoot + "/install-all.ps1")) {
    $version = Get-Content $tempFilePath -First 1
}