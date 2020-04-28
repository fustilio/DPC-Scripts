$currentVersion = 1.0.2

$currentFilePath = $PSCommandPath
$tempFilePath = $PSScriptRoot + "/install-all-temp.ps1"
$numbersOnlyPattern = '[^0-9]'
$versionOnlyPattern = '[^.0-9]'

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/fustilio/DPC-Scripts/master/install-all.ps1?token=AFRXBMYU37LJHDRNTPZ4TSS6WF3O4" -OutFile $tempFilePath

if (Test-Path ($tempFilePath)) {
    
    $tempVersion = (Get-Content $tempFilePath -First 1) -replace $versionOnlyPattern, ""
    $tempVersionNumber = $tempVersion -replace $numbersOnlyPattern, ""

    Write-Host $tempVersion
    Write-Host $tempVersionNumber
    if ($tempVersion -gt $currentVersion) {
        Copy-Item $tempFilePath $PSCommandPath
        Write-Host Updated install-all.ps1 to $tempVersion
    }
}
