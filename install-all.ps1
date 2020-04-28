$currentVersion = "v1.0.3"

$currentFilePath = $PSCommandPath
$tempFilePath = $PSScriptRoot + "/install-all-temp.ps1"
$numbersOnlyPattern = '[^0-9]'
$versionOnlyPattern = '[^.0-9]'

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/fustilio/DPC-Scripts/master/install-all.ps1?token=AFRXBMYU37LJHDRNTPZ4TSS6WF3O4" -OutFile $tempFilePath

if (Test-Path ($PSScriptRoot + "/install-all.ps1")) {
    
    $tempVersion = (Get-Content $tempFilePath -First 1) -replace $versionOnlyPattern, ""
    $tempVersionNumber = $tempVersioNNumber -replace $numbersOnlyPattern, ""
    Write-Host Latest version is: $tempVersion
    Write-Host Current Version is: $currentVersion
    if ($tempVersion -gt $currentVersion) {
        Copy-Item $tempFilePath $PSCommandPath
        Write-Host Updated install-all.ps1 to $tempVersion
    }

    Remove-Item $tempFilePath
}
