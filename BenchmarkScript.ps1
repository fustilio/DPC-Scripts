#Requires -RunAsAdministrator

"`n`n`n`n`n`n`n`n`n"


Write-Host Hello there! This is the DPC PCMark10 benchmark script! -ForegroundColor Yellow
Write-Host Written by Hong Liang
Write-Host Last updated by Hong Liang 09/08/2020

"`n"

$PCMarkPath = "$PSScriptRoot\Misc\PCMark10"

if (Test-Path $PCMarkPath) {
    Write-Host PCMark10 installation file found. -ForegroundColor Green
} else {

    Write-Host "PCMark10 installation file not detected, proceeding to download and unpack, go grab a coffee ;/" -ForegroundColor Yellow

    try { 
        Import-Module BitsTransfer

        $url = "https://benchmarks.ul.com/downloads/pcmark10-professional.zip"
        $tempFilePath = "$PSScriptRoot\pcmark10-professional_temp.zip"

        Start-BitsTransfer $url $tempFilePath


        Write-Host "Zip file downloaded, unpacking.." -ForegroundColor Yellow

        Expand-Archive -Path $tempFilePath -DestinationPath $PCMarkPath

        Write-Host "Unpack complete." -ForegroundColor Green
    } catch {
        Write-Error Downloading PCMark10 files failed.
    }
}

"`n"

$configPath = "$PSScriptRoot\config.xml"
$tokenKeys = @("refresh_token",
                "client_id",
                "client_secret",
                "upload_folder",
                "drive_id"
              )
$writeToDrive = $true

$config = $null

if (Test-Path $configPath) {
    
    try {
        $config = ([xml](Get-Content $configPath)).config
        ForEach ($key in $tokenKeys) {
            if ([string]::IsNullOrEmpty($config.($key))) {
                $writeToDrive = $false
                Write-Output "Config key not found: $key"
                break
            }
        }

        if ($writeToDrive)
        {
            Write-Host "Configuration file found at $configPath" -ForegroundColor Green
        }

    } catch [System.Management.Automation.PSInvalidCastException] {
        Write-Error "Error parsing config.xml: $_.Exception"
    } catch {
        Write-Error "Unknown Error parsing configuration file."
    }

} else {
    Write-Host "No configuration file found at $configPath" -ForegroundColor Red
    Write-Host "Skipping writing to drive" -ForegroundColor Yellow
    $writeToDrive = $false
}


"`n"


$modulePath = Join-Path -Path $PSScriptRoot -ChildPath "SwitchUACLevel.psm1"
Import-Module $modulePath

Write-Host Supressing UAC notifications -ForegroundColor Yellow
Set-UACLevel 0 | Out-Null

Function GracefullyKill-Process($procName) {
    $proc = Get-Process $procName -ErrorAction SilentlyContinue
    if ($proc) {
      # try gracefully first
      $proc.CloseMainWindow()
      # kill after five seconds
      Sleep 5
      if (!$proc.HasExited) {
        $proc | Stop-Process -Force
      }
    }
}

#kill all known programs for testing
GracefullyKill-Process("chrome")
GracefullyKill-Process("AcroRd32")
GracefullyKill-Process("soffice")
GracefullyKill-Process("zoom")

#Stop-Process -Name "chrome" -Force
#Stop-Process -Name "AcroRd32" -Force
#Stop-Process -Name "soffice" -Force
#Stop-Process -Name "zoom" -Force


#Write-Host "Connecting to engineeringGood WiFi..."
Push-Location $PSScriptRoot
#netsh wlan add profile filename="Wi-Fi-eG.xml"
Start-Sleep 5
#Write-Host "Wifi profile added."
"`n"





Write-Host "Setting Time Zone to Singapore Time"
Set-TimeZone -Id "Singapore Standard Time"
net start w32time
W32tm /resync /force
"`n"

$biosInfo = Get-CimInstance Win32_bios | Select-Object -Property SerialNumber
$processorInfo = Get-WmiObject -Class Win32_Processor | Select-Object -Property Name
$ramInfo = (Get-CimInstance -ClassName Win32_ComputerSystem).totalphysicalmemory 
$ramInfo = ([Math]::Round(($ramInfo)/1GB,0))

Write-Host "`nInstalling PCMark 10..."

$pcMark10ResultsFile = "logs\" + $processorInfo.Name + "_" + $ramInfo + "GB_" + $biosInfo.SerialNumber +"_bmarkExpress.pdf"

$pcMark10ResultsPath = Join-Path -Path $PSScriptRoot -ChildPath "$pcMark10ResultsFile"


cmd /c start /wait Misc\PCMark10\pcmark10-setup.exe /quiet /silent
& 'C:\Program Files\UL\PCMark 10\PCMark10Cmd.exe'`
 --register PCM10-TPRO-20210801-227PQ-FD6M2-DUJNH-VM5V7 `
 --definition=pcm10_express.pcmdef `
 --out=$PSScriptRoot\bmark.pcmark10-result `
 --export-pdf=$pcMark10ResultsPath `
 --online on `
 --systeminfo on `
 --systeminfomonitor on



Write-Host "System Info"
"`n"
$processorInfo = Get-WmiObject -Class Win32_Processor | Select-Object -Property Name
Write-Host "CPU Name: "$processorInfo.Name""
$ramInfo = (Get-CimInstance -ClassName Win32_ComputerSystem).totalphysicalmemory 
$ramInfo = ([Math]::Round(($ramInfo)/1GB,0))
Write-Host "Total Installed RAM: $ramInfo GB"


$systemInfo = Get-CimInstance Win32_ComputerSystem | Select-Object -Property Name, Manufacturer, Model
#$biosInfo = Get-CimInstance Win32_bios | Select-Object -Property SerialNumber
$windowsInfo = Get-CimInstance -ClassName win32_operatingsystem | Select-Object -Property OSArchitecture, Caption
Write-Host "Laptop Brand: "$systemInfo.Manufacturer""
Write-Host "Laptop Model: "$systemInfo.Model""
Write-Host "Laptop S/N: "$biosInfo.SerialNumber""
Write-Host "Windows Version: "$windowsInfo.Caption""
Write-Host "Windows Type: "$windowsInfo.OSArchitecture""
Start-Sleep 15


Function Get-DiskInfo {
$disk = Get-WMIObject Win32_Logicaldisk -ComputerName $computer |
            Select-Object  @{Name="Computer";Expression={$computer}}, 
                DeviceID,
                @{Name="Size in GB";Expression={$_.Size/(1000*1000*1000) -as [int]}}
            
        #Write-Host $Computer -ForegroundColor Magenta
        $disk
}

Function Get-VRamInfo {
$vram = Get-WmiObject win32_videocontroller -ComputerName $computer | 
            Select-Object @{Name="Computer";Expression={$computer}},
                @{Name="Video RAM in MB";Expression={$_.adapterram / (1000*1000) -as [int]}},
                @{Name="Size in GB";Expression={$_.adapterram/(1000*1000*1000) -as [int]}},
                Name
        #Write-Host $computer -ForegroundColor Cyan
        $vram
}

$computer = '.'

Get-VRamInfo | Format-Table
Get-DiskInfo | Format-Table


"`n"
Start-Sleep 5


"`n"

Start-Process $pcMark10ResultsPath

if ($writeToDrive) {
    $ping = Test-NetConnection
    #write-host $ping.PingSucceeded
    $pingResult = $ping.PingSucceeded
    #write-host $pingResult

    if ($pingResult -eq $false)
    {
    do {
        Write-Host "Please connect to WiFi manually before we can continue." -ForegroundColor green
        $ping = Test-NetConnection
        #write-host $ping.PingSucceeded
        $pingResult = $ping.PingSucceeded
        # write-host $pingResult
        pause
    }
    while ($pingResult -eq $false)
    }


    Write-Host Uploading Benchmark results to Google Drive...

    # Set the Google Auth parameters. Fill in your RefreshToken, ClientID, and ClientSecret
    $params = @{
        Uri = 'https://accounts.google.com/o/oauth2/token'
        Body = @(
            "refresh_token=$($config.refresh_token)", # Replace $RefreshToken with your refresh token
            "client_id=$($config.client_id)",         # Replace $ClientID with your client ID
            "client_secret=$($config.client_secret)", # Replace $ClientSecret with your client secret
            "grant_type=refresh_token"
        ) -join '&'
        Method = 'Post'
        ContentType = 'application/x-www-form-urlencoded'
    }
    $accessToken = (Invoke-RestMethod @params).access_token

    # Change this to the file you want to upload
    $SourceFile = $pcMark10ResultsPath

    # Get the source file contents and details, encode in base64
    $sourceItem = Get-Item $sourceFile
    $sourceBase64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($sourceItem.FullName))
    $sourceMime = [System.Web.MimeMapping]::GetMimeMapping($sourceItem.FullName)

    # If uploading to a Team Drive, set this to 'true'
    $supportsTeamDrives = 'true'

    # Set the file metadata
    $uploadMetadata = @{
        originalFilename = $sourceItem.Name
        name = $sourceItem.Name
        description = $sourceItem.VersionInfo.FileDescription
        parents = @($config.upload_folder)      # Include to upload to a specific folder
        teamDriveId = $config.drive_id          # Include to upload to a specific teamdrive
    }

    Write-Host $uploadMetadata

    # Set the upload body
    $uploadBody = @"
--boundary
Content-Type: application/json; charset=UTF-8

$($uploadMetadata | ConvertTo-Json)

--boundary
Content-Transfer-Encoding: base64
Content-Type: $sourceMime

$sourceBase64
--boundary--
"@

    # Set the upload headers
    $uploadHeaders = @{
        "Authorization" = "Bearer $accessToken"
        "Content-Type" = 'multipart/related; boundary=boundary'
        "Content-Length" = $uploadBody.Length
    }

    # Perform the upload
    $response = Invoke-RestMethod -Uri "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&supportsTeamDrives=$supportsTeamDrives" -Method Post -Headers $uploadHeaders -Body $uploadBody

    Write-Host "`nBenchmark results uploaded Google Drive TAC folder."
}


Write-Host "`nUninstalling PCMark 10..."

cmd /c start /wait Misc\PCMark10\pcmark10-setup.exe /uninstall


# Revert UAC Settings to default
Write-Host Restoring UAC settings to Default -ForegroundColor Yellow
Set-UACLevel 2 | Out-Null

Read-Host -Prompt "Press Enter to exit"
Write-Host "That's all folks, remember to save the computer's details" -ForegroundColor Yellow
PAUSE
PAUSE

