<# v1.2.7
.Description
This script installs the applications listed in msi_list.txt sequentially.
Requires input to -Source parameter
Use the -LICENSE flag to check the status of previously activated licenses.
Use the -DEFENDER flag to update Windows Defender Antimalware Definitions.
#>

#Requires -RunAsAdministrator

[CmdletBinding(DefaultParameterSetName="install")]
Param(
    [Parameter(ParameterSetName="install", Mandatory=$true)]
    [Alias('s64')]
    [String] $Source64,
    [Parameter(ParameterSetName="install", Mandatory=$true)]
    [Alias('s32')]
    [String] $Source32,
    [Alias('l','lic')]
    [switch] $LICENSE = $false,
    [Alias('d','def')]
    [switch] $DEFENDER = $false,
    [Alias('c','cln')]
    [switch] $CLEANUP = $false,
    [Parameter(ParameterSetName="update")]
    [Alias('u','upd')]
    [switch] $UPDATE = $false,
    [Alias('q','QC')]
    [switch] $CHECK = $false
)

BEGIN {

    $currentVersion = "1.2.7"
    $currentVersionDate = "01/05/2020"
    Write-Host Hello there! This is the DPC software install script! -ForegroundColor Yellow
    Write-Host "Current version of the script is v$currentVersion last updated on $currentVersionDate." -ForegroundColor Yellow
 
}

PROCESS {

    $currentFilePath = $PSCommandPath
    $tempFilePath = $PSScriptRoot + "/install-all-temp.ps1"
    $runmePath = $PSScriptRoot + "/runme.bat"
    $runmeLicPath = $PSScriptRoot + "/runme-license.bat"
    $runmeNoClean = $PSScriptRoot + "/runme-noclean.bat"
    $numbersOnlyPattern = '[^0-9]'
    $versionOnlyPattern = '[^.0-9]'

    $downloadList = @(
        @{
            name="runme.bat";
            path=$PSScriptRoot + "/runme.bat";
            uri="https://raw.githubusercontent.com/fustilio/DPC-Scripts/master/runme.bat";
        },
        @{
            name="runme-license.bat";
            path=$PSScriptRoot + "/runme-license.bat";
            uri="https://raw.githubusercontent.com/fustilio/DPC-Scripts/master/runme-license.bat";
        },
        @{
            name="runme-noclean.bat";
            path=$PSScriptRoot + "/runme-noclean.bat";
            uri="https://raw.githubusercontent.com/fustilio/DPC-Scripts/master/runme-noclean.bat"
        },
        @{
            name="runme-noclean-qc.bat";
            path=$PSScriptRoot + "/runme-noclean-qc.bat";
            uri="https://raw.githubusercontent.com/fustilio/DPC-Scripts/master/runme-noclean-qc.bat"
        }

    )

    Try {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/fustilio/DPC-Scripts/master/install-all.ps1" -OutFile $tempFilePath
    }
    Catch {
        if ($UPDATE) {
            Write-Host "Could not check for new version, please check your internet connection or ping for help." -ForegroundColor Red
        } else {
            Write-Host "Update not available, continuing..." -ForegroundColor Red
        }
    }

    if (Test-Path ($tempFilePath)) {
    
        $tempVersion = (Get-Content $tempFilePath -First 1) -replace $versionOnlyPattern, ""
        $tempVersionNumber = $tempVersion -replace $numbersOnlyPattern, ""
        $currentVersionNumber = $currentVersion -replace $numbersOnlyPattern, ""
        
        if ($tempVersionNumber -ge $currentVersionNumber) {

            if ($UPDATE) {
                Write-Host Current Version is: v$currentVersion
                Write-Host Latest version is: v$tempVersion 

                if ($tempVersionNumber -ne $currentVersionNumber) {
                    Copy-Item $tempFilePath $PSCommandPath
                    Write-Host Updated install-all.ps1 to $tempVersion -ForegroundColor Green

                    Write-Host Executing update again to download other files
                    Powershell -Command "$PSCommandPath -UPDATE"
                } else {
                    Write-Host Downloading other files..
                
                    ForEach ($_ in $downloadList) {
                    
                        Try {
                            Invoke-WebRequest -Uri $_.uri -OutFile $_.path
                        }
                        Catch {
                            Write-Error Error downloading $_.name
                        }

                        if (Test-Path $_.path) {
                            Write-Host Successfully downloaded $_.name
                        }

                    }
                }
            } else {
                Write-Host "Latest version is: v$tempVersion." -ForegroundColor Yellow
                Write-Host "Run update.bat to update." -ForegroundColor Yellow
            }

            
        }

        if (Test-Path ($tempFilePath)) {
            Remove-Item $tempFilePath
        }

        if ($UPDATE) {
            PAUSE
            EXIT
        }

    }

    ###############################################################################################################################
    # Dump useful computer information
    $diskInfo = Get-CimInstance -Class CIM_DiskDrive |
        Select-Object -Property Name, Model, @{
            label='Size'
            expression={($_.Size/1GB).ToString('F2') + " GB"}
        }

    $allDisks = @()
    ForEach ($disk in $diskInfo) {
        $allDisks += $disk.Size.ToString()
    }


    Start-Service WinRM

    $info = Get-ComputerInfo
    $outputInfo = $info | Select-Object -Property @{
                                        name='Make'
                                        expression={$_.CsManufacturer}
                                    },
                                    @{
                                        name='System Family'
                                        expression={$_.CsSystemFamily}
                                    },
                                    @{
                                        name='Model'
                                        expression={$_.CsModel}
                                    },
                                    @{
                                        name='Serial Number'
                                        expression={$_.BiosSeralNumber}
                                    },
                                    @{
                                        name='CPU'
                                        expression={($_.CsProcessors | Select -First 1).Name}
                                    },
                                    @{
                                        name='RAM'
                                        expression={[Math]::Round(($_.CsTotalPhysicalMemory/1GB), 0).toString('F2') + " GB"}
                                    },
                                    @{
                                        name='Architecture'
                                        expression={$_.OsArchitecture}
                                    },
                                    @{
                                        name='Logical Processors'
                                        expression={$_.CsNumberOfLogicalProcessors}
                                    }


    Add-Member -InputObject $outputInfo -NotePropertyName 'Disk Size' -NotePropertyValue $allDisks
    Add-Member -InputObject $outputInfo -NotePropertyName 'Original Product Key' -NotePropertyValue (Get-CimInstance -Class SoftwareLicensingService).OA3xOriginalProductKey
    Add-Member -InputObject $outputInfo -NotePropertyName 'Original Product Key Description' -NotePropertyValue (Get-CimInstance -Class SoftwareLicensingService).OA3xOriginalProductKeyDescription
               
    $outputInfo | Format-List

    Stop-Service WinRM


    ###############################################################################################################################

    Write-Host Running battery checks -ForegroundColor Yellow

    Try{          
        $BattAssembly = [Windows.Devices.Power.Battery,Windows.Devices.Power.Battery,ContentType=WindowsRuntime] 
    }
    Catch
    {
        Write-Error "Unable to load the Windows.Devices.Power.Battery class"
    }
        
    Try{
        $Report = [Windows.Devices.Power.Battery]::AggregateBattery.GetReport() 
    }
    Catch{
        Write-Error "Unable to retrieve Battery Report information"
        Break
    }

    If ($Report.Status -ne "NotPresent")
    {
        
        if ($Report.DesignCapacityInMilliwattHours -ne 0) {
            $batteryHealth = $Report.FullChargeCapacityInMilliwattHours / $Report.DesignCapacityInMilliwattHours
        } else {
            $batteryHealth = 0
        }

        $data = @{
            Status = $Report.Status
            "Battery Health" = ($batteryHealth * 100).toString('F2') + "%"
            "Charge Rate (%/min)" = ($Report.ChargeRateInMilliwatts / $Report.FullChargeCapacityInMilliwattHours / 60 * 100).toString('F2') + "%"
        }
        
        New-Object PSObject -Property $data | Format-List
        
        if ($batteryHealth -eq 0) {
            Write-Host Battery is dead -ForegroundColor Red
        } elseif ($batteryHealth -lt 0.2) {
            Write-Host Battery is very weak -ForegroundColor Red
        } elseif ($batteryHealth -lt 0.6) {
            Write-Host Battery is weak -ForegroundColor Yellow
        } else {
            Write-Host Battery health is decent -ForegroundColor Green
        }
       
    }
    Else
    {
        Write-Host "Unable to detect working battery, please check." -ForegroundColor Red
    }

    Write-Host "`n"

    ###############################################################################################################################
    # SET TIME ZONE AND  RESYNC INTERNET TIME

    $tz = Get-TimeZone
    $correctTz = "Singapore Standard Time"

    if ($tz.id -ne $correctTz) {
        Write-Host Current Time Zone: $tz.id -ForegroundColor Yellow
        Set-TimeZone -Id $correctTz
        Write-Host New Time Zone: (Get-TimeZone).id 
    } else {
        Write-Host Current Time Zone: $tz.id -ForegroundColor Green
    }

    Write-Host "Synchronizing with internet clock, I hope you're connected to the internet." -ForegroundColor Yellow
    Start-Process "net" -ArgumentList "start w32time" -Wait | Out-Null
    $proc = Start-Process "w32tm" -ArgumentList "/resync" -Wait -PassThru -NoNewWindow

    if ($proc.ExitCode -eq 0) {
        Write-Host "Synchronization complete, the current date-time is" (Get-Date) -ForegroundColor Green
    } else {
        Write-Host "Synchronization failed, are you connected to the internet?" -ForegroundColor Red
    }

    Write-Host "`n"

    ###############################################################################################################################

    if ($LICENSE) {
        Write-Host Checking for existing licenses -ForegroundColor Yellow
        $licList = Get-CimInstance -Class SoftwareLicensingProduct |
            where {$_.name -match ‘windows’ -AND $_.LicenseFamily -AND $_.LicenseStatus -ne 0} |
                Select-Object -Property Name, `
                         @{Label= “License Status”; Expression={switch (foreach {$_.LicenseStatus}) `

                          { 0 {“Unlicensed”} `

                            1 {“Licensed”} `

                            2 {“Out-Of-Box Grace Period”} `

                            3 {“Out-Of-Tolerance Grace Period”} `

                            4 {“Non-Genuine Grace Period”} `

                            5 {“Notification”} `

                            6 {“Extended Grace Period”} `
                          } } }
        if ($licList -eq $null) {
            Write-Host No license found -ForegroundColor Red
        } else {
            Write-Host The following licenses were found: -ForegroundColor Green
            $licList | Format-List

        }
    }
 

    ###############################################################################################################################

    $modulePath = Join-Path -Path $PSScriptRoot -ChildPath "SwitchUACLevel.psm1"
    Import-Module $modulePath

    if ([System.Environment]::Is64BitOperatingSystem) {
        $Source = $Source64
    } else {
        $Source = $Source32
    }

    Write-Host Installing $(If([System.Environment]::Is64BitOperatingSystem) {"64-bit"} Else {"32-bit"}) applications listed in $Source -ForegroundColor Yellow

    Write-Host Supressing UAC notifications -ForegroundColor Yellow
    Set-UACLevel 0 | Out-Null

    Write-Host "`n"

    # Get list of applications to be installed
    $filePaths = Get-Content -Path (Join-Path -Path $PSScriptRoot -ChildPath $Source)

    # Define folder for logs
    $logFolderPath = Join-Path $PSScriptRoot -ChildPath "logs"

    foreach ($filePath in $filePaths) {
        $fullPath = Join-Path -Path $PSScriptRoot -ChildPath $filePath
        if ([IO.File]::Exists($fullPath)) {
        
            $DataStamp = get-date -Format yyyyMMddTHHmmss
            $logFile = '{0}-{1}.log' -f $filePath,$DataStamp
            $logFilePath = Join-Path -Path $logFolderPath -ChildPath $logFile

            $extn = [IO.Path]::GetExtension($fullPath)
   
            if ($extn -eq ".msi") {
                New-Item -ItemType File -Force -Path $logFilePath | Out-Null
                $MSIArguments = @(
                    "/i"
                    ('"{0}"' -f $fullPath)
                    "/qn"
                    "/norestart"
                    "/L*v"
                    $logFilePath
                )
                Write-Host Installing: $fullPath
                $proc = Start-Process "msiexec.exe" -ArgumentList $MSIArguments -PassThru -Wait #-NoNewWindow
                switch($proc.ExitCode) {
                    0    { Write-Host Successfully Installed: $fullPath -ForegroundColor Green; break }
                    1602 { Write-Host Error: $proc.ExitCode "User cancelled installation" -ForegroundColor Red; break }
                    1603 { Write-Host Error: $proc.ExitCode "Fatal error during installation" -ForegroundColor Red; break }
                    1639 { Write-Host Error: $proc.ExitCode "Invalid command line argument, check folder structure" -ForegroundColor Red; break }
                    3010 { Write-Host "Successfully Installed, restart required." -ForegroundColor Yellow; break }
                    default { Write-Host Error: $proc.ExitCode -ForegroundColor Red }                     
                }
                	
            } elseif ($extn -eq ".msp") {
                New-Item -ItemType File -Force -Path $logFilePath | Out-Null
                $MSIArguments = @(
                    "/p"
                    ('"{0}"' -f $fullPath)
                    "/qn"
                    "/norestart"
                    "/L*v"
                    $logFilePath
                )
                Write-Host Installing: $fullPath
                $proc = Start-Process "msiexec.exe" -ArgumentList $MSIArguments -PassThru -Wait #-NoNewWindow
                switch($proc.ExitCode) {
                    0    { Write-Host Successfully Installed: $fullPath -ForegroundColor Green; break }
                    1602 { Write-Host Error: $proc.ExitCode "User cancelled installation" -ForegroundColor Red; break }
                    1603 { Write-Host Error: $proc.ExitCode "Fatal error during installation" -ForegroundColor Red; break }
                    1639 { Write-Host Error: $proc.ExitCode "Invalid command line argument, check folder structure" -ForegroundColor Red; break }
                    3010 { Write-Host "Successfully Installed, restart required." -ForegroundColor Yellow; break }
                    default { Write-Host Error: $proc.ExitCode -ForegroundColor Red }                     
                }
            } elseif ($filePath -eq "Office\setup.exe") {
                $dir = [IO.Path]::GetDirectoryName($fullPath)
                $configPath = Join-Path -Path $dir -ChildPath "configuration.xml"

                # Check if config file exists
                if ([IO.File]::Exists($configPath)) {
                    Write-Host Configuration File Found
                    Write-Host Installing: $fullPath
                    $cmd = $fullPath.ToString() + " `/configure " + $configPath.ToString()
                    $proc = Invoke-Expression $cmd
                    Write-Host Done -ForegroundColor Green
                } else {
                    Write-Host Error: No Config Found -ForegroundColor Red
                }
            
            } else {
                Write-Host Error: Unidentified Extension -ForegroundColor Red
            }
        } else {
            Write-Host File $fullPath does not exist
        }
    }

    # Revert UAC Settings to default
    Set-UACLevel 2 | Out-Null
    Write-Host Restored UAC settings to Default -ForegroundColor Yellow

    ###############################################################################################################################

    if ($DEFENDER) {
        Write-Host Testing for Network -ForegroundColor Yellow
        $ping = Test-NetConnection
        $status = Get-MpComputerStatus
        $currVer = $status.AntivirusSignatureVersion
        Write-Host Windows Defender last updated on $status.AntispywareSignatureLastUpdated
        if ($ping.PingSucceeded) {
            Write-Host Network Detected -ForegroundColor Yellow
            Write-Host Updating Windows Defender antimalware definitions -ForegroundColor Yellow
            Update-MpSignature
            $status = Get-MpComputerStatus
            if ($status.AntivirusSignatureVersion -eq $currVer) {
                Write-Host Windows Defender is already up-to-date. -ForegroundColor Green
            } else {
                Write-Host Windows Defender Signature Version is now $status.AntivirusSignatureVersion -ForegroundColor Green
            }
        } else {
            Write-Host No Network Detected -ForegroundColor Red
            Write-Host Update Windows Defender when internet connection is available. -ForegroundColor Red
        }
    }

    ###############################################################################################################################
    # QC STUFF

    Filter findActivePath {
        if (Test-Path $_) {
            $_
        }
    }


    if ($CHECK) {
        Write-Host Running QC Checks

        #kill all known programs for testing

        $processList = @("chrome", "AcroRd32", "soffice", "zoom")

        ForEach ($_ in $processList) {
            $proc = Get-Process $_ -ErrorAction SilentlyContinue
            if ($proc) { 
                $proc.CloseMainWindow()
                Sleep 5
                if (!$proc.HasExited) {
                    $proc | Stop-Process -Force | Out-Null
                }
            }
        }

        $counter = 0

  
        Write-Host "Starting SW Test 1/5 - Chrome..."
        $list = @("C:\Program Files (x86)\Google\Chrome\Application\chrome.exe", "C:\Program Files\Google\Chrome\Application\chrome.exe")
        $testProgram = $list | findActivePath | Select -First 1
        If ($testProgram) {
            Start-Process $testProgram
            Start-Sleep 3
            Write-Host "SW Test Passed. Chrome started." -ForegroundColor green
            $counter++
        } else {
            Write-Host "Chrome is not installed or does not exist in the standard location." -ForegroundColor red
        }
        "`n"

        Write-Host "Starting SW Test 2/5 - Acrobat..."
        $list = @("C:\Program Files (x86)\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe")
        $testProgram = $list | findActivePath | Select -First 1
        If ($testProgram) {
            Start-Process $testProgram
            Start-Sleep 3
            Write-Host "SW Test Passed. Acrobat started." -ForegroundColor green
            $counter++
        } else {
            Write-Host "Acrobat is not installed or does not exist in the standard location." -ForegroundColor red
        }
        "`n"

        Write-Host "Starting SW Test 3/5 - LibreOffice..."
        $list = @("C:\Program Files\LibreOffice\program\soffice.exe")
        $testProgram = $list | findActivePath | Select -First 1
        if ($testProgram) {
            Start-Process "C:\Program Files\LibreOffice\program\soffice.exe"
            Start-Sleep 5
            Write-Host "SW Test Passed. LibreOffice started." -ForegroundColor green
            $counter++
            
        } else {
            Write-Host "LibreOffice is not installed or does not exist in the standard location." -ForegroundColor red
        }
        "`n"


        do {
            $ping = Test-NetConnection
            $pingResult = $ping.PingSucceeded
            Write-Host "Please connect to WiFi manually before we can continue." -ForegroundColor green
        }
        while ($pingResult -eq $false) {
            $ping = Test-NetConnection
            $pingResult = $ping.PingSucceeded
        }

        Write-Host "Starting SW Test 4/5 - Joining Zoom Meeting..."
        $ZoomAppDataPath =  [Environment]::GetFolderPath('ApplicationData') + "\Zoom\bin\Zoom.exe";
        $list = @("C:\Program Files (x86)\Zoom\bin\Zoom.exe", $ZoomAppDataPath);
        $testProgram = $list | findActivePath | Select -First 1
        If ($testProgram) {
            Start-Process "zoommtg://zoom.us/join?confno=3966517262&zc=0&uname=User"
            Start-Sleep 5
            Write-Host "SW Test Passed. Zoom started." -ForegroundColor green
            $counter++
        } else {
            Write-Host "Zoom is not installed or does not exist in the standard location." -ForegroundColor red
        }
   
        "`n"

        Start-Sleep 5


        Write-Host "Starting SW Test 5/5 Copying Joseph Schooling Video to Desktop..."
        Set-Location $PSScriptRoot
        $DesktopPath = [Environment]::GetFolderPath("Desktop")
        Copy-Item "Team Singapore Surprise.mp4" -Destination $DesktopPath
        $VidPath = Join-Path -Path $DesktopPath -ChildPath "\Team Singapore Surprise.mp4"
        $testProgram = Test-Path $VidPath
        If (Test-Path $VidPath) {
            Start-Process $VidPath
            Start-Sleep 5
            Write-Host "SW Test Passed. Joseph Schooling Video played." -ForegroundColor green
            $counter++
        else {
            Write-Host "Joseph Schooling Video is not found on Desktop. Please copy it manually." -ForegroundColor red}
        }
        "`n"

    
        $list = @("C:\Program Files\Microsoft Office\Office16", "C:\Program Files (x86)\Microsoft Office\Office16");
        $testProgram = $list | findActivePath | Select -First 1

        If ($testProgram) {
            Set-Location $testProgram
        } else {
            Write-Host "Office is not installed."
        }

        $officeActivation = cscript ospp.vbs /dstatus
        If ($officeActivation -match "---LICENSED---"){
            Write-host "Office is activated." -ForegroundColor green
        } else {
            Write-Host "Office is not activated." -Foreground red
        }
        "`n"

        slmgr /xpr
        Write-host "See pop up for Windows Activation status."


        "`n"
        If ($counter -eq 5) {
            Write-Host "QC Software passed." -ForegroundColor green
        } else {
             Write-Host "QC Software failed. Please review the log to find what failed." -Foreground red
        }

        "`n"

    }

    ###############################################################################################################################

    if ($CLEANUP) {
        Write-Host "Running Windows disk cleanup tool" -ForegroundColor Yellow     
        

        $strKeyPath = “SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches”
        $strValueName = “StateFlags0314”

        $subkeys = gci -Path HKLM:\$strKeyPath -Name
        ForEach ($subkey in $subkeys) {
            Try {
                New-ItemProperty -Path HKLM:\$strKeyPath\$subkey -Name $strValueName -PropertyType DWord -Value 2 -ErrorAction SilentlyContinue | Out-Null
            }
            Catch {
            }
        
        }

        Try {
            Start-Process cleanmgr -ArgumentList “/sagerun:314” -Wait -NoNewWindow -ErrorAction SilentlyContinue -WarningAction SilentlyContinue
        }

        Catch {
        }

        #Write-Host "Running AUTOCLEAN"
        #Start-Process "cleanmgr.exe" -ArgumentList "/AUTOCLEAN" -PassThru -Wait

        #Start-Process "cleanmgr.exe" -ArgumentList "/VERYLOWDISK" -PassThru -Wait

        Write-Host "Disk cleanup tool completed"

        Write-Host "Checking for old files, please check through and manually confirm deletion..." -ForegroundColor Yellow  


        
        $scriptPath = Split-Path -parent $MyInvocation.MyCommand.Definition

        function Get-RootFolder
        {
            param
            (
                $Path
            )

            $item = Get-Item -Path $Path
            if ($item.FullName -ne $Item.Root.FullName)
            {
                Get-RootFolder -Path $Item.Parent.FullName | Write-Output 
            }
            else
            {
                Write-Output $Item.FullName
            }
        }


                $rootDrive = Get-RootFolder -Path $scriptPath

                $allDrives = Get-PSDrive -PSProvider 'FileSystem'

                $currentDateTime = Get-Date
                $recentDateTime = $currentDateTime.AddDays(-7)

        $filesToDelete = @()
        $fileNames = @()

        ForEach ($drive in $allDrives) {
   
            if ($drive.Root -ne $rootDrive) 
            {
                if (Test-Path $drive.Root) 
                {
                    Get-ChildItem $drive.Root |
                        ForEach-Object {
                           if ($_.LastWriteTime -lt $recentDateTime -or $_.Name -eq "Windows.old") 
                           {
                                $filesToDelete += $_
                                $fileNames += $_.FullName
                           }
                        }
                }

            }
        }

        if ($filesToDelete.Length -eq 0) {
            Write-Host "Scan complete, no files to be deleted found." -ForegroundColor Green
        } else {

            $formattedList = $filesToDelete | Format-Wide -Property FullName -Column ([int]([math]::max(($filesToDelete.Length / 20), 1))) | Out-String


            $title = "Delete confirmation?"
            $question = "The following files, folders and their contents will be deleted: " + $formattedList

            $choices = "&Yes", "&No"

            $decision = $Host.UI.PromptForChoice($title, $question, $choices, 1)


            if ($decision -eq 0) 
            {
                ForEach ($file in $filesToDelete) {
                    Remove-Item -Recurse -Force -Path $file.FullName
                }

                Write-Host "Files deleted."
            } 
            else 
            {
                Write-Host "Delete aborted, please do manual check and deletion."
            }
            
        }

        ForEach ($subkey in $subkeys) {
            Try {
                Remove-ItemProperty -Path HKLM:\$strKeyPath\$subkey -Name $strValueName | Out-Null
            }
            Catch {
            }
        }  


        Write-Host "Clean Up Completed" -ForegroundColor Green

    }

    ###############################################################################################################################

    $title = "Remove Wifi profiles?"
    $question = "Would you like to remove all Wifi profiles on this machine?"

    $choices = "&Yes", "&No"

    $decision = $Host.UI.PromptForChoice($title, $question, $choices, 0)


    if ($decision -eq 0) 
    {
        netsh wlan delete profile name=* i=*
        Write-Host "Wifi profiles deleted" -ForegroundColor Green
    } 
    else 
    {
        Write-Host "WiFi profiles unchanged" -ForegroundColor Yellow
    }

}

END {
    Write-Host "That's all folks, remember to save the computer's details" -ForegroundColor Yellow
    PAUSE
    PAUSE
}

