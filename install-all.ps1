<# v1.0.8
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
    [switch] $UPDATE = $false
)

BEGIN {

    $currentVersion = "1.0.8"
    $currentVersionDate = "29/04/2020"
    Write-Host Hello there! This is the DPC software install script! -ForegroundColor Yellow
    Write-Host "Current version of the script is v$currentVersion last updated on $currentVersionDate." -ForegroundColor Yellow
    

}

PROCESS {

    if ($UPDATE) {

        $currentFilePath = $PSCommandPath
        $tempFilePath = $PSScriptRoot + "/install-all-temp.ps1"
        $runmePath = $PSScriptRoot + "/runme.bat"
        $runmeLicPath = $PSScriptRoot + "/runme-license.bat"
        $numbersOnlyPattern = '[^0-9]'
        $versionOnlyPattern = '[^.0-9]'

        Try {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/fustilio/DPC-Scripts/master/install-all.ps1?token=AFRXBMYU37LJHDRNTPZ4TSS6WF3O4" -OutFile $tempFilePath
        }
        Catch {
            Write-Error "Web request failed, check URL?"
        }

        if (Test-Path ($tempFilePath)) {
    
            $tempVersion = (Get-Content $tempFilePath -First 1) -replace $versionOnlyPattern, ""
            $tempVersionNumber = $tempVersion -replace $numbersOnlyPattern, ""
            $currentVersioNumber = $currentVersion -replace $numbersOnlyPattern, ""
            Write-Host Latest version is: $tempVersion
            Write-Host Current Version is: $currentVersion
            if ($tempVersionNumber -gt $currentVersioNumber) {
                Copy-Item $tempFilePath $PSCommandPath
                Write-Host Updated install-all.ps1 to $tempVersion -ForegroundColor Green

                if (-not (Test-Path $runmePath)) {
                    Try {
                        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/fustilio/DPC-Scripts/master/runme.bat?token=AFRXBM5AWJ3IEQYIZXMKXRC6WHFGA" -OutFile $runmePath
                    }
                    Catch {
                        Write-Error "Error downloading runme.bat"
                    }

                    if (Test-Path $runmePath) {
                        Write-Host "Successfully downloaded runme.bat"
                    }
                }

                if (-not (Test-Path $runmeLicPath)) {
                    Try {
                        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/fustilio/DPC-Scripts/master/runme-license.bat?token=AFRXBM5DOQ3ILJJJULWW35S6WHFM4" -OutFile $runmeLicPath
                    } 
                    Catch {
                        Write-Error "Error downloading runme-license.bat"
                    }

                    if (Test-Path $runmeLicPath) {
                        Write-Host "Successfully downloaded runme-license.bat"
                    }
                }
                }
            }

            Remove-Item $tempFilePath
        }

        PAUSE
        EXIT

    }

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

        $batteryHealth = $Report.FullChargeCapacityInMilliwattHours / $Report.DesignCapacityInMilliwattHours

        $data = @{
            Status = $Report.Status
            "Battery Health" = ($batteryHealth * 100).toString('F2') + "%"
            "Charge Rate (%/min)" = ($Report.ChargeRateInMilliwatts / $Report.FullChargeCapacityInMilliwattHours / 60 * 100).toString('F2') + "%"
        }
        
        New-Object PSObject -Property $data | Format-List

        if ($batteryHealth -lt 0.2) {
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
                if ($proc.ExitCode -eq 0) {
                    Write-Host Successfully Installed: $fullPath -ForegroundColor Green
                } else {
                    switch($proc.ExitCode) {
                        1602 { Write-Host Error: $proc.ExitCode "User cancelled installation" -ForegroundColor Red; break }
                        1603 { Write-Host Error: $proc.ExitCode "Fatal error during installation" -ForegroundColor Red; break }
                        1639 { Write-Host Error: $proc.ExitCode "Invalid command line argument, check folder structure" -ForegroundColor Red; break }
                        default { Write-Host Error: $proc.ExitCode -ForegroundColor Red }                     
                    }
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
                if ($proc.ExitCode -eq 0) {
                    Write-Host Successfully Installed: $fullPath -ForegroundColor Green
                } else {
                    switch($proc.ExitCode) {
                        1602 { Write-Host Error: $proc.ExitCode "User cancelled installation" -ForegroundColor Red; break }
                        1603 { Write-Host Error: $proc.ExitCode "Fatal error during installation" -ForegroundColor Red; break }
                        1639 { Write-Host Error: $proc.ExitCode "Invalid command line argument, check folder structure" -ForegroundColor Red; break }
                        default { Write-Host Error: $proc.ExitCode -ForegroundColor Red }                     
                    }
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



}

END {
    Write-Host "That's all folks, remember to save the computer's details" -ForegroundColor Yellow
    PAUSE
    PAUSE
}

