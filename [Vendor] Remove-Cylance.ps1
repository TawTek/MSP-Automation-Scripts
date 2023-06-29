param (
    # Required for CLI, Optional for UI
    # Specify if the safemode is set to Yes/No.
    #   Yes will allow you to test the script without making any system changes
    #   No will allow for deleting/modification of system.
    [Parameter(HelpMessage = 'safemode (Yes/No)- Default: Yes | When set to Yes, no changes will be made to the system.')]
    [ValidateSet("Yes", "No")]
    [string]$safemode = 'Yes',
    [Parameter(HelpMessage = 'PartialCleanup (Yes/No) - Default: No | When set to Yes, ProgramData is backed up and restored. This should not be used unless advised.')]
    [ValidateSet("Yes", "No")]
    [string]$PartialCleanup = 'No',
    [Parameter(HelpMessage = 'Pause (Yes/No) - Default: Yes | When set to No, all pauses are excluded and the script exits in all cases.')]
    [ValidateSet("Yes", "No")]
    [string]$Pause = 'Yes',
    [Parameter(HelpMessage = 'If you use a uninstall password in Venue UI, specify it here in single quotes.')]
    [String]$uninstallpassword
)

# Check for CPU architecture and re-encode the script on 64-bit systems.
if ($env:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    $x64PS = Join-Path $PSHome.ToLower().Replace("syswow64", "sysnative").Replace("system32", "sysnative") Powershell.exe
    $cmd = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($myinvocation.MyCommand.Definition))
    $Out = & "$x64PS" -NonInteractive -NoProfile -ExecutionPolicy Bypass -EncodedCommand $cmd
    $Out
    exit $LASTEXITCODE
  }

if ($safemode -eq "No") {
    $global:SkipPauseAfter10s = "Yes"
}

[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

$ScriptInfo = '
 *************************************************************************************************************************
 *  Support Script: Uninstall_Cleanup_EPP_EDR.ps1
 *  Created: 06/13/2022 by SDS
 *  Updated: 04/27/2023 by SDS
 *  Version: 4.5
 *  Tracked via: SDT00052661
 *  Description: Script to automate the windows cleanup of Cylance Protect and Cylance Optics - KB 66473
 *
 *  Instructions for running script:
 *    1. When possible, administrators should assign a policy with "Prevent Service Shutdown" disabled, as well as "Script Control" disabled.
 *    2. When possible, run the script using the NT AUTHORITY\SYSTEM account. (An example of this is using psexec -s )
 *    3. Run the script with "-safemode Yes" as a test run
 *    4. When ready to make changes, set the safemode flag set to "No"
 *    5. In some cases, the script may require a reboot and or reboot and rerun of the script.
 *
 * Switches:
 *   -safemode - Yes/No - safemode Yes will not make any changes. Defaults to Yes
 *   -uninstallpassword - Specify the uninstall password if needed in single quotes. Defaults to No
 *   -Pause - Yes/No - Script will pause at the end to let the end-user know if a restart and re-run is required. In some cases (CLI push), you may not want
 *                      the script to pause. In all cases, the script does have a audit log to review. . Defaults to Yes
 *
 * Example for unintended runs as administrator
 *  .\Uninstall_Cleanup_EPP_EDR.ps1 -safemode No -uninstallpassword ''mypassword''
 *  .\Uninstall_Cleanup_EPP_EDR.ps1 -safemode Yes -uninstallpassword ''mypassword''
 *
 * Example for unintended runs as NT AUTHORITY\SYSTEM
 *  .\psexec -accepteula -i -s Powershell -ExecutionPolicy Bypass -File C:\<Path>\Uninstall_Cleanup_EPP_EDR.ps1 -safemode No -uninstallpassword ''mypassword''
 *  .\psexec -accepteula -i -s Powershell -ExecutionPolicy Bypass -File C:\<Path>\Uninstall_Cleanup_EPP_EDR.ps1 -safemode Yes -uninstallpassword '' mypassword''
 *
 *************************************************************************************************************************
'

function Check-Permissions {
    # Settings Variables
    $global:safemode = $safemode
    $global:uninstallpassword = $uninstallpassword
    $KeyName = ""
    $MultiStringValue = ""
    $Registrykeys = ""
    $Result = ""
    $global:Continue = "Yes"
    $global:KWildcard = ""
    $global:MultiStringName = ""
    $global:Originalkey = ""
    $global:RegOutputFile = ""
    $global:RegistryPath = ""
    $global:RemoveDelete_Value = ""
    $global:SafeExportName = ""
    $global:SafeFileName = ""
    $global:Servicevalue = ""
    $installed = ""
    $global:DateTime = ""
    $global:FolderName = ""
    $global:Folder = ""
    $global:dirPath = ""
    $global:RunAsNtSystem = ""
    $global:RestartWarning = 0
    $global:RestartRequired = 0
    $global:ElamRestart = 0
    $global:Protect2 = 0
    $global:Protect3 = 0
    $is64bitOS = ""
    $Arch = ""

    $global:DateTime = $(get-date -f yyyy-MM-dd_hh_mm);
    $global:FolderName = "Protect_Optics_Uninstall_Results";
    $global:Folder = $global:FolderName + "_" + $global:DateTime;
    $global:dirPath = $PSScriptRoot + "\" + $global:Folder
    try {
        New-Item -ItemType directory -Path $global:dirPath
        Write-Host ""
    }
    catch {
        Write-Warning "Exception caught";
        Write-Warning "$_";
        Exit 1;
    }
    $global:RegBackupFolder = $global:dirPath + "\RegBackup"
    Write-Host "Starting Transcript_log"
    try {
        Start-Transcript -path $global:dirPath\Transcript_log.txt -Append #Start logging from this point
    } catch {
        Write-Warning "Exception caught";
        Write-Warning "$_";
    }

    Write-Host $ScriptInfo
    Write-Host ""
    Write-Host ""
    Write-Host "Starting Script via: .\Uninstall_Cleanup_EPP_EDR.ps1 -safemode $safemode -partialCleanup $PartialCleanup -pause $Pause -uninstallpassword $uninstallpassword"
    Write-Host ""

    # Start of Check-Permissions
    Write-Host "Checking for elevated permissions..."
    $whoami = ""
    $whoami = (whoami)

    $PSVersion = ""
    $PSVersion = $PSVersionTable.PSVersion.Major

    if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
                [Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Warning "Insufficient permissions to run this script. Open the PowerShell console as an administrator and run this script again."
        Write-Host ""
        Write-Host ""
        Break
    }
    else {
        Write-Host "Script is running as administrator..." -ForegroundColor Green
    }

    $ntsystem = 'nt authority\system'
    If (($whoami -like '*authority*')) {
        Write-Host "Script is running as $ntsystem..." -ForegroundColor Green
        Write-Host ""
        $global:RunAsNtSystem = "Yes"
    }
    else {
        Write-Warning "Script is not running as $ntsystem. Extra restarts may be needed."
        Write-Host "   .\psexec -i -s powershell"
        Write-Host ""
    }

    # Check to see if your PS windows is running in x86 or x64 (AMD64/x86)
    $Arch = (Get-Process -Id $PID).StartInfo.EnvironmentVariables["PROCESSOR_ARCHITECTURE"];
    if ($Arch -eq 'x86') {
        Write-host 'Running 32-bit PowerShell'
    }
    elseif ($Arch -eq 'amd64') {
        Write-host 'Running 64-bit PowerShell'
    }

    # Check to see if your version of WIndows is 64bit (True/False)
    $is64bitOS = [System.Environment]::Is64BitOperatingSystem
    if ($is64bitOS -eq 'True') {
        Write-host 'Running 64-bit OS'
    }
    elseif (!$is64bitOS) {
        Write-host 'Running 32-bit OS'
    }

    # Check if you are running x86 version of powershell on windows x64
    # No point to continue here as a bunch of cmdlets will fail
    if ($Arch -eq 'x86' -and $is64bitOS -eq 'False') {
        Write-Host "You are running a x86 version of Powershell on Windows x64, Registry cleanup may fail. Please switch to x64 version of powershell."
        If ($Pause -eq "No") {
            exit 1
        }
        else {
            pause
            exit 1
        }
    }

} # End of Check-Permissions

function Check_DisableRegistryTools {
    if (Test-Path -Path "Registry::HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System") {
        $global:Originalkey = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        $HiveAbr = $global:Originalkey.Substring(0, $global:Originalkey.IndexOf(':'))
        $Hivepath = $global:Originalkey.Substring($global:Originalkey.IndexOf('\') + 1)
        Write-Host ""
        Write-Host "Checking if DisableRegistryTools is enabled in the Registry"
        try {
            $DisableRegistryTools = (Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System -ErrorAction Stop).DisableRegistryTools
        }
        catch {
            # Start catch
            Write-Warning "Exception caught";
            Write-Warning "$_";
        } # End catch

        If ( $DisableRegistryTools -eq 2) {
            Write-Host " 'DisableRegistryTools' is Enabled($DisableRegistryTools)" -fore Yellow
            Write-Host "Exiting Script as we cant make registry changes" -fore Red
            Exit 1;
        }
        else {
            Write-Host "DisableRegistryTools is not Enabled";
            Write-Host ""
        }
    }
    else {
        Write-Host "DisableRegistryTools is not Enabled";
        Write-Host ""
    }
} # End of check GPO DisableRegistryTools

function variables {
    if ($global:safemode -eq $null -or $global:safemode -eq '') {
        ###################################################################################################
        ###########################    THE ONLY VALUE YOU SHOULD CHANGE IS THIS ###########################
        ###################################################################################################
        $global:safemode = "Yes"; # Change this to "No" to make edits to the registry. "Yes" will allow the script to run but not change anything

        ###################################################################################################
        ###########################    THE ONLY VALUE YOU SHOULD CHANGE IS THIS ###########################
        ###################################################################################################

        Write-Host "safemode Flag was incorrect or blank. Settings to Yes"
    }
    else {
        Write-Host "safemode was set via CLI to: $global:safemode"
    }

    if ($global:safemode -eq "Yes") {
        Write-Host "safemode is Enabled. No Changes will be made." -ForegroundColor Green
    }
    elseif ($global:safemode -eq "No") {
        Write-Warning "safemode is Disabled. Changes will be made."
        if ($global:SkipPauseAfter10s -eq "Yes") {
            Write-Host "Pausing for 10s"
            Write-Host ""
            Start-Sleep -Seconds 5
        }
        else {
            exit 1
        }
    }
    else {
        Write-host "Invalid safemode flag"
        try { Stop-Transcript } catch {}
        exit 1
    }

    $global:MultiStringName = "UpperFilters"; # UpperFilters is the name of the Multi-String Name
    $global:RemoveDelete_Value = "CyDevFlt"; # CyDevFlt is the name of the value to remove
    $global:RemoveDelete_Value2 = "CyDevFltV2"; # CyDevFlt is the name of the value to remove
    $global:RegistryPath = "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\class";

} # End of Variables for script

function PartialCleanupBackup {
    # This is a hidden function that is only called with -partialCleanup Yes/No
    # When you use -partialCleanup Yes the programData folder is backed up and restored after the script is run in prep upcoming activities

    If ($PartialCleanup -eq "Yes" -and $safemode -eq "No") {
        Write-Host "PartialCleanup is: $PartialCleanup"

        $sourceFolders = @(
        (${Env:ProgramData} + "\Cylance")
        )

        foreach ($sourceFolder in $sourceFolders) {

            Write-Host "Source Folder: $sourceFolder"

            # Set the path of the temporary directory where the folder will be created
            $global:tempDir = ${Env:TEMP}

            # Set the name of the folder you want to create
            $global:folderName = "Cylance_ProgramData_Backup"

            # Check if the folder already exists
            if (-not (Test-Path "$global:tempDir\$global:folderName")) {
                # Create the folder if it does not exist
                try {
                    New-Item -ItemType Directory -Path "$global:tempDir\$global:folderName" | Out-Null
                    Write-Host "Temp Folder created successfully."
                    Write-Host "  Folder: $global:tempDir\$global:folderName"
                }
                catch {
                    Write-Host "An error occurred creating the backup folder:"
                    Write-Host $_
                    try { Stop-Transcript } catch {} # Stop logging here
                    exit 1
                }
            }
            else {
                Write-Host "Temp Folder already exists."
                try {
                    # Get the date of the existing folder
                    $NewDate = ""
                    $NewDate = Get-Item "$global:tempDir\$global:folderName" | Select-Object -ExpandProperty CreationTime | Get-Date -f "yyyyMMdd_hhmmss"

                    #Rename the folder to append the create time
                    Rename-Item -Path "$global:tempDir\$global:folderName" -NewName ${global:folderName}_$NewDate | Out-Null
                    Write-Host "Renamed old Folder from $global:folderName to ${global:folderName}_$NewDate"
                }
                catch {
                    Write-Host "An error occurred with rename/re-create folder:"
                    Write-Host $_
                    try { Stop-Transcript } catch {} # Stop logging here
                    exit 1
                }

                # Create the folder
                try {
                    New-Item -ItemType Directory -Path "$global:tempDir\$global:folderName" | Out-Null
                    Write-Host "Temp Folder created successfully."
                    Write-Host "  Folder: $global:tempDir\$global:folderName"
                }
                catch {
                    Write-Host "An error occurred creating the backup folder 2:"
                    Write-Host $_
                    try { Stop-Transcript } catch {} # Stop logging here
                    exit 1
                }
            }
            # Check if the source folder exists before copying it to the temporary directory
            if (Test-Path $sourceFolder) {

                $Grant = "/grant:r"
                #$Remove = "/remove"
                $replaceInherit = "/inheritance:e"
                $permission = ":(OI)(CI)(F)"
                $useraccount2 = "Administrators"

                # If you are not running as System user, \ProgramData\Cylance\Desktop\q folder will fail to copy
                Invoke-Expression -Command ('icacls $sourceFolder $Grant "${useraccount2}${permission}" /Q /T' 2>&1) *> $null
                Invoke-Expression -Command ('icacls $sourceFolder $replaceInherit /Q /T') *> $null

                try {
                    Copy-Item $sourceFolder $global:tempDir\$global:folderName -Recurse -Force
                }
                catch {
                    Write-Information "$_";
                }

                # Get a count of the files in both locations to check if the copy was successful
                $SourceCount = (Get-ChildItem $sourceFolder -File -Recurse | Measure-Object).count
                $BackupCount = (Get-ChildItem $global:tempDir\$global:folderName -File -Recurse | Measure-Object).count

                If ($SourceCount -eq $BackupCount) {
                    Write-Host "Temp folder backed up all $BackupCount files"
                }
                elseif ($BackupCount -eq 0 -and $SourceCount -ne 0) {
                    Write-Host "No Files backed up"
                    try { Stop-Transcript } catch {} # Stop logging here
                    exit 1
                }
                elseif ($BackupCount -ne $SourceCount) {
                    Write-Host "1 or more files did not backup"
                }

            }
            else {
                Write-Host "Source folder does not exist."
                exit 1
            }
        }
    }

}

function PartialCleanupRestore {
    # This is a hidden function that is only called with -partialCleanup Yes/No
    # When you use -partialCleanup Yes the programData folder is backed up and restored after the script is run in prep upcoming activities

    If ($PartialCleanup -eq "Yes" -and $safemode -eq "No") {
        Write-Host "PartialCleanup is: $PartialCleanup"

        $sourceFolders = @(
            (${Env:ProgramData} + "\Cylance")
        )

        foreach ($sourceFolder in $sourceFolders) {

            # Set the path of the temporary directory where the folder will be created
            $global:tempDir = ${Env:TEMP}

            # Set the name of the folder you want to create.
            $global:folderName = "Cylance_ProgramData_Backup\Cylance"

            if (Test-Path "$global:tempDir\$global:folderName") {
                Write-Host "Found backup data: $global:folderName"
                try {
                    Copy-Item $global:tempDir\$global:folderName $sourceFolder -Recurse -Force
                }
                catch {
                    Write-Information "$_";
                }

                # Get a count of the files in both locations to check if the copy was successful
                $SourceCount = (Get-ChildItem $sourceFolder -File -Recurse | Measure-Object).count
                $BackupCount = (Get-ChildItem $global:tempDir\$global:folderName -File -Recurse | Measure-Object).count

                If ($SourceCount -eq $BackupCount) {
                    Write-Host "Temp folder Restored all $BackupCount files"
                }
                elseif ($BackupCount -eq 0 -and $SourceCount -ne 0) {
                    Write-Host "No Files Restored up"
                    try { Stop-Transcript } catch {} # Stop logging here
                    exit 1
                }
                elseif ($BackupCount -ne $SourceCount) {
                    Write-Host "1 or more files did not Restore"
                }

            }
            else {
                Write-Host "Could not Found any backed up data: $global:folderName"
            }

        }
    }
}

function Try_Add/Remove {
    #Attempt Add/Remove of Optics/Protect using Uninstaller
    Write-Host ""
    Write-Host "Attempting to uninstall using Add/Remove programs silently..."
    Write-Host "... This make take a few minutes"
    Write-Host ""
    if ($global:safemode -eq "No") {
        $software = ""
        $software = @(
            ####################################################
            # Protect Needs to be last in this list if enabled #
            ####################################################
              'Cylance OPTICS'
            , 'Cylance Unified Agent'
            , 'Cylance PROTECT'
            , 'Cylance PROTECT with OPTICS'
            #,'Cylance Platform' # Installed With DLP 1.0 | Persona 1.3
            #,'CylanceGATEWAY' # Gateway 2.5
            #,'CylanceAVERT' # DLP 1.0
            #,'CylanceAVERT and Platform' # DLP 1.0
            #,'BlackBerry Persona Agent' # Installed with Persona 1.3
        )

        $i = ""
        foreach ($i in $software) {
            $applicationName = $i

            # Get the uninstall registry key for the application
            $appKeys = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { $_.DisplayName -eq $applicationName }
            foreach ($appKey in $appKeys) {

                # If the application is not found, exit the script
                if (!$appKey) {
                    Write-Host "Application not found in Add/Remove: $applicationName"
                    Write-Host ""
                }
                else {

                    # Get the uninstall string for the application
                    $DisplayName = $appKey.DisplayName
                    if ($DisplayName) {
                        Write-Host "DisplayName: $DisplayName"
                    }

                    # Get the uninstall string for the application
                    $uninstallString = $appKey.UninstallString
                    if ($uninstallString) {
                        Write-Host "   Reg UninstallString: $uninstallString"
                        #Write-Host ""
                    }

                    # Get the uninstall version for the application
                    $DisplayVersion = $appKey.DisplayVersion
                    if ($DisplayVersion) {
                        Write-Host "   DisplayVersion: $DisplayVersion"
                        #Write-Host ""
                    }

                    # If the uninstall command is not found, exit the script
                    if (!$uninstallString) {
                        Write-Host "   Uninstall command not found in registry for application: $applicationName"
                    }
                    else {
                        if ($applicationName -eq "Cylance Protect") {
                            Write-Host "   Attempting to stop CylanceSvc with a 15s timeout"
                            # Attempt Shutdown of Protect

                            $ProgramFilePaths = @(
                                (${Env:Programfiles} + "\Cylance\Desktop")
                            #, (${Env:ProgramFiles(x86)} + "\Cylance\Desktop")
                            )

                            foreach ($ProgramFilePath in $ProgramFilePaths) {
                                if(Test-Path "$ProgramFilePath\CylanceSVC.exe" -PathType Leaf) {
                                    Start-Process -NoNewWindow -ErrorAction Stop -FilePath $ProgramFilePath\CylanceSvc.exe -ArgumentList "/shutdown"
                                    Start-Sleep -Seconds 15
                                }
                            }

                            if ($uninstallString -like '*MsiExec*' ) {
                                Write-Host "   Uninstalling $applicationName Silently..."
                                # Remove any switches from the uninstall command but keeps the last quote
                                $uninstallString_exe, $uninstallString_switch = $uninstallString.split(' ')

                                $timeout = 240 # Timeout in seconds
                                if ($global:uninstallpassword -eq $null -or $global:uninstallpassword -eq '') {
                                    Write-Host "   Uninstall password not set"
                                    $process = Start-Process -NoNewWindow -ErrorAction Stop -FilePath "$uninstallString_exe" -ArgumentList "$uninstallString_switch /qn /norestart /Lxv* $global:dirPath\Protect_Uninstall_MsiExec.log" -PassThru
                                } else {
                                    Write-Host "   Uninstall password set"
                                    $process = Start-Process -NoNewWindow -ErrorAction Stop -FilePath "$uninstallString_exe" -ArgumentList "$uninstallString_switch /qn /norestart /Lxv* $global:dirPath\Protect_Uninstall_MsiExec.log UNINSTALLKEY=$global:uninstallpassword" -PassThru
                                }
                                if ($process.WaitForExit($timeout * 1000)) {
                                    Write-Host "   MSI uninstallation finished"
                                } else {
                                    Write-Host "   MSI uninstallation timed out after $timeout seconds"
                                    Write-Host "   process.Id: $process.Id"
                                    Stop-Process -Id $process.Id -Force
                                }

                                $Search = "Cylance_PROTECT*.log"
                                Write-Host "   Copying logs..."
                                get-Item -Path $env:TEMP\$Search | Copy-Item -Destination $global:dirPath
                                Write-Host ""
                                
                            } elseif ($uninstallString -like '*CylanceProtectSetup*' ) {
                                Write-Host "   Uninstalling $applicationName Silently..."
                                $p = $uninstallString.lastIndexOf("`"")
                                $uninstallString_exe = $uninstallString.Substring(0,$p+1)
                                $uninstallString_switch = $uninstallString.SubString($p+1, $uninstallString.length - $uninstallString_exe.length).trim()

                                $timeout = 240 # Timeout in seconds
                                if ($global:uninstallpassword -eq $null -or $global:uninstallpassword -eq '') {
                                    Write-Host "   Uninstall password not set"
                                    $process = Start-Process -NoNewWindow -ErrorAction Stop -FilePath "$uninstallString_exe" -ArgumentList "/uninstall /quiet /norestart /qn /Lxv* $global:dirPath\Protect_Uninstall_CylanceProtectSetup.log" -PassThru
                                } else {
                                    Write-Host "   Uninstall password set"
                                    $process = Start-Process -NoNewWindow -ErrorAction Stop -FilePath "$uninstallString_exe" -ArgumentList "/uninstall /quiet /norestart /qn /Lxv* $global:dirPath\Protect_Uninstall_CylanceProtectSetup.log UNINSTALLKEY=$global:uninstallpassword" -PassThru
                                }

                                if ($process.WaitForExit($timeout * 1000)) {
                                    Write-Host "   MSI uninstallation finished"
                                } else {
                                    Write-Host "   MSI uninstallation timed out after $timeout seconds"
                                    Write-Host "   process.Id: $process.Id"
                                    Stop-Process -Id $process.Id -Force
                                }

                                $Search = "Cylance_PROTECT*.log"
                                Write-Host "   Copying logs..."
                                get-Item -Path $env:TEMP\$Search | Copy-Item -Destination $global:dirPath
                                Write-Host ""
                            } else {
                                Write-Warning "   Unknown Uninstall String for $applicationName. Skipping Add/Remove Uninstall"
                                Write-Host "   DisplayName: $DisplayName"
                                Write-Host "   UninstallString: $uninstallString"
                            }
                        } elseif ($applicationName -eq "Cylance Optics") {
                            Write-Host "   Uninstalling $applicationName Silently..."
                            if ($uninstallString -like '*MsiExec*' ) {
                                # Remove any switches from the uninstall command but keeps the last quote. Used for Pre optics3.2
                                $uninstallString_exe, $uninstallString_switch = $uninstallString.split(' ')

                                # Remove any switches from the uninstall command but keeps the last quote
                                $uninstallString = $uninstallString.Substring(0, $uninstallString.lastIndexOf('"') + 1)

                                If ($uninstallString_switch -like "*/I*") {
                                    $uninstallString_switch = $uninstallString_switch.replace('/I', '/X') # Replace /I with /X for uninstall
                                }

                                $timeout = 240 # Timeout in seconds
                                if ($global:uninstallpassword -eq $null -or $global:uninstallpassword -eq '') {
                                    Write-Host "   Uninstall password not set"
                                    $process = Start-Process -NoNewWindow -ErrorAction Stop -FilePath "$uninstallString_exe" -ArgumentList "$uninstallString_switch /norestart /qn /Lxv* $global:dirPath\Optics_Uninstall_MsiExec.log" -PassThru

                                } else {
                                    Write-Host "   Uninstall password set"
                                    $process = Start-Process -NoNewWindow -ErrorAction Stop -FilePath "$uninstallString_exe" -ArgumentList "$uninstallString_switch /norestart /qn /Lxv* $global:dirPath\Optics_Uninstall_MsiExec.log UNINSTALLKEY=$global:uninstallpassword" -PassThru
                                }

                                if ($process.WaitForExit($timeout * 1000)) {
                                    Write-Host "   MSI uninstallation finished"
                                } else {
                                    Write-Host "   MSI uninstallation timed out after $timeout seconds"
                                    Stop-Process -Id $process.Id
                                }
                            }
                            elseif ($uninstallString -like '*CylanceOPTICSSetup.exe*') {
                                # Remove any switches from the uninstall command but keeps the last quote. Used for Pre optics3.2
                                $uninstallString_exe, $uninstallString_switch = $uninstallString.split('  ')

                                # Remove any switches from the uninstall command but keeps the last quote
                                $uninstallString = $uninstallString.Substring(0, $uninstallString.lastIndexOf('"') + 1)

                                $timeout = 240 # Timeout in seconds
                                if ($global:uninstallpassword -eq $null -or $global:uninstallpassword -eq '') {
                                    Write-Host "   Uninstall password not set"
                                    $process = Start-Process -NoNewWindow -ErrorAction Stop -FilePath "$uninstallString" -ArgumentList "/uninstall /quiet /norestart /log $global:dirPath\Optics_Uninstall_CylanceOPTICSSetup.log" -PassThru

                                } else {
                                    Write-Host "   Uninstall password set"
                                    $process = Start-Process -NoNewWindow -ErrorAction Stop -FilePath "$uninstallString" -ArgumentList "/uninstall /quiet /norestart UNINSTALLKEY=$global:uninstallpassword /log $global:dirPath\Optics_Uninstall_CylanceOPTICSSetup.log" -PassThru
                                }
                                if ($process.WaitForExit($timeout * 1000)) {
                                    Write-Host "   MSI uninstallation finished"
                                } else {
                                    Write-Host "   MSI uninstallation timed out after $timeout seconds"
                                    Stop-Process -Id $process.Id
                                }
                            }
                            elseif ($uninstallString -like '*CyOpticsUninstaller.exe*') {
                                # Remove any switches from the uninstall command but keeps the last quote. Used for Pre optics3.2
                                $uninstallString_exe, $uninstallString_switch = $uninstallString.split('  ')

                                # Remove any switches from the uninstall command but keeps the last quote
                                $uninstallString = $uninstallString.Substring(0, $uninstallString.lastIndexOf('"') + 1)

                                $timeout = 240 # Timeout in seconds
                                if ($global:uninstallpassword -eq $null -or $global:uninstallpassword -eq '') {
                                    Write-Host "   Uninstall password not set"
                                    $process = Start-Process -NoNewWindow -ErrorAction Stop -FilePath "$uninstallString" -ArgumentList "--use_cli --file_log_level debug -t v20 --force_locking_process_termination" -PassThru

                                } else {
                                    Write-Host "   Uninstall password set"
                                    $process = Start-Process -NoNewWindow -ErrorAction Stop -FilePath "$uninstallString" -ArgumentList "--use_cli --file_log_level debug -t v20 --force_locking_process_termination --password $global:uninstallpassword" -PassThru
                                }
                                if ($process.WaitForExit($timeout * 1000)) {
                                    Write-Host "   MSI uninstallation finished"
                                } else {
                                    Write-Host "   MSI uninstallation timed out after $timeout seconds"
                                    Stop-Process -Id $process.Id
                                }
                            } else {
                                Write-Warning "   Unknown Uninstall String for $applicationName. Skipping Add/Remove Uninstall"
                                Write-Host "   DisplayName: $DisplayName"
                                Write-Host "   UninstallString: $uninstallString"
                            }
                            $Search = "Cylance_OPTICS*.log"
                            Write-Host "   Copying logs..."
                            get-Item -Path $env:TEMP\$Search | Copy-Item -Destination $global:dirPath
                            Write-Host ""

                        } elseif ($applicationName -eq "Cylance PROTECT with OPTICS") {
                            Write-Host "   Attempting to stop CylanceSvc with a 15s timeout"
                            # Attempt Shutdown of Protect

                            $ProgramFilePaths = @(
                                (${Env:Programfiles} + "\Cylance\Desktop")
                            #, (${Env:ProgramFiles(x86)} + "\Cylance\Desktop")
                            )

                            foreach ($ProgramFilePath in $ProgramFilePaths) {
                                if(Test-Path "$ProgramFilePath\CylanceSVC.exe" -PathType Leaf) {
                                    Start-Process -NoNewWindow -Wait -ErrorAction Stop -FilePath $ProgramFilePath\CylanceSvc.exe -ArgumentList "/shutdown"
                                    Start-Sleep -Seconds 15
                                }
                            }

                            if ($uninstallString -like '*CylanceProtectSetupWithOptics.exe*' ) {
                                Write-Host "   Uninstalling $applicationName Silently..."
                                $p = $uninstallString.lastIndexOf("`"")
                                $uninstallString_exe = $uninstallString.Substring(0,$p+1)
                                $uninstallString_switch = $uninstallString.SubString($p+1, $uninstallString.length - $uninstallString_exe.length).trim()

                                $timeout = 240 # Timeout in seconds
                                if ($global:uninstallpassword -eq $null -or $global:uninstallpassword -eq '') {
                                    Write-Host "   Uninstall password not set"
                                    $process = Start-Process -NoNewWindow -Wait -ErrorAction Stop -FilePath "$uninstallString_exe" -ArgumentList "/uninstall /quiet /norestart /qn /Lxv* $global:dirPath\Protect_Uninstall_CylanceProtectSetup.log" -PassThru
                                } else {
                                    Write-Host "   Uninstall password set"
                                    $process = Start-Process -NoNewWindow -Wait -ErrorAction Stop -FilePath "$uninstallString_exe" -ArgumentList "/uninstall /quiet /norestart /qn /Lxv* $global:dirPath\Protect_Uninstall_CylanceProtectSetup.log UNINSTALLKEY=$global:uninstallpassword" -PassThru
                                }

                                if ($process.WaitForExit($timeout * 1000)) {
                                    Write-Host "   MSI uninstallation finished"
                                } else {
                                    Write-Host "   MSI uninstallation timed out after $timeout seconds"
                                    Write-Host "   process.Id: $process.Id"
                                    Stop-Process -Id $process.Id -Force
                                }

                                $Search = "Cylance_PROTECT_with_OPTICS*.log"
                                Write-Host "   Copying logs..."
                                get-Item -Path $env:TEMP\$Search | Copy-Item -Destination $global:dirPath
                                Write-Host ""
                            } else {
                                Write-Warning "   Unknown Uninstall String for $applicationName. Skipping Add/Remove Uninstall"
                                Write-Host "   DisplayName: $DisplayName"
                                Write-Host "   UninstallString: $uninstallString"
                            }
                        } else {
                            Write-Warning "   Unknown Uninstall String for $applicationName. Skipping Add/Remove Uninstall"
                            Write-Host "   DisplayName: $DisplayName"
                            Write-Host "   UninstallString: $uninstallString"
                        } 
                    }
                } # end else
            } # end foreach loop
        } # end foreach
    } # End Try_Add/Remove
} # end function

function GetProtectVersion {
    # Get the version of protect to flip a flag if below 3.x
    if ($global:safemode -eq "No") {
        $software = ""
        $software = @(
            ####################################################
            # Protect Needs to be last in this list if enabled #
            ####################################################
            , 'Cylance Unified Agent'
            , 'Cylance PROTECT'
            , 'Cylance PROTECT with OPTICS'
        )

        $i = ""
        foreach ($i in $software) {
            $applicationName = $i
            $appKeys = Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*" | Where-Object { $_.DisplayName -eq $applicationName }
            foreach ($appKey in $appKeys) {
                # If the application is not found, exit the script
                if ($appKey) {
                    # Get the uninstall version for the application
                    $DisplayVersion = $appKey.DisplayVersion
                    if ($DisplayVersion) {
                        If ($DisplayVersion -like "2.*") {
                            Write-Host "Found: $applicationName Version: $DisplayVersion"
                            $global:Protect2++
                        }
                        If ($DisplayVersion -like "3.*") {
                            Write-Host "Found: $applicationName Version: $DisplayVersion"
                            $global:Protect3++
                        }
                    }
                }
            } # end foreach loop
        } # end foreach
    } # End
} # end function

function modify-Self-Protection-Desktop {
    if (Test-Path -Path "Registry::HKLM\SOFTWARE\Cylance\Desktop") {
        $global:Originalkey = "HKLM:\SOFTWARE\Cylance\Desktop"
        $HiveAbr = $global:Originalkey.Substring(0, $global:Originalkey.IndexOf(':'))
        $Hivepath = $global:Originalkey.Substring($global:Originalkey.IndexOf('\') + 1)
        Write-Host ""
        Write-Host "Checking if SelfProtection Level is enabled in the Registry for Protect"
        try {
            $SelfProtectionLevel = (Get-ItemProperty HKLM:\SOFTWARE\Cylance\Desktop -ErrorAction Stop).SelfProtectionLevel
        }
        catch {
            Write-Warning "Exception caught while checking protect SelfProtection Level";
            Write-Warning "$_";
        }
        If ( $SelfProtectionLevel -eq 0 -or $SelfProtectionLevel -eq 2) {
            Write-Host " 'SelfProtectionLevel' is Disabled($SelfProtectionLevel)";
            Write-Host "  Changing 'SelfProtectionLevel' to Enabled(1)";
            if ($global:safemode -eq "No") {

                Write-Host "  Taking Ownership of $global:Originalkey"
                try {
                    Take-Permissions $HiveAbr $Hivepath
                }
                catch {
                    Write-Warning "Exception caught while taking Ownership of $global:Originalkey";
                    Write-Warning "$_";
                }
                try {
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Cylance\Desktop" -Name "SelfProtectionLevel" -Value 1;
                    if ($LASTEXITCODE -eq 1) {
                        Write-Warning "Exception caught while setting Protect SelfProtectionLevel";
                        try { Stop-Transcript } catch {}
                        exit 1
                    }
                }
                catch {
                    Write-Warning "Exception caught while setting Protect SelfProtectionLevel";
                    Write-Warning "$_";
                }
            }
            else {
                Write-Host " **** safemode: No changes have been made ****"
            }
        }
        elseif ( $SelfProtectionLevel -eq 1) {
            Write-Host " 'SelfProtectionLevel' is Enabled(1)";
        }
        elseIf ( !$SelfProtectionLevel) {
            Write-Host ""
            Write-Host " 'SelfProtectionLevel' is Missing";
            Write-Host "  Creating 'SelfProtectionLevel' with registry key with value set to Enabled(1)";
            if ($global:safemode -eq "No") {
                Write-Host "  Taking Ownership of $global:Originalkey"
                try {
                    Take-Permissions $HiveAbr $Hivepath
                }
                catch {
                    Write-Warning "Exception caught while taking Ownership of $global:Originalkey";
                    Write-Warning "$_";
                }

                try {
                    New-ItemProperty -Path "HKLM:\SOFTWARE\Cylance\Desktop" -Name 'SelfProtectionLevel' -Value 1 -PropertyType DWord -ErrorAction Stop;
                }
                catch {
                    Write-Warning "Exception caught while creating Protect SelfProtectionLevel";
                    Write-Host "$_";
                }
            }
            else {
                Write-Host " **** safemode: No changes have been made ****"
            }
        }
        else {
            Write-Host "'SelfProtectionLevel' Unknown Error";
            Write-Host "SelfProtectionLevel: $SelfProtectionLevel"
        }
    }
    else {
        Write-Host "HKLM:\SOFTWARE\Cylance\Desktop Does not exist"
    }
}

function modify-Self-Protection-Optics {
    if (Test-Path -Path "Registry::HKLM\SOFTWARE\Cylance\Optics") {
        $global:Originalkey = "HKLM:\SOFTWARE\Cylance\Optics"
        $HiveAbr = $global:Originalkey.Substring(0, $global:Originalkey.IndexOf(':'))
        $Hivepath = $global:Originalkey.Substring($global:Originalkey.IndexOf('\') + 1)
        Write-Host ""
        Write-Host "Checking if SelfProtection Level is enabled in the Registry for Optics"
        try {
            $SelfProtectionLevel = (Get-ItemProperty HKLM:\SOFTWARE\Cylance\Optics -ErrorAction Stop).SelfProtectionLevel
        }
        catch {
            Write-Warning "Exception caught while checking Optics SelfProtection Level";

            Write-Warning "$_";
        }
        If ( $SelfProtectionLevel -eq 0 -or $SelfProtectionLevel -eq 2) {
            Write-Host " 'SelfProtectionLevel' is Disabled($SelfProtectionLevel)";
            Write-Host "  Changing 'SelfProtectionLevel' to Enabled(1)";
            if ($global:safemode -eq "No") {
                Write-Host "  Taking Ownership of $global:Originalkey"
                try {
                    Take-Permissions $HiveAbr $Hivepath
                }
                catch {
                    Write-Warning "Exception caught while taking Ownership of $global:Originalkey";
                    Write-Warning "$_";
                }
                try {
                    Set-ItemProperty -Path "HKLM:\SOFTWARE\Cylance\Optics" -Name "SelfProtectionLevel" -Value 1;
                    if ($LASTEXITCODE -eq 1) {
                        Write-Warning "Exception caught while setting Optics SelfProtectionLevel";
                        try { Stop-Transcript } catch {}
                        exit 1
                    }
                }
                catch {
                    Write-Warning "Exception caught while setting Optics SelfProtectionLevel";
                    Write-Warning "$_";
                }
            }
            else {
                Write-Host " **** safemode: No changes have been made ****"
            }
        }
        elseif ( $SelfProtectionLevel -eq 1) {
            Write-Host " 'SelfProtectionLevel' is Enabled(1)";
        }
        elseIf ( !$SelfProtectionLevel) {
            Write-Host ""
            Write-Host " 'SelfProtectionLevel' is Missing";
            Write-Host "  Creating 'SelfProtectionLevel' with to Enabled(1)";
            if ($global:safemode -eq "No") {
                Write-Host "  Taking Ownership of $global:Originalkey"
                try {
                    Take-Permissions $HiveAbr $Hivepath
                }
                catch {
                    Write-Warning "Exception caught while Taking Ownership of $global:Originalkey";
                    Write-Warning "$_";
                }
                try {
                    New-ItemProperty -Path "HKLM:\SOFTWARE\Cylance\Optics" -Name 'SelfProtectionLevel' -Value 1 -PropertyType DWord -ErrorAction Stop;
                }
                catch {
                    Write-Warning "Exception caught while creating Protect SelfProtectionLevel";
                    Write-Host "$_";
                }
            }
            else {
                Write-Host " **** safemode: No changes have been made ****"
            }
        }
        else {
            Write-Host "'SelfProtectionLevel' Unknown Error";
            Write-Host "SelfProtectionLevel: $SelfProtectionLevel"
        }
    }
    else {
        Write-Host "SelfProtectionLevel does not exist in: HKLM:\SOFTWARE\Cylance\Optics"
    }
}

function modify-LastStateRestorePoint-InstallToken {
    if (Test-Path -Path "Registry::HKLM\SOFTWARE\Cylance\Desktop") {
        $global:Originalkey = "HKLM:\SOFTWARE\Cylance\Desktop"
        $HiveAbr = $global:Originalkey.Substring(0, $global:Originalkey.IndexOf(':'))
        $Hivepath = $global:Originalkey.Substring($global:Originalkey.IndexOf('\') + 1)
        Write-Host ""
        Write-Host "Checking if LastStateRestorePoint exists in the Registry"
        try {
            $SelfProtectionLevel = (Get-ItemProperty $global:Originalkey).PSObject.Properties.Name -contains "LastStateRestorePoint"
        }
        catch {
            Write-Warning "Exception caught while checking if LastStateRestorePoint is in the Registry";
            Write-Warning "$_";
        }
        if ($SelfProtectionLevel) {
            Write-Host " Found Value: LastStateRestorePoint"

            if ($global:safemode -eq "No") {
                Write-Host "Taking Ownership of HKLM:\SOFTWARE\Cylance\Desktop"
                try {
                    Take-Permissions $HiveAbr $Hivepath
                }
                catch {
                    Write-Warning "Exception caught while taking Ownership of HKLM:\SOFTWARE\Cylance\Desktop";
                    Write-Warning "$_";
                }
                Write-Host "Deleting LastStateRestorePoint"
                try {
                    Remove-ItemProperty -Path HKLM:\SOFTWARE\Cylance\Desktop -Name LastStateRestorePoint -Force -ErrorAction Stop
                    Write-Host " Successfully Deleted LastStateRestorePoint"
                    Write-Host ""
                }
                catch {
                    Write-Warning "    Exception caught deleting Protect LastStateRestorePoint";
                    Write-Warning "    $_";
                    Write-Host ""
                }
            }
            else {
                Write-Host "    Key for Deletion/Modification: LastStateRestorePoint"
                Write-Host " **** safemode: No changes have been made ****"
                Write-Host ""
            }
        }
        else {
            Write-Host "LastStateRestorePoint does not exist in: HKLM:\SOFTWARE\Cylance\Desktop"
        }
        Write-Host ""
        Write-Host "Checking if InstallToken is set in the Registry"
        try {
            $SelfProtectionLevel = (Get-ItemProperty $global:Originalkey).PSObject.Properties.Name -contains "InstallToken"
        }
        catch {
            Write-Warning "Exception caught while checking if InstallToken is in the Registry";
            Write-Warning "$_";
        }
        if ($SelfProtectionLevel) {
            Write-Host " Found Value: InstallToken"

            if ($global:safemode -eq "No") {
                Write-Host "Taking Ownership of HKLM:\SOFTWARE\Cylance\Desktop"
                try {
                    Take-Permissions $HiveAbr $Hivepath
                }
                catch {
                    Write-Warning "Exception caught while taking Ownership of HKLM:\SOFTWARE\Cylance\Desktop";
                    Write-Warning "$_";
                }
                Write-Host "Deleting InstallToken"
                try {
                    Remove-ItemProperty -Path HKLM:\SOFTWARE\Cylance\Desktop -Name InstallToken -Force -ErrorAction Stop
                    Write-Host " Successfully Deleted InstallToken"
                    Write-Host ""
                }
                catch {
                    Write-Warning "    Exception caught deleting Protect InstallToken";
                    Write-Warning "    $_";
                    Write-Host ""
                }
            }
            else {
                Write-Host "    Key for Deletion/Modification: InstallToken"
                Write-Host " **** safemode: No changes have been made ****"
            }
        }
        else {
            Write-Host "InstallToken does not exist in: HKLM:\SOFTWARE\Cylance\Desktop"
        }
    }
}

function modify-Services {
    # We need to ensure that all existing services for Cylance are set to Disabled in the event that a reboot is required
    Write-Host ""
    Write-Host "Checking if all Cylance Services are disabled"
    $RegkeysHive = ""
    $RegkeysHive = @(
        'HKLM:\SYSTEM\CurrentControlSet\services\CyDevFlt' # Protect 2.x? Default Start(?)
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CyDevFlt64' # Protect 3.0? Default Start(?)
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CylanceDrv' # Protect 3.1 Default Start(0)
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CylanceSvc' # Protect 3.1 Default Start(2)
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CyProtectDrv'
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CyOptics' # Optics 3.2 Default Start(2)
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CyOpticsDrv' # Optics 3.2 Default Start(1)
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CyAgent' # DLP 1.0 Default Start(2) | Persona 1.3 Default Start(2) | Protect/Optics?
        #,'HKLM:\SYSTEM\CurrentControlSet\services\CyElamDrv' # Protect 3.1 Default Start(0)
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CyDevFltV2' # Protect 3.1 Default Start(0)
        #,'HKLM:\SYSTEM\CurrentControlSet\services\BlackBerryGatewayCalloutDriver' # Gateway 2.5 Default Start(0)
        #,'HKLM:\SYSTEM\CurrentControlSet\services\BlackBerryGatewayService' # Gateway 2.5 Default Start(2)
    )

    $k = ""
    foreach ($k in $RegkeysHive) {
        # Start foreach loop
        $kk = $k.replace(':', '') # Replacing " with nonthing
        $kk = "Registry::" + $kk # Registry:: which is needed when you are not using :\ in the path
        $global:Originalkey = $k
        $global:SafeFileName = $k.replace(':', '_') # Replacing " with _ for supported filename
        $global:SafeFileName = $global:SafeFileName.replace('\', '_') # Replacing \ with _ for supported filename
        $global:SafeExportName = $k.replace(':', '') # Removing : to support exporting variable
        $HiveAbr = $global:Originalkey.Substring(0, $global:Originalkey.IndexOf(':'))
        $Hivepath = $global:Originalkey.Substring($global:Originalkey.IndexOf('\') + 1)

        if (Test-Path -Path $kk) {
            # Start If loop
            try {
                $global:Servicevalue = (Get-ItemProperty $k -ErrorAction Stop).Start;
            }
            catch {
                Write-Warning "Exception caught";
                Write-Warning "$_";
            }

            If ( $global:Servicevalue -ne 4 ) {
                Write-Host ""
                Write-Host "Service $k is not disabled"
                Write-Host "  Current value: $global:Servicevalue"
                Write-Host "  Disabling the service via registry 'Disabled(4)'"

                if ($global:safemode -eq "No") {
                    Write-Host "  Taking Ownership of $global:Originalkey"
                    try {
                        Take-Permissions $HiveAbr $Hivepath
                    }
                    catch {
                        # Start catch
                        Write-Warning "Exception caught";
                        Write-Warning "$_";
                    } # End catch

                    try {
                        Set-ItemProperty -Path $k -Name "Start" -Value 4;
                        $CheckValue = (Get-ItemProperty $k -ErrorAction Stop).Start;
                        if ($CheckValue -ne 4) {
                            write-Error "Disabling the service failed Current value: '$CheckValue'";
                        }

                    }
                    catch {
                        # Start catch
                        Write-Warning "Exception caught";
                        Write-Warning "$_";
                    } # End catch
                }
                else {
                    Write-Host "  **** safemode: No changes have been made ****"
                } # End safemode Check
            }

        } # End If loop

    } # End foreach loop
    #Write-Warning "Any changes to the services may require a reboot and re-run of the script"

} # End We need to ensure that all existing services for Cylance are set to Disabled

function Stop-Delete-Services {

    # We need to stop any service that may be running as well as the CylanceUI.exe however, depending on Self Protection, LastStateRestorePoint
    #  and the state of the endpoint, this may fail. If we see any errors we may need to reboot the endpoint and re-run the script.

    $Services = @(
        # ,'Cylance Service'
        , 'CylanceSVC'
        # ,'Cylance Driver'
        # ,'CyProtectDrv'
        # ,'CyDevFlt64'
        # ,'CyAgent'
        # ,'Optics'
        'CyOptics'
    )

    foreach ($k in $Services) {
        # Start Foreach Service
        $service = Get-Service -Name $k -ErrorAction SilentlyContinue
        if ($service.Length -gt 0) {
            Write-Host "Service Exists: $k"
            if ($global:safemode -eq "No") {
                # Start of safemode check
                Write-Host ""
                Write-Host "Stopping Service"

                if ($k -like '*CylanceSVC*') {
                    Write-Host "Attempting to deregister and shutdown the CylanceSVC Service."

                    # Unregister Protect with Windows Security Center
                    $ProgramFilePaths = @(
                        (${Env:Programfiles} + "\Cylance\Desktop")
                        #, (${Env:ProgramFiles(x86)} + "\Cylance\Desktop")
                    )

                    foreach ($ProgramFilePath in $ProgramFilePaths) {
                        if (Test-Path "$ProgramFilePath\CylanceSVC.exe" -PathType Leaf) {
                            Start-Process -NoNewWindow -Wait -ErrorAction Stop -FilePath $ProgramFilePath\CylanceSvc.exe -ArgumentList "/unregister"
                        }
                    }

                    # Requests that the service shut itself down
                    try {
                        # Stop the Service
                        # Requests that the service shut itself down
                    $ProgramFilePaths = @(
                        (${Env:Programfiles} + "\Cylance\Desktop")
                        #, (${Env:ProgramFiles(x86)} + "\Cylance\Desktop")
                    )

                    foreach ($ProgramFilePath in $ProgramFilePaths) {
                        if (Test-Path "$ProgramFilePath\CylanceSVC.exe" -PathType Leaf) {
                            Start-Process -NoNewWindow -Wait -ErrorAction Stop -FilePath $ProgramFilePath\CylanceSvc.exe -ArgumentList "/shutdown"
                            Start-Sleep -Seconds 15
                        }
                    }
                        Stop-Service -Name CylanceSVC -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 15

                    # Stop the Service once more so we can delete it
                    # Requests that the service shut itself down
                    $ProgramFilePaths = @(
                        (${Env:Programfiles} + "\Cylance\Desktop")
                        #, (${Env:ProgramFiles(x86)} + "\Cylance\Desktop")
                    )

                    foreach ($ProgramFilePath in $ProgramFilePaths) {
                        if (Test-Path "$ProgramFilePath\CylanceSVC.exe" -PathType Leaf) {
                            Start-Process -NoNewWindow -Wait -ErrorAction Stop -FilePath $ProgramFilePath\CylanceSvc.exe -ArgumentList "/shutdown"
                        }
                    }
                        Stop-Service -Name CylanceSVC -ErrorAction SilentlyContinue
                        Start-Sleep -Seconds 10
                    }
                    catch {
                        Write-Information "$_";
                    }
                }

                try {
                    Stop-ServiceWithTimeout $k 30
                }
                catch {
                    Write-Warning "Exception caught";
                    Write-Information "$_";
                    #Write-Warning "You may need to restart the endpoint and re-run the script"
                    $global:RestartWarning++
                } # End try to stop service

                Write-Host ""
                Write-Host "Removing Service $k"
                # If the msiexec uninstaller did not run, this will likely fail with a access denied and a reboot wil be required
                & sc.exe delete $k | out-null
                if ( $LASTEXITCODE -eq 0 ) {
                    Write-Host "Service was deleted successfully."
                    Write-Host ""
                }
                elseif ( $LASTEXITCODE -eq 5 ) {
                    Write-Warning "Access Denied! Please reboot the endpoint and re-run the script."
                    Write-Host ""
                    $global:RestartWarning++
                }
                elseif ( $LASTEXITCODE -eq 1072 ) {
                    Write-Warning "Service is marked for deletion and will be removed during the next reboot."
                    Write-Host ""
                    $global:RestartWarning++
                }
                else {
                    Write-Host "Unknown Error: $LASTEXITCODE"
                    Write-Host ""
                }
            } # End of safemode check

        }
    } # End Foreach Service


    # Get CylanceUI process
    if ($global:safemode -eq "No") {
        # Start safemode check for CylanceUI
        $CylanceUI = Stop-Process -ProcessName "CylanceUI" -Force -ErrorAction SilentlyContinue
        if ($CylanceUI) {
            # try gracefully first
            $CylanceUI.CloseMainWindow()
            # kill after five seconds
            Start-Sleep 5
            if (!$CylanceUI.HasExited) {
                $CylanceUI | Stop-Process -Force
            }
        }
        Remove-Variable CylanceUI
    } # End safemode check for CylanceUI

} # End try to stop services

function Backup_Reg_Keys {
    # Start Backup and Delete Registry keys
    # By default, only two hives are added to paths. We need to also add HKCR so we don't have to duplicate a lot of code
    try {
        New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT -ErrorAction Stop
    }
    catch {
        Write-Host "$_";
        try { Stop-Transcript } catch {}
        exit 1
    }

    Write-Host ""
    Write-Host "Scanning Windows Registry 1of7..."
    Write-Host "... This may take a few minutes. "
    Write-Host ""
    # Search the registry for static folders to backup.
    $RegkeysHive = ""
    $RegkeysHive = @(
        'HKLM:\SOFTWARE\Cylance\Desktop' # Protect
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CyDevFlt' # Protect
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CyDevFltV2' # Protect
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CylanceDrv' # Protect
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CyProtectDrv' # Protect
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CylanceSvc' # Protect
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CyDevFlt64' # Protect
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CyAgent' # Protect
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\C5CF46E2682913A419B6D0A84E2B9245' # Protect
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\EEEA7AC670DE2F343B7B624D338C49E8' # not 100% what this is from yet
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{2E64FC5C-9286-4A31-916B-0D8AE4B22954}' # Protect
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{2E64FC5C-9286-4A31-916B-0D8AE4B22954}.RebootRequired' # Protect
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{007a6b01-d455-4744-866c-d8bd010b464b}' # Protect
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{007a6b01-d455-4744-866c-d8bd010b464b}.RebootRequired' # Protect
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{a23b3945-2f47-40bf-816f-838593f443e6}' # Unified installer 1534 on x86 windows
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{a23b3945-2f47-40bf-816f-838593f443e6}.RebootRequired' # Unified installer 1534 on x86 windows
        , 'HKCR:\Installer\Dependencies\{6e002c37-0e3e-4152-b8b8-dc11f5f36378}' # Protect
        , 'HKCR:\Installer\Features\C5CF46E2682913A419B6D0A84E2B9245' # Protect
        , 'HKCR:\Installer\Products\C5CF46E2682913A419B6D0A84E2B9245' # Protect
        , 'HKCR:\Installer\Features\EEEA7AC670DE2F343B7B624D338C49E8' # not 100% what this is from yet
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DIFx\Services\CyProtectDrv' # Protect
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DIFx\Services\CylanceDrv' # Protect
        , 'HKLM:\SOFTWARE\Microsoft\RADAR\HeapLeakDetection\DiagnosedApplications\CylanceSvc.exe' # Protect
        , 'HKLM:\SOFTWARE\Microsoft\Tracing\CylanceSvc_RASAPI32' # Protect
        , 'HKLM:\SOFTWARE\Microsoft\Tracing\CylanceSvc_RASMANCS' # Protect
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DIFxApp\Components\{450500FA-75A8-44E8-BC01-734384C37067}' # Protect
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DIFxApp\Components\{72B70F45-0B32-5191-A610-8350D30001BD}' # Protect
        , 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\CylanceSvc' # Protect
        , 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\CyAgent' # Protect
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CyElamDrv' # Protect 3.1
        , 'HKLM:\SYSTEM\ControlSet001\services\CyElamDrv' # Protect 3.1
        , 'HKCU:\SOFTWARE\Cylance\Desktop' # Protect
        , 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{99b0c63f-0286-45d4-b672-1423a65b601c}' # Protect
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{99b0c63f-0286-45d4-b672-1423a65b601c}' # Protect
        , 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{99b0c63f-0286-45d4-b672-1423a65b601c}.RebootRequired' # Protect
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{99b0c63f-0286-45d4-b672-1423a65b601c}.RebootRequired' # Protect
        , 'HKLM:\SOFTWARE\Cylance\Optics'
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CyOpticsDrv' # Optics
        , 'HKLM:\SYSTEM\CurrentControlSet\services\CyOptics' # Optics
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\5E3ECEF636AC03A42AD963002F50F714' # Optics
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{6FECE3E5-CA63-4A30-A29D-3600F2057F41}' # Optics
        , 'HKCR:\Installer\Dependencies\{6FECE3E5-CA63-4A30-A29D-3600F2057F41}' # Optics
        , 'HKCR:\Installer\Dependencies\{cb2e0274-626f-4b8f-b63e-e6fb6dd43af4}' # Optics
        , 'HKCR:\Installer\Products\5E3ECEF636AC03A42AD963002F50F714' # Optics
        , 'HKCR:\Installer\Dependencies\{5d39164a-404e-467e-9df1-fec1b910f559}' # Optics
        , 'HKCR:\Installer\Dependencies\{4d29bdf1-4c6d-400f-926f-0f740881b09b}' # Optics
        , 'HKCR:\Installer\Dependencies\{6FECE3E5-CA63-4A30-A29D-3600F2057F41}' # Optics
        , 'HKCR:\Installer\Products\5E3ECEF636AC03A42AD963002F50F714' # Optics
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DIFx\Services\CylanceOpticsDrv' # Optics
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DIFx\Services\CyOpticsDrv' # Optics
        , 'HKLM:\SOFTWARE\Microsoft\Tracing\CyOptics_RASAPI32' # Optics
        , 'HKLM:\SOFTWARE\Microsoft\Tracing\CyOptics_RASMANCS' # Optics
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DIFxApp\Components\{0F031C0D-153A-45EA-A827-C50D4D89FF3B}' # Optics
        , 'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application\CyOptics' # Optics
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\5E3ECEF636AC03A42AD963002F50F714' # Optics
        , 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{5d39164a-404e-467e-9df1-fec1b910f559}' # Optics 2.x
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{5d39164a-404e-467e-9df1-fec1b910f559}' # Optics 2.x
        , 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\{BCFA2637-2DB5-4D2B-A0D0-61D84F20B38E}' # Optics 2.x
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{BCFA2637-2DB5-4D2B-A0D0-61D84F20B38E}' # Optics 2.x
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\{cb2e0274-626f-4b8f-b63e-e6fb6dd43af4}.RebootRequired' # Optics 3.2
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\7362AFCB5BD2B2D40A0D168DF4023BE8' # Optics
    )

    # Perform iteration to create the same file in each folder
    $k = ""

    foreach ($k in $RegkeysHive) {
        # Start foreach loop
        $kk = $k.replace(':', '') # Replacing " with nothing
        $kk = "Registry::" + $kk # Registry:: which is needed when you are not using :\ in the path
        $global:Originalkey = $k
        $global:SafeFileName = $k.replace(':', '_') # Replacing " with _ for supported filename
        $global:SafeFileName = $global:SafeFileName.replace('\', '_') # Replacing \ with _ for supported filename
        $global:SafeExportName = $k.replace(':', '') # Removing : to support exporting variable
        $HiveAbr = $global:Originalkey.Substring(0, $global:Originalkey.IndexOf(':')) # take only "HKLM" from the variable
        $Hivepath = $global:Originalkey.Substring($global:Originalkey.IndexOf('\') + 1) # Strip "HKLM:\" from the variable

        if (Test-Path -Path $kk) {
            $global:RegOutputFile = "";
            $global:RegOutputFile = $global:dirPath + "\" + $global:SafeFileName + ".reg";
            try {
                reg.exe export $global:SafeExportName $global:RegOutputFile /y | out-null;
                if ($LASTEXITCODE -eq 1) {
                    Write-Warning "Exception caught";
                }
                Write-Host "Exported $k successfully";
                Delete_Reg_Keys;
            }
            catch {
                Write-Warning "Exception caught";
                Write-Host "$_";
            }
            # Append .RebootRequired and delete that key as well
            $Hivepath = $Hivepath + ".RebootRequired"
            Delete_Reg_Keys;
        } # End If loop
    } # End foreach loop


    Write-Host ""
    Write-Host "Scanning Windows Registry 2of7..."
    Write-Host "... This may take a few minutes."
    Write-Host ""
    # Some regkeys does not have a static folder path, thus we need to search using keywords and build the path to backup.
    $RegkeysHive = ""
    $RegkeysHive = @(
        'HKCR:\Installer\Products'
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
        , 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
        , 'HKCR:\Installer\Dependencies'
        , 'HKLM:\SOFTWARE\Classes\Installer\Dependencies'
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DIFx\DriverStore'
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products'
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\'
        , 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\7362AFCB5BD2B2D40A0D168DF4023BE8\InstallProperties'
        #,'HKLM:\SOFTWARE\Microsoft\Security Center\Provider\Av' # Protect Entries to Windows Security Center
    )

    $l = ""
    foreach ($l in $RegkeysHive) {
        $kk = $l.replace(':', '') # Replacing " with nothing
        $kk = "Registry::" + $kk # Registry:: which is needed when you are not using :\ in the path
        if (Test-Path -Path $kk) {
            # Start foreach loop
            $global:Originalkey = $l
            $global:KWildcard = $l + "\*" # append \* for the search
            $HiveAbr = $global:Originalkey.Substring(0, $global:Originalkey.IndexOf(':'))
            $Hivepath = $global:Originalkey.Substring($global:Originalkey.IndexOf('\') + 1)

            $SearchWord = ""
            $SearchWord = @(
                'Cylance PROTECT'
                #,'Cylance Platform' # Installed With DLP 1.0 | Persona 1.3
                , 'Cylance OPTICS'
                , 'Cylance PROTECT with OPTICS'
                , 'CylancePROTECT'
                , 'Cylance Unified Agent' # Installed with Protect + Optics Installer
                #,'CylancePROTECT' # Protect used in \Security Center\Provider\Av
                #,'Cylance Persona' # Installed with Persona 1.3
                #,'Cylance Persona Capability' # Installed with Persona 1.3
                #,'CylanceAVERT and Platform' # Installed with DLP 1.0
                #,'Cylance Agent' # Installed With DLP 1.0 | Persona 1.3
            )

            $m = ""
            foreach ($m in $SearchWord) {
                # Start foreach loop for SearchWord
                $installed = (Get-ItemProperty $global:KWildcard | Where-Object { $_.DisplayName -eq $m -or $_.ProductName -eq $m }) -ne $null;

                If ( $installed ) {
                    $KeyName = ""
                    $Result = ""
                    $KeyName = (Get-ItemProperty $global:KWildcard | Where-Object { $_.DisplayName -eq $m -or $_.ProductName -eq $m }).PSChildName;
                    foreach ($Result in $KeyName) {
                        # Start Loop through multiple results if exist
                        $n = $l + "\" + $Result
                        $global:Originalkey = $n
                        $global:SafeFileName = $n.replace(':', '_') # Replacing " with _ for supported filename
                        $global:SafeFileName = $global:SafeFileName.replace('\', '_') # Replacing \ with _ for supported filename
                        $global:SafeExportName = $n.replace(':', '') # Removing : to support exporting variable
                        $global:RegOutputFile = "";
                        $global:RegOutputFile = $global:dirPath + "\" + $SafeFileName + ".reg";
                        $HiveAbr = $global:Originalkey.Substring(0, $global:Originalkey.IndexOf(':'))
                        $Hivepath = $global:Originalkey.Substring($global:Originalkey.IndexOf('\') + 1)
                        # TODO: Should we remove the try catch here?
                        try {
                            reg.exe export $global:SafeExportName $global:RegOutputFile /y | out-null;
                            if ($LASTEXITCODE -eq 1) {
                                Write-Warning "Unknown Error: $LASTEXITCODE"
                            }
                            Write-Host "Exported $k successfully";
                            Delete_Reg_Keys;
                        }
                        catch {
                            Write-Warning "Exception caught";
                            Write-Host "$_";
                        } # End catch

                        # Append .RebootRequired and delete that key as well
                        $Hivepath = $Hivepath + ".RebootRequired"
                        Delete_Reg_Keys;
                    } # Start Loop through multiple results if exist
                } # End if
            } # End foreach loop for SearchWord
        }
    } # End foreach loop


    Write-Host ""
    Write-Host "Scanning Windows Registry 3of7..."
    Write-Host "... This may take a few minutes."
    Write-Host ""
    # Checking registry UpperFilters and LowerFilters that contain CyDevFlt for backup
    $RegkeysHive = ""
    $RegkeysHive = @(
        'HKLM:\SYSTEM\CurrentControlSet\Control\class'
    )

    $k = ""
    foreach ($k in $RegkeysHive) {
        # Start foreach loop
        $global:Originalkey = $k
        $global:KWildcard = $k + "\*" # append \* for the search

        $SearchWord = "CyDevFlt";
        $Result = (Get-ItemProperty $global:KWildcard | Where-Object { $_.UpperFilters -eq $SearchWord -or $_.LowerFilters -eq $SearchWord }).PSChildName;
        $key = ""
        foreach ($key in $Result) {
            # Start foreach loop
            #$key = $RegkeysHive + "\" + $key
            $key = "$RegkeysHive\$key"
            $global:SafeFileName = $key.replace(':', '_') # Replacing " with _ for supported filename
            $global:SafeFileName = $global:SafeFileName.replace('\', '_') # Replacing \ with _ for supported filename
            $global:SafeExportName = $key.replace(':', '') # Removing : to support exporting variable
            $global:RegOutputFile = "";
            $global:RegOutputFile = $global:dirPath + "\" + $SafeFileName + ".reg";

            reg.exe export $global:SafeExportName $global:RegOutputFile /y | out-null;
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Unknown Error: $LASTEXITCODE"
            }
            Write-Host "Exported $key successfully";
            # Do not call Delete_Reg_Keys here or it will blow away the usb drivers.;
        } # End if
    } # End foreach loop


    Write-Host ""
    Write-Host "Scanning Windows Registry 4of7..."
    Write-Host "... This may take a few minutes."
    Write-Host ""
    # Checking registry for CylanceMemDef*.dll
    $global:Originalkey = ""
    $global:KWildcard = ""
    $RegkeysHive = ""
    $RegkeysHive = @(
        'HKLM:\SOFTWARE\Classes\CLSID'
    )

    $k = ""
    foreach ($k in $RegkeysHive) {
        # Start foreach loop
        $global:Originalkey = $k
        $global:KWildcard = $k + "\*" # append \* for the search

        $key = ""
        $Result = ""
        $Result = (get-childitem -recurse $global:KWildcard | get-itemproperty | where { $_.'(Default)' -match 'CylanceMemDef.dll' -or $_.'(Default)' -match 'CylanceMemDef64.dll' }).PSParentPath;

        foreach ($key in $Result) {
            $key = $key -replace '^[^:]+::' # Remove everything beofre ::
            $key = $key.replace('HKEY_LOCAL_MACHINE', 'HKLM:') # replace HKEY_LOCAL_MACHINE to HKLM:
            $global:Originalkey = $key
            $HiveAbr = $global:Originalkey.Substring(0, $global:Originalkey.IndexOf(':'))
            $Hivepath = $global:Originalkey.Substring($global:Originalkey.IndexOf('\') + 1)

            $global:SafeFileName = $key.replace(':', '_') # Replacing " with _ for supported filename
            $global:SafeFileName = $global:SafeFileName.replace('\', '_') # Replacing \ with _ for supported filename
            $global:SafeExportName = $key.replace(':', '') # Removing : to support exporting variable
            $global:RegOutputFile = "";
            $global:RegOutputFile = $global:dirPath + "\" + $SafeFileName + ".reg";

            reg.exe export $global:SafeExportName $global:RegOutputFile /y | out-null;
            if ($LASTEXITCODE -ne 0) {
                Write-Warning "Unknown Error: $LASTEXITCODE"
            }
            Write-Host "Exported $key successfully";
            Delete_Reg_Keys;
        } # End if
    } # End foreach loop

    # Search HKEY_USERS Registry for keys(Folders) that contain a keyword.
    Write-Host ""
    Write-Host "Scanning Windows Registry 5of7..."
    Write-Host "... This may take a few minutes."
    Write-Host ""
    $keywords = ""
    $subkeys = ""
    $keywords = @("Cylance", "Optics")

    $subkeys = Get-ChildItem -Path "Registry::HKEY_USERS" -Recurse -ErrorAction SilentlyContinue
    foreach ($key in $subkeys) {
        foreach ($keyword in $keywords) {
            if ($key.Name -like "*$keyword*") {
                $key = $key -replace '^[^:]+::' # Remove everything before ::
                $key = $key.replace('HKEY_USERS', 'HKU:') # replace HKEY_LOCAL_MACHINE to HKLM:
                $global:Originalkey = $key
                $HiveAbr = $global:Originalkey.Substring(0, $global:Originalkey.IndexOf(':'))
                $Hivepath = $global:Originalkey.Substring($global:Originalkey.IndexOf('\') + 1)
                $global:Originalkey2 = "REGISTRY::HKEY_USERS\" + $Hivepath
                $global:SafeFileName = $key.replace(':', '_') # Replacing " with _ for supported filename
                $global:SafeFileName = $global:SafeFileName.replace('\', '_') # Replacing \ with _ for supported filename
                $global:SafeExportName = $key.replace(':', '') # Removing : to support exporting variable
                $global:RegOutputFile = "";
                $global:RegOutputFile = $global:dirPath + "\" + $SafeFileName + ".reg";

                reg.exe export $global:SafeExportName $global:RegOutputFile /y | out-null;
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "Unknown Error: $LASTEXITCODE with $global:SafeExportName"
                }
                $global:Originalkey =
                Write-Host "Exported $key successfully";
                $global:Originalkey = $global:Originalkey2
                Delete_Reg_Keys;
            }
        }
    }

    # This function will search a few specific keys where the Name of the key contains the keywords and will remove the entries but keep the key "folder"
    Write-Host ""
    Write-Host "Scanning Windows Registry 6of7..."
    Write-Host "... This may take a few minutes."
    Write-Host ""
    $RegkeysHive = ""
    $SearchWord = ""
    $m = ""
    $properties = ""
    $property = ""

    $RegkeysHive = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\Folders'
        , 'HKLM:\SYSTEM\ControlSet001\Services\bam\State\UserSettings\S-1-5-18'
    )

    $l = ""
    foreach ($l in $RegkeysHive) {

        $SearchWord = @(
            '\Cylance\'
        )

        foreach ($m in $SearchWord) {

            # Get all properties of the specified registry key
            $properties = Get-ItemProperty -Path $l | Select-Object -Property *

            # Delete any property that contains the keyword
            foreach ($property in $properties.PSObject.Properties) {
                if ($property.Name -like "*$m*") {
                    $global:Originalkey = $l
                    $global:SafeFileName = $l.replace(':', '_') # Replacing " with _ for supported filename
                    $global:SafeFileName = $global:SafeFileName.replace('\', '_') # Replacing \ with _ for supported filename
                    $global:SafeExportName = $l.replace(':', '') # Removing : to support exporting variable
                    $global:RegOutputFile = "";
                    $global:RegOutputFile = $global:dirPath + "\" + $SafeFileName + ".reg";

                    reg.exe export $global:SafeExportName $global:RegOutputFile /y | out-null;
                    if ($LASTEXITCODE -ne 0) {
                        Write-Warning "Unknown Error: $LASTEXITCODE"
                    }
                    else {
                        Write-Host "Exported $l successfully";
                    }

                    if ($global:safemode -eq "No") {
                        try {
                            Write-Host "Deleting $($property.Name)"
                            Remove-ItemProperty -Path $l -Name $property.Name -Force
                            Write-Host " Successfully Deleted $($property.Name) From: $global:SafeExportName"
                            Write-Host ""
                        }
                        catch {
                            Write-Warning "Exception caught";
                            Write-Host "$_";
                        }
                    }
                    else {
                        Write-Host "    Key for Deletion/Modification: $($property.Name)"
                        Write-Host " **** safemode: No changes have been made ****"
                        Write-Host ""
                    }
                }
            }
        }
    }

    # This function will search a folder and subfolders for any Name or Data fields that contain the keyword and will remove the entire folder.
    Write-Host ""
    Write-Host "Scanning Windows Registry 7of7..."
    Write-Host "... This may take a few minutes."
    Write-Host ""
    $RegkeysHive = ""
    $SearchWord = ""
    $m = ""
    $properties = ""
    $property = ""

    $RegkeysHive = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Components'
    )

    $l = ""
    foreach ($l in $RegkeysHive) {

        $SearchWord = @(
            '\\Cylance\\Desktop\\'
            '\\Cylance\\Optics\\'
        )

        foreach ($m in $SearchWord) {
            # Get all properties of the specified registry key
            $properties = get-childitem -recurse $l | get-itemproperty | where { $_ -match $m }

            # Delete any property that contains the keyword
            foreach ($property in $properties) {
                Write-Output "Deleting registry property: "
                $global:Originalkey = $l
                $global:SafeFileName = $l.replace(':', '_') # Replacing " with _ for supported filename
                $global:SafeFileName = $global:SafeFileName.replace('\', '_') # Replacing \ with _ for supported filename
                $global:SafeExportName = $l.replace(':', '') # Removing : to support exporting variable
                $global:SafeExportName = $global:SafeExportName + "\" + $($property.PSChildName)
                $global:RegOutputFile = "";
                $global:RegOutputFile = $global:dirPath + "\" + $SafeFileName + "_" + $($property.PSChildName) + ".reg";

                reg.exe export $global:SafeExportName $global:RegOutputFile /y | out-null;

                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "Unknown Error: $LASTEXITCODE"
                }
                else {
                    Write-Host "Exported $global:SafeExportName successfully";
                    Write-Host ""
                }

                if ($global:safemode -eq "No") {
                    try {
                        Write-Host "Deleting $($property.PSChildName)"
                        Remove-Item -Path $global:Originalkey\$($property.PSChildName) -Force -Recurse -ErrorAction stop
                        Write-Host " Successfully Deleted $($property.PSChildName) From: $global:SafeExportName"
                        Write-Host ""
                    }
                    catch {
                        Write-Warning "Exception caught";
                        Write-Host "$_";
                    }
                }
                else {
                    Write-Host "    Key for Deletion/Modification: $($property.PSChildName)"
                    Write-Host " **** safemode: No changes have been made ****"
                    Write-Host ""
                }
            }
        }
    }
} # End of all Backup_Reg_Keys


function Search_Reg_CyDevFlt {
    # Start of Search_Reg_CyDevFlt

    $RegFilterList = ""
    $RegFilterList = @('UpperFilters', 'LowerFilters')

    $f = ""
    foreach ($f in $RegFilterList) {
        # Start of foreach RegFilterList
        $global:MultiStringName = $f

        Write-Host ""
        #Write-Host "safemode Enabled: $global:safemode"
        Write-Host "RegKey Name: $global:MultiStringName" #UpperFilters or LowerFilters
        Write-Host "RegKey Value: $global:RemoveDelete_Value"
        Write-Host "RegKey Start Path: $global:RegistryPath"

        $Registrykeys = Get-ChildItem -Recurse -Path "Registry::$global:RegistryPath" -ErrorAction SilentlyContinue
        $Registrykeys | Select-Object -Property Name | ForEach-Object { #ForEach-Object Start
            $Path = $_.name
            $MultiStringValue = (Get-ItemProperty Registry::$Path -Name $global:MultiStringName -ErrorAction SilentlyContinue).$global:MultiStringName

            if ($MultiStringValue -like $global:RemoveDelete_Value) {

                if ($MultiStringValue.length -eq '1') {
                    Write-Host ""
                    Write-Host "Single Value Found"
                    Write-Host "    Path: $path"
                    Write-Host "    Old Value: $MultiStringValue"
                    if ($global:safemode -eq 'No') {
                        Write-Host "    Removed $Path $global:MultiStringName"
                        Remove-ItemProperty Registry::$Path -Name $global:MultiStringName
                    }
                    else {
                        Write-Host "    **** safemode: No changes have been made ****"
                    }

                }
                elseif ($MultiStringValue.length -gt '1') {
                    Write-Host ""
                    Write-Host "Multi Value Found"
                    Write-Host "    Path: $path"
                    Write-Host "    Old Value: $MultiStringValue"
                    $NewMultiStringValue = $MultiStringValue | Where-Object { $_ -ne $global:RemoveDelete_Value }
                    #Remove CyDevFlt and print the new list
                    Write-Host "    New Value: $NewMultiStringValue"
                    if ($global:safemode -eq 'No') {
                        Write-Host "    Updated $Path $global:MultiStringName"
                        Set-ItemProperty Registry::$Path -Name $global:MultiStringName -Value $NewMultiStringValue
                    }
                    else {
                        Write-Host "    **** safemode: No changes have been made ****"
                    }
                } #end elseif
            } # end if

        } #ForEach-Object End
    } # End of foreach RegFilterList

} # end remove CyDevFlt function

function Search_Reg_CyDevFltV2 {
    # Start of Search_Reg_CyDevFltV2

    $RegFilterList = ""
    $RegFilterList = @('UpperFilters', 'LowerFilters')

    $f = ""
    foreach ($f in $RegFilterList) {
        # Start of foreach RegFilterList
        $global:MultiStringName = $f

        Write-Host ""
        #Write-Host "safemode Enabled: $global:safemode"
        Write-Host "RegKey Name: $global:MultiStringName" #UpperFilters or LowerFilters
        Write-Host "RegKey Value: $global:RemoveDelete_Value2"
        Write-Host "RegKey Start Path: $global:RegistryPath"

        $Registrykeys = Get-ChildItem -Recurse -Path "Registry::$global:RegistryPath" -ErrorAction SilentlyContinue
        $Registrykeys | Select-Object -Property Name | ForEach-Object { #ForEach-Object Start
            $Path = $_.name
            $MultiStringValue = (Get-ItemProperty Registry::$Path -Name $global:MultiStringName -ErrorAction SilentlyContinue).$global:MultiStringName

            if ($MultiStringValue -like $global:RemoveDelete_Value2) {

                if ($MultiStringValue.length -eq '1') {
                    Write-Host ""
                    Write-Host "Single Value Found"
                    Write-Host "    Path: $path"
                    Write-Host "    Old Value: $MultiStringValue"
                    if ($global:safemode -eq 'No') {
                        Write-Host "    Removed $Path $global:MultiStringName"
                        Remove-ItemProperty Registry::$Path -Name $global:MultiStringName
                    }
                    else {
                        Write-Host "    **** safemode: No changes have been made ****"
                    }

                }
                elseif ($MultiStringValue.length -gt '1') {
                    Write-Host ""
                    Write-Host "Multi Value Found"
                    Write-Host "    Path: $path"
                    Write-Host "    Old Value: $MultiStringValue"
                    $NewMultiStringValue = $MultiStringValue | Where-Object { $_ -ne $global:RemoveDelete_Value2 }
                    #Remove CyDevFltV2 and print the new list
                    Write-Host "    New Value: $NewMultiStringValue"
                    if ($global:safemode -eq 'No') {
                        Write-Host "    Updated $Path $global:MultiStringName"
                        Set-ItemProperty Registry::$Path -Name $global:MultiStringName -Value $NewMultiStringValue
                    }
                    else {
                        Write-Host "    **** safemode: No changes have been made ****"
                    }
                } #end elseif
            } # end if

        } #ForEach-Object End
    } # End of foreach RegFilterList

} # end remove CyDevFltv2 function

function Delete_Reg_Keys {
    # Start of Delete_Reg_Keys
    if ($global:safemode -eq "Yes") {
        # Start of safemode check
        Write-Host "    Key for Deletion/Modification: $global:SafeExportName"
        Write-Host " **** safemode: No changes have been made ****"
        Write-Host ""

    }
    else {
        $ll = "Registry::" + $HiveAbr + "\" + $Hivepath
        if (Test-Path -Path $ll) {
            Write-Host " Taking Ownership of $global:Originalkey"
            try {
                Take-Permissions $HiveAbr $Hivepath
            }
            catch {
                # Start catch
                Write-Warning "Exception caught";
                Write-Warning "$_";
            } # End catch

            Write-Host "Deleting $global:SafeExportName"
            try {
                Remove-Item -Path $global:Originalkey -Force -Recurse -ErrorAction Stop
                Write-Host " Successfully Deleted $global:SafeExportName"
                Write-Host ""
            }
            catch {
                # Start catch
                Write-Warning "    Exception caught";
                Write-Warning "    $_";
                Write-Host ""
            } # End catch

        }
        else {
            Write-Host "Path Not Found"
            Write-Host $ll
            Write-Host ""
        }

    } # End of safemode check
} # End of Delete_Reg_Keys

function Take-Permissions {

    # Start Take over ownership and permissions on a registry hive
    # Developed for PowerShell v4.0

    # # group BULTIN\Users takes full control of key and all subkeys
    #Take-Permissions "HKLM" "SOFTWARE\test"

    # group Everyone takes full control of key and all subkeys
    #Take-Permissions "HKLM" "SOFTWARE\test" "S-1-1-0"

    # group Everyone takes full control of key WITHOUT subkeys
    #Take-Permissions "HKLM" "SOFTWARE\test" "S-1-1-0" $false

    param($rootKey, $key, [System.Security.Principal.SecurityIdentifier]$sid = 'S-1-5-32-545', $recurse = $true)

    switch -regex ($rootKey) {
        'HKCU|HKEY_CURRENT_USER' { $rootKey = 'CurrentUser' }
        'HKLM|HKEY_LOCAL_MACHINE' { $rootKey = 'LocalMachine' }
        'HKCR|HKEY_CLASSES_ROOT' { $rootKey = 'ClassesRoot' }
        'HKCC|HKEY_CURRENT_CONFIG' { $rootKey = 'CurrentConfig' }
        'HKU|HKEY_USERS' { $rootKey = 'Users' }
    }

    ### Step 1 - escalate current process's privilege
    # get SeTakeOwnership, SeBackup and SeRestore privileges before executes next lines, script needs Admin privilege
    $import = '[DllImport("ntdll.dll")] public static extern int RtlAdjustPrivilege(ulong a, bool b, bool c, ref bool d);'
    $ntdll = Add-Type -Member $import -Name NtDll -PassThru
    $privileges = @{ SeTakeOwnership = 9; SeBackup = 17; SeRestore = 18 }
    $i = ""
    foreach ($i in $privileges.Values) {
        $null = $ntdll::RtlAdjustPrivilege($i, 1, 0, [ref]0)
    }

    function Take-KeyPermissions {
        param($rootKey, $key, $sid, $recurse, $recurseLevel = 0)

        ### Step 2 - get ownerships of key - it works only for current key
        $regKey = [Microsoft.Win32.Registry]::$rootKey.OpenSubKey($key, 'ReadWriteSubTree', 'TakeOwnership')
        $acl = New-Object System.Security.AccessControl.RegistrySecurity
        $acl.SetOwner($sid)
        $regKey.SetAccessControl($acl)

        ### Step 3 - enable inheritance of permissions (not ownership) for current key from parent
        $acl.SetAccessRuleProtection($false, $false)
        $regKey.SetAccessControl($acl)

        ### Step 4 - only for top-level key, change permissions for current key and propagate it for subkeys
        # to enable propagations for subkeys, it needs to execute Steps 2-3 for each subkey (Step 5)
        if ($recurseLevel -eq 0) {
            $regKey = $regKey.OpenSubKey('', 'ReadWriteSubTree', 'ChangePermissions')
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule($sid, 'FullControl', 'ContainerInherit', 'None', 'Allow')
            $acl.ResetAccessRule($rule)
            $regKey.SetAccessControl($acl)
        }

        ### Step 5 - recursively repeat steps 2-5 for subkeys
        if ($recurse) {
            foreach ($subKey in $regKey.OpenSubKey('').GetSubKeyNames()) {
                Take-KeyPermissions $rootKey ($key + '\' + $subKey) $sid $recurse ($recurseLevel + 1)
            }
        }
    }
    Take-KeyPermissions $rootKey $key $sid $recurse
}

function Take-Ownership-Permission-Individual-Files {
    # Start Take ownership of specific files
    # Retake ownership of the following files
    $FolderPaths1 = ""
    $FolderPaths1 = @(
          (${Env:SystemRoot} + "\System32\drivers\CyProtectDrv64.sys")
        , (${Env:SystemRoot} + "\System32\drivers\CylanceDrv64.sys") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\System32\drivers\CyOpticsDrv.sys") # Added with Optics 3.2
        , (${Env:SystemRoot} + "\System32\drivers\CyDevFlt64.sys")
        , (${Env:SystemRoot} + "\System32\drivers\CyDevFltV264.sys") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\System32\drivers\CyElamDrv64.cat") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\System32\drivers\CyElamDrv64.inf") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\System32\drivers\CyElamDrv64.sys") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\ELAMBKUP\CyElamDrv64.sys") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\ELAMBKUP\CyElamDrv64.sys.bak") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\CylanceDrv64.cat") # Added with Protect 3.x
        , (${Env:SystemRoot} + "\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\CyOpticsDrv.cat") # Added with Protect 3.x
    )
    Write-Host ""
    Write-Host "Assigning ownership to Administrator group for Individual Files"
    foreach ($path1 in $FolderPaths1) {
        if ($global:safemode -eq "Yes") {
            # Start safemode Check
            Write-Host " **** safemode: No changes have been made ****"
        }
        else {
            # Start safemode Check Else
            if (Test-Path -Path $path1) {
                # Start Test-Path
                    takeown.exe /f "$path1" /A
                    if ($LASTEXITCODE -eq 0) {
                    } else {
                        Write-Warning "Unknown Error: $LASTEXITCODE"
                    }
            } # End Test-Path
        } # End safemode Check Else
    }

    # Retake Permissions of the following files/folders
    $FolderPaths2 = @(
          (${Env:SystemRoot} + "\System32\drivers\CyProtectDrv64.sys")
        , (${Env:SystemRoot} + "\System32\drivers\CylanceDrv64.sys") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\System32\drivers\CyOpticsDrv.sys") # Added with Optics 3.2
        , (${Env:SystemRoot} + "\System32\drivers\CyOpticsDrv.bak") # Added with Optics 3.2
        , (${Env:SystemRoot} + "\System32\drivers\CyDevFlt64.sys")
        , (${Env:SystemRoot} + "\System32\drivers\CyDevFltV264.sys") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\System32\drivers\CyElamDrv64.cat") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\System32\drivers\CyElamDrv64.inf") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\System32\drivers\CyElamDrv64.sys") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\ELAMBKUP\CyElamDrv64.sys") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\ELAMBKUP\CyElamDrv64.sys.bak") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\CylanceDrv64.cat") # Added with Protect 3.x
        , (${Env:SystemRoot} + "\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\CyOpticsDrv.cat") # Added with Protect 3.x
    )

    # Set PS variables for each of the icacls options
    $Grant = "/grant:r"
    #$Remove = "/remove"
    $replaceInherit = "/inheritance:e"
    $permission = ":(OI)(CI)(F)"
    $useraccount2 = "Administrators"

    Write-Host ""
    Write-Host "Assigning Full Control permissions to for Individual Files"
    foreach ($filepath1 in $FolderPaths2) {
        if ($global:safemode -eq "Yes") {
            # Start safemode Check
            Write-Host " **** safemode: No changes have been made ****"
        }
        else {
            # Start safemode Check Else
            if (Test-Path -Path $filepath1) {
                # Start Test-Path
                try {
                    Invoke-Expression -Command ('icacls $filepath1 $Grant "${useraccount2}${permission}" /Q /T')
                    Invoke-Expression -Command ('icacls $filepath1 $replaceInherit /Q /T')
                    if ($LASTEXITCODE -eq 1) {
                        Write-Warning "Unknown Error: $LASTEXITCODE"
                    }
                }
                catch {
                    # Start catch
                    Write-Warning "Exception caught";
                    Write-Warning "$_";
                } # End catch
            } # End Test-Path
        } # End safemode Check Else
    }
} # End Take ownership and permissions on Individual system32 files

function Take-Ownership-Permission-Folder-Files {
    # Start Take ownership and permissions on files and folders

    # Retake ownership of the following files/folders
    $FolderPaths1 = ""
    $FolderPaths1 = @(
         (${Env:Programfiles} + "\Cylance\Desktop")
        #, (${Env:ProgramFiles(x86)} + "\Cylance\Desktop")
        , (${Env:ProgramData} + "\Cylance\Status")
        , (${Env:ProgramData} + "\Cylance\Optics")
        , (${Env:ProgramData} + "\Cylance\Desktop")
        , (${Env:Programfiles} + "\Cylance\Optics")
        #, (${Env:ProgramFiles(x86)} + "\Cylance\Optics")
    )

    Write-Host ""
    Write-Host "Assigning ownership to Administrator group"
    foreach ($path1 in $FolderPaths1) {
        if ($global:safemode -eq "Yes") {
            # Start safemode Check
            Write-Host " **** safemode: No changes have been made ****"
        }
        else {
            # Start safemode Check Else
            if (Test-Path -Path $path1) {
                # Start Test-Path
                takeown.exe /f "$path1" /R /A /D Y
                    if ($LASTEXITCODE -eq 0) {
                    } else {
                        Write-Warning "Unknown Error: $LASTEXITCODE"
                    }
            } # End Test-Path
        } # End safemode Check Else
    }

    # Retake Permissions of the following files/folders
    $FolderPaths2 = ""
    $FolderPaths2 = @(
        (${Env:Programfiles} + "\Cylance\Desktop")
        #, (${Env:ProgramFiles(x86)} + "\Cylance\Desktop")
        , (${Env:ProgramData} + "\Cylance\Status")
        , (${Env:ProgramData} + "\Cylance\Optics")
        , (${Env:ProgramData} + "\Cylance\Desktop")
        , (${Env:Programfiles} + "\Cylance\Optics")
       #, (${Env:ProgramFiles(x86)} + "\Cylance\Optics")
    )

    # Set PS variables for each of the icacls options
    $Grant = "/grant:r"
    #$Remove = "/remove"
    $replaceInherit = "/inheritance:e"
    $permission = ":(OI)(CI)(F)"
    $useraccount2 = "Administrators"
    Write-Host ""
    Write-Host "Assigning Full Control permissions to Files/Folders"
    foreach ($filepath1 in $FolderPaths2) {
        if ($global:safemode -eq "Yes") {
            # Start safemode Check
            Write-Host " **** safemode: No changes have been made ****"
        }
        else {
            # Start safemode Check Else
            if (Test-Path -Path $filepath1) {
                # Start Test-Path
                try {
                    Invoke-Expression -Command ('icacls $filepath1 $Grant "${useraccount2}${permission}" /Q /T')
                    Invoke-Expression -Command ('icacls $filepath1 $replaceInherit /Q /T')
                    if ($LASTEXITCODE -eq 1) {
                        Write-Warning "Unknown Error: $LASTEXITCODE"
                    }
                }
                catch {
                    # Start catch
                    Write-Warning "Exception caught";
                    Write-Warning "$_";
                } # End catch
            } # End Test-Path
        } # End safemode Check Else
    }
    Write-Host ""
} # End Take ownership and permissions on files and folders

function Delete-Files-n-Folders {
    # Start End Delete files and folders

    $FolderPaths3 = @(
      (${Env:LOCALAPPDATA} + "\Cylance\Desktop")
        , (${Env:Programfiles} + "\Cylance\Desktop")
        , (${Env:Programfiles} + "\Cylance\Optics")
        #, (${Env:ProgramFiles(x86)} + "\Cylance\Desktop")
        #, (${Env:ProgramFiles(x86)} + "\Cylance\Optics")
        , (${Env:ProgramData} + "\Cylance\Desktop")
        , (${Env:ProgramData} + "\Cylance\Optics")
        , (${Env:ProgramData} + "\Cylance\Status")
        , (${Env:ProgramData} + "\Microsoft\Windows\Start Menu\Programs\Cylance\Cylance PROTECT.lnk")
        , (${Env:ProgramData} + "\Microsoft\Windows\Start Menu\Programs\Startup\Cylance Desktop.lnk")
        # , (${Env:ProgramData} + "\Microsoft\Windows\Start Menu\Programs\Cylance")
        , (${Env:SystemRoot} + "\System32\DRVSTORE\CylanceDrv*")
        , (${Env:SystemRoot} + "\System32\DRVSTORE\CyProtect*")
        , (${Env:SystemRoot} + "\System32\DRVSTORE\CyOpticsDr*")
        , (${Env:SystemRoot} + "\System32\drivers\CyProtectDrv64.sys")
        , (${Env:SystemRoot} + "\System32\drivers\CylanceDrv64.sys") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\System32\drivers\CyOpticsDrv.sys") # Added with Optics 3.2
        , (${Env:SystemRoot} + "\System32\drivers\CyDevFlt64.sys")
        , (${Env:SystemRoot} + "\System32\drivers\CyDevFltV264.sys") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\System32\drivers\CyElamDrv64.cat") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\System32\drivers\CyElamDrv64.inf") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\System32\drivers\CyElamDrv64.sys") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\ELAMBKUP\CyElamDrv64.sys") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\ELAMBKUP\CyElamDrv64.sys.bak") # Added with Protect 3.1
        , (${Env:SystemRoot} + "\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\CylanceDrv64.cat") # Added with Protect 3.x
        , (${Env:SystemRoot} + "\CatRoot\{F750E6C3-38EE-11D1-85E5-00C04FC295EE}\CyOpticsDrv.cat") # Added with Protect 3.x
    )

    Write-Host "Removing Files and Folders"
    foreach ($filepath3 in $FolderPaths3) {
        if (Test-Path $filepath3) {
            # Start Test-Path
            if ($filepath3 -like '*ELAM*' -or $filepath3 -like '*chp.db*' -or $filepath3 -like '*Status.json*' -or $filepath3 -like '*Optics.pvlt*' -or $filepath3 -like '*OpticsCore.cvlt*' -or $filepath3 -like '*optics.settings*') {
                $global:OutputFile = "";
                # This grabs the folder path like C:\Windows\Folder
                $FolderOnly = (Split-Path -Path $filepath3)
                #Take the $FolderOnly and remove the C:\
                $FolderOnly = $FolderOnly.Replace("C:\", "")
                # Append everything together
                $global:OutputFile = $global:dirPath + "\" + $FolderOnly;

                Write-Host ""
                Write-Host " Backing up $filepath3"
                try {
                    New-Item -ItemType Directory $global:OutputFile -Force  | out-null
                    Copy-Item $filepath3 -Destination $global:OutputFile -Force  | out-null
                }
                catch {
                    Write-Warning "Exception caught";
                    Write-Warning "$_";
                }
            }

            # This will test is the path/file exists from FolderPaths3. If so we will delete it.
            Write-Host ""
            Write-Host " Deleting $filepath3"
            # Delete the files if they exist
            if ($global:safemode -eq "No") {
                #Start of If safemode
                # Before we delete, check if it's a ELAM file
                if ($filepath3 -like '*Elam*') {
                    #Write-Host "Found $filepath3, Checking if Regkey exist..."
                    if (Test-Path -Path 'Registry::HKLM\SYSTEM\CurrentControlSet\Services\CyElamDrv') {
                        Write-Warning "  ELAM Registry still exist. Skipping deletion of file to prevent any boot issues."
                    }
                    else {
                        #Write-Host "Did not found ELAM regkey, safe to continue"
                        try {
                            Remove-Item -Recurse -Force $filepath3 -ErrorAction stop
                        }
                        catch {
                            Write-Warning "$_";
                            $global:RestartRequired++
                        }
                    }
                } elseif ($filepath3 -like '*CyDevFlt*') {
                    try {
                        Remove-Item -Recurse -Force $filepath3 -ErrorAction stop
                    }
                    catch {
                        Write-Warning "$_";
                    }
                }
                else {
                    try {
                        Remove-Item -Recurse -Force $filepath3 -ErrorAction stop
                    }
                    catch {
                        $global:RestartRequired++
                        Write-Warning "$_";
                    }
                } #End Else
            } # End of If safemode

            else {
                Write-Host " **** safemode: No changes have been made ****"
            }
            if ($LASTEXITCODE -eq 1) {
                Write-Warning "Unknown Error: $LASTEXITCODE"
            }
        } # End Test-Path
    }


    $filepath4 = ""
    $FolderPaths4 = ""
    $FolderPaths4 = @(
    (${Env:LOCALAPPDATA} + "\Cylance"),
    (${Env:Programfiles} + "\Cylance"),
    #(${Env:ProgramFiles(x86)} + "\Cylance"),
    (${Env:ProgramData} + "\Cylance")
    )

    foreach ($filepath4 in $FolderPaths4) {
        if (Test-Path $filepath4) {
            # Start test-Path check
            if ((Get-ChildItem $filepath4 | Measure-Object).Count -eq 0) {
                # Start if folder-check is empty
                # Start Test-Path
                Write-Host ""
                Write-Host " Deleting $filepath4"
                if ($global:safemode -eq "No") {
                    try {
                        Remove-Item -Recurse -Force $filepath4 -ErrorAction stop
                    }
                    catch {
                        #Write-Warning "Exception caught";
                        Write-Warning "$_";
                        #Write-Warning "You may need to restart the endpoint and manually delete or re-run the script";
                        $global:RestartWarning++
                    }
                }
                else {
                    Write-Host " **** safemode: No changes have been made ****"
                }
                if ($LASTEXITCODE -eq 1) {
                    Write-Warning "Unknown Error: $LASTEXITCODE"
                }
            } # End if folder-check is empty
        } # End Test-Path check

    } # End Delete files and folders


    # Cleanup the Package Cache directory. If a msi or exe is found, it will delete the parent dir
    Write-Host ""
    $keywords = ""
    $keyword = ""
    $Directories = ""
    $directory = ""

    $Directories = @(
            (${Env:ProgramData} + "\Package Cache")
    )
    foreach ($directory in $Directories) {
        $keywords = @(
            'CylanceProtect'
            , 'CylanceOptics'
        )
        foreach ($keyword in $keywords) {
            Get-ChildItem -Path $directory -Recurse -include @("*.exe", "*.msi") | Where-Object { $_.Name -like "*$keyword*" } | ForEach-Object {
                Write-Host "Found $($_.Directory.FullName)"
                if ($global:safemode -eq "No") {
                    Try {
                        Write-Host " Deleting $($_.Directory.FullName)"
                        Remove-Item $_.Directory.FullName -Recurse -Force -ErrorAction stop
                        Write-Host ""
                    }
                    catch {
                        Write-Warning "Exception caught";
                        Write-Warning "$_";
                    }
                }
                else {
                    Write-Host " **** safemode: No changes have been made ****"
                    Write-Host ""
                }
            }
        } # End foreach keyword in keywords
    } # End foreach directory in Directories

} # Start End Delete files and folders

function Backup-Files-n-Folders {
    $FolderPaths3 = @(
          (${Env:Programfiles} + "\Cylance\Desktop\cylog.log")
        #, (${Env:ProgramFiles(x86)} + "\Cylance\Desktop\cylog.log")
        , (${Env:Programfiles} + "\Cylance\Desktop\Cylance.Host.WMIProvider_GAC.InstallLog")
        #, (${Env:ProgramFiles(x86)} + "\Cylance\Desktop\Cylance.Host.WMIProvider_GAC.InstallLog")
        , (${Env:Programfiles} + "\Cylance\Desktop\Cylance.Host.WMIProvider_GAC.InstallState")
        #, (${Env:ProgramFiles(x86)} + "\Cylance\Desktop\Cylance.Host.WMIProvider_GAC.InstallState")
        , (${Env:Programfiles} + "\Cylance\Desktop\log")
        #, (${Env:ProgramFiles(x86)} + "\Cylance\Desktop\log")
        , (${Env:ProgramData} + "\Cylance\Status\Status.json")
        , (${Env:ProgramData} + "\Cylance\Desktop\chp.db")
        , (${Env:ProgramData} + "\Cylance\Desktop\chp.db-journal")
        , (${Env:ProgramData} + "\Cylance\Desktop\CylanceWscCmd.Log")
        , (${Env:ProgramData} + "\Cylance\Optics\optics.settings")
        , (${Env:ProgramData} + "\Cylance\Optics\DataStore\DataBases\Core\OpticsCore.cvlt")
        , (${Env:ProgramData} + "\Cylance\Optics\DataStore\DataBases\Processed\Optics.pvlt")
    )

    Write-Host ""
    Write-Host "Backing up database files..."
    foreach ($filepath3 in $FolderPaths3) {
        if (Test-Path $filepath3) {
            # Start Test-Path
            if ($filepath3 -like '*ELAM*' -or $filepath3 -like '*.Log*' -or $filepath3 -like '*.InstallState*' -or $filepath3 -like '*.InstallLog*' -or $filepath3 -like '*chp.db*' -or $filepath3 -like '*Status.json*' -or $filepath3 -like '*Optics.pvlt*' -or $filepath3 -like '*OpticsCore.cvlt*' -or $filepath3 -like '*optics.settings*') {
                $global:OutputFile = "";
                # This grabs the folder path like C:\Windows\Folder
                $FolderOnly = (Split-Path -Path $filepath3)
                #Take the $FolderOnly and remove the C:\
                $FolderOnly = $FolderOnly.Replace("C:\", "")
                # Append everything together
                $global:OutputFile = $global:dirPath + "\" + $FolderOnly;

                Write-Host " Backing up $filepath3"
                try {
                    New-Item -ItemType Directory $global:OutputFile -Force | out-null
                    Copy-Item $filepath3 -Destination $global:OutputFile -Force | out-null
                }
                catch {
                    Write-Warning "Exception caught";
                    Write-Warning "$_";
                }
            }
        } # End Test-Path
    }
    Write-Host ""
} # End Backup-Files-n-Folders

function Stop-ServiceWithTimeout ([string] $name, [int] $timeoutSeconds) {
    # Start Function to handle timeout on start service
    # Creating this function to handle cases where the script waits on stoping forever
    $timespan = New-Object -TypeName System.Timespan -ArgumentList 0, 0, $timeoutSeconds
    $svc = Get-Service -Name $name
    if ($svc -eq $null) { return $false }
    if ($svc.Status -eq [ServiceProcess.ServiceControllerStatus]::Stopped) { return $true }
    $svc.Stop()
    try {
        $svc.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, $timespan)
    }
    catch [ServiceProcess.TimeoutException] {
        Write-Verbose "Timeout stopping service $($svc.Name)"
        return $false
    }
    return $true
} # End Function to handle timeout on start service

function Check-ServiceWithTimeout ([string] $name, [int] $timeoutSeconds) {
    # Function that will continue to check a Service for its status but timeout after xx seconds
    $timespan = New-Object -TypeName System.Timespan -ArgumentList 0, 0, $timeoutSeconds
    $svc = Get-Service -Name $name
    if ($svc -eq $null) { return $false }
    if ($svc.Status -eq [ServiceProcess.ServiceControllerStatus]::Stopped) { return $true }
    try {
        $svc.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, $timespan)
    }
    catch [ServiceProcess.TimeoutException] {
        Write-Verbose "Timeout stopping service $($svc.Name)"
        return $false
    }
    return $true
}

function Pre-DeRegistration {
    # This function will delete the keys needed to ensure all policy data is removed and protect is deregistered. This will aid with Prevent Service Shutdown.
    if (Test-Path -Path "Registry::HKLM\SOFTWARE\Cylance\Desktop") {
        if ($global:safemode -eq "No") {
            $k = "HKLM:\SOFTWARE\Cylance\Desktop"
            $kk = $k.replace(':', '') # Replacing " with nonthing
            $kk = "Registry::" + $kk # Registry:: which is needed when you are not using :\ in the path
            $global:Originalkey = $k
            $global:SafeFileName = $k.replace(':', '_') # Replacing " with _ for supported filename
            $global:SafeFileName = $global:SafeFileName.replace('\', '_') # Replacing \ with _ for supported filename
            $global:SafeExportName = $k.replace(':', '') # Removing : to support exporting variable
            $HiveAbr = $global:Originalkey.Substring(0, $global:Originalkey.IndexOf(':')) # take only "HKLM" from the variable
            $Hivepath = $global:Originalkey.Substring($global:Originalkey.IndexOf('\') + 1) # Strip "HKLM:\" from the variable
            $global:RegOutputFile = "";
            $global:RegOutputFile = $global:dirPath + "\" + $global:SafeFileName + ".reg";

            Write-Host ""
            Write-Host "Taking Ownership of HKLM:\SOFTWARE\Cylance\Desktop"
            try {
                Take-Permissions $HiveAbr $Hivepath
            }
            catch {
                Write-Warning "Exception caught while taking ownership of HKLM:\SOFTWARE\Cylance\Desktop";
                Write-Warning "$_";
            }

            Write-Host "Exporting HKLM:\SOFTWARE\Cylance\Desktop"
            reg.exe export $global:SafeExportName $global:RegOutputFile /y | out-null;
            if ( $LASTEXITCODE -ne 0 ) {
                Write-Host "Exception caught while exporting of HKLM:\SOFTWARE\Cylance\Desktop Error: $LASTEXITCODE"
                Write-Host ""
            }

            Write-Host "Deleting HKLM:\SOFTWARE\Cylance\Desktop\*"
            try {
                Remove-Item -Path HKLM:\SOFTWARE\Cylance\Desktop -Recurse
            }
            catch {
                Write-Warning "Exception caught while removing HKLM:\SOFTWARE\Cylance\Desktop";
                Write-Warning "$_";
            }
        }
    }
}

function Stop-CylanceSVC {
    if ($global:safemode -eq "No") {
        $name = ""
        $name = "CylanceSVC"

        # Service status: StartPending, StopPending, Running, Stopped
        try {
            $ServiceStatus = (Get-Service -name $name -ErrorAction SilentlyContinue).Status
        }
        catch {
            Write-Host "Exception caught while getting the service status of CylanceSVC";
            Write-Host "$_";
        }
        If (!$ServiceStatus) {
            #Write-Host "Service $name not Found"
            $ServiceStatus = "Missing"
        }
        #Write-Host "Current Status of CylanceSVC: $ServiceStatus"
        Write-Host "Attempting to stop CylanceSVC Service"

        try {
            Stop-Service -Name $name -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "Exception caught while stopping CylanceSVC via Stop-Service";
            Write-Host "$_";
        }

        $ProgramFilePaths = @(
            (${Env:Programfiles} + "\Cylance\Desktop")
            #, (${Env:ProgramFiles(x86)} + "\Cylance\Desktop")
        )

        foreach ($ProgramFilePath in $ProgramFilePaths) {
            if (Test-Path "$ProgramFilePath\CylanceSVC.exe" -PathType Leaf) {
                Start-Process -NoNewWindow -Wait -ErrorAction Stop -FilePath $ProgramFilePath\CylanceSvc.exe -ArgumentList "/shutdown"
            }
        }

        try {
            $ServiceStatus = (Get-Service -name $name -ErrorAction SilentlyContinue).Status
        }
        catch {
            Write-Host "Exception caught while getting the service status of CylanceSVC";
            Write-Host "$_";
        }
        If (!$ServiceStatus) {
            #Write-Host "Service $name not Found"
            $ServiceStatus = "Missing"
        }

        #Write-Host "Current Status of CylanceSVC: $ServiceStatus"

        If ($ServiceStatus -eq "StopPending" -or $ServiceStatus -eq "StartPending") {
            Check-ServiceWithTimeout $name 30
            try {
                $ServiceStatus = (Get-Service -name $name -ErrorAction SilentlyContinue).Status
            }
            catch {
                Write-Host "Exception caught while getting the service status of CylanceSVC";
                Write-Host "$_";
            }
            If (!$ServiceStatus) {
                #Write-Host "Service $name not Found"
                $ServiceStatus = "Missing"
            }
            #Write-Host "Current Status of CylanceSVC: $ServiceStatus"
        }
    }
}

function Stop-CyOptics {
    if ($global:safemode -eq "No") {
        $name = ""
        $name = "CyOptics"
        Write-Host ""
        # Service status: StartPending, StopPending, Running, Stopped
        try {
            $ServiceStatus = (Get-Service -name $name -ErrorAction SilentlyContinue).Status
        }
        catch {
            Write-Host "Exception caught while getting the service status of CylanceSVC";
            Write-Host "$_";
        }
        If (!$ServiceStatus) {
            #Write-Host "Service $name not Found"
            $ServiceStatus = "Missing"
        }
        #Write-Host ""
        #Write-Host "Current Status of CyOptics: $ServiceStatus"
        Write-Host "Attempting to stop CyOptics Service"

        try {
            Stop-Service -Name $name -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "Exception caught while stopping CyOptics via Stop-Service";
            Write-Host "$_";
        }

        try {
            $ServiceStatus = (Get-Service -name $name -ErrorAction SilentlyContinue).Status
        }
        catch {
            Write-Host "Exception caught while getting the service status of CyOptics";
            Write-Host "$_";
        }
        If (!$ServiceStatus) {
            #Write-Host "Service $name not Found"
            $ServiceStatus = "Missing"
        }

        #Write-Host "Current Status of CyOptics: $ServiceStatus"

        If ($ServiceStatus -eq "StopPending" -or $ServiceStatus -eq "StartPending") {
            Check-ServiceWithTimeout $name 30
            try {
                $ServiceStatus = (Get-Service -name $name -ErrorAction SilentlyContinue).Status
            }
            catch {
                Write-Host "Exception caught while getting the service status of CyOptics";
                Write-Host "$_";
            }
            #Write-Host "Current Status of CyOptics: $ServiceStatus"
        }
    }
}

function Start-CylanceSVC {
    if ($global:safemode -eq "No") {
        $name = ""
        $name = "CylanceSVC"
        Write-Host ""
        # Service status: StartPending, StopPending, Running, Stopped
        try {
            $ServiceStatus = (Get-Service -name $name -ErrorAction SilentlyContinue).Status
        }
        catch {
            Write-Host "Exception caught while getting the service status of CylanceSVC";
            Write-Host "$_";
        }
        If (!$ServiceStatus) {
            #Write-Host "Service $name not Found"
            $ServiceStatus = "Missing"
        }

        #Write-Host ""
        #Write-Host "Current Status of CylanceSVC: $ServiceStatus"
        Write-Host "Attempting to start CylanceSVC Service"

        try {
            Start-Service -Name $name -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "Exception caught while starting CylanceSVC via Stop-Service";
            Write-Host "$_";
        }

        $ProgramFilePaths = @(
            (${Env:Programfiles} + "\Cylance\Desktop")
            #, (${Env:ProgramFiles(x86)} + "\Cylance\Desktop")
        )

        foreach ($ProgramFilePath in $ProgramFilePaths) {
            if (Test-Path "$ProgramFilePath\CylanceSVC.exe" -PathType Leaf) {
                Start-Process -NoNewWindow -Wait -ErrorAction Stop -FilePath $ProgramFilePath\CylanceSvc.exe
            }
        }

        try {
            $ServiceStatus = (Get-Service -name $name -ErrorAction SilentlyContinue).Status
        }
        catch {
            Write-Host "Exception caught while getting the service status of CylanceSVC";
            Write-Host "$_";
        }
        If (!$ServiceStatus) {
            #Write-Host "Service $name not Found"
            $ServiceStatus = "Missing"
        }

        #Write-Host "Current Status of CylanceSVC: $ServiceStatus"

        If ($ServiceStatus -eq "StopPending" -or $ServiceStatus -eq "StartPending") {
            Check-ServiceWithTimeout $name 30
            try {
                $ServiceStatus = (Get-Service -name $name -ErrorAction SilentlyContinue).Status
            }
            catch {
                Write-Host "Exception caught while getting the service status of CylanceSVC";
                Write-Host "$_";
            }
            If (!$ServiceStatus) {
                #Write-Host "Service $name not Found"
                $ServiceStatus = "Missing"
            }
            #Write-Host "Current Status of CylanceSVC: $ServiceStatus"

        }
    }
}

function Start-CyOptics {
    if ($global:safemode -eq "No") {
        $name = ""
        $name = "CyOptics"
        Write-Host ""
        # Service status: StartPending, StopPending, Running, Stopped
        try {
            $ServiceStatus = (Get-Service -name $name -ErrorAction SilentlyContinue).Status
        }
        catch {
            Write-Host "Exception caught while getting the service status of CylanceSVC";
            Write-Host "$_";
        }
        If (!$ServiceStatus) {
            #Write-Host "Service $name not Found"
            $ServiceStatus = "Missing"
        }

        #Write-Host ""
        #Write-Host "Current Status of CyOptics: $ServiceStatus"
        Write-Host "Attempting to start CyOptics Service"

        try {
            Start-Service -Name $name -ErrorAction SilentlyContinue
        }
        catch {
            Write-Host "Exception caught while starting CyOptics via Stop-Service";
            Write-Host "$_";
        }

        try {
            $ServiceStatus = (Get-Service -name $name -ErrorAction SilentlyContinue).Status
        }
        catch {
            Write-Host "Exception caught while getting the service status of CyOptics";
            Write-Host "$_";
        }
        If (!$ServiceStatus) {
            #Write-Host "Service $name not Found"
            $ServiceStatus = "Missing"
        }

        #Write-Host "Current Status of CyOptics: $ServiceStatus"

        If ($ServiceStatus -eq "StopPending" -or $ServiceStatus -eq "StartPending") {
            Check-ServiceWithTimeout $name 30
            try {
                $ServiceStatus = (Get-Service -name $name -ErrorAction SilentlyContinue).Status
            }
            catch {
                Write-Host "Exception caught while getting the service status of CyOptics";
                Write-Host "$_";
            }
            If (!$ServiceStatus) {
                #Write-Host "Service $name not Found"
                $ServiceStatus = "Missing"
            }

            #Write-Host "Current Status of CyOptics: $ServiceStatus"
        }
        Write-Host ""
    }
}

function ReEnable-Windows-Defender {
    # Windows Defender WdBoot is disabled when Protect is installed by the following values
    # Disabled
    # Group = _Early-launch
    # Start = 3
    # Enabled
    # Group = Early-launch
    # Start = 0

    # Ensure that the \SYSTEM\CurrentControlSet\Services\WdBoot Key exists
    if (Test-Path -Path "Registry::HKLM\SYSTEM\CurrentControlSet\Services\WdBoot") {
        $global:Originalkey = ""
        $HiveAbr = ""
        $Hivepath = ""
        $global:Originalkey = "HKLM:\SYSTEM\CurrentControlSet\Services\WdBoot"
        $HiveAbr = $global:Originalkey.Substring(0, $global:Originalkey.IndexOf(':'))
        $Hivepath = $global:Originalkey.Substring($global:Originalkey.IndexOf('\') + 1)
        Write-Host ""
        Write-Host "Checking if Early-Launch is Disabled in the Registry"
        # Within the \SYSTEM\CurrentControlSet\Services\WdBoot Key, check for Group = _Early-Launch
        try {
            $WdEarlyLaunchGroup = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\WdBoot -ErrorAction Stop).Group
        }
        catch {
            # Start catch
            Write-Warning "Exception caught";
            Write-Warning "$_";
        } # End catch

        # Within the \SYSTEM\CurrentControlSet\Services\WdBoot Key, check for Start = 3
        try {
            $WdEarlyLaunchStart = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\WdBoot -ErrorAction Stop).Start
        }
        catch {
            # Start catch
            Write-Warning "Exception caught";
            Write-Warning "$_";
        } # End catch

        # Within the \SYSTEM\CurrentControlSet\Services\WdBoot Key, check for ImagePath
        try {
            $WdEarlyLaunchImagePath = (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\WdBoot -ErrorAction Stop).ImagePath
        }
        catch {
            # Start catch
            Write-Warning "Exception caught";
            Write-Warning "$_";
        } # End catch

        If ( $WdEarlyLaunchGroup -like '*_Early-Launch*' ) {
            Write-Host " 'Windows Defender Early-Launch' is Disabled($WdEarlyLaunchGroup)";
            Write-Host "  Changing Windows Defender Early-Launch to Enabled(Early-Launch)";
            if ($global:safemode -eq "No") {

                # try to take ownership of the folder
                Write-Host " Taking Ownership of $global:Originalkey"
                try {
                    Take-Permissions $HiveAbr $Hivepath
                }
                catch {
                    # Start catch
                    Write-Warning "Exception caught";
                    Write-Warning "$_";
                } # End catch

                # try to re-enable Group from _Early-Launch to Early-Launch
                try {
                    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdBoot" -Name "Group" -Value "Early-Launch";
                    if ($LASTEXITCODE -eq 1) {
                        Write-Warning "Unknown Error: $LASTEXITCODE"
                        try { Stop-Transcript } catch {}
                        exit 1
                    }
                }
                catch {
                    # Start catch
                    Write-Warning "Exception caught";
                    Write-Warning "$_";
                } # End catch

                If ( $WdEarlyLaunchStart -eq 3 ) {
                    Write-Host " 'Windows Defender Early-Launch' Service is Disabled($WdEarlyLaunchStart)";
                    Write-Host "  Changing Windows Defender Early-Launch to Enabled(0)";
                    # try to re-enable Start to 0
                    try {
                        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdBoot" -Name "Start" -Value 0;
                        if ($LASTEXITCODE -eq 1) {
                            Write-Warning "Unknown Error: $LASTEXITCODE"
                            try { Stop-Transcript } catch {}
                            exit 1
                        }
                    }
                    catch {
                        # Start catch
                        Write-Warning "Exception caught";
                        Write-Warning "$_";
                    } # End catch
                }

                If ( $WdEarlyLaunchImagePath -like '*\SystemRoot\system32\drivers\wd\WdBoot.sys*' ) {
                    Write-Host " 'Windows Defender Early-Launch' ImagePath($WdEarlyLaunchImagePath)";
                    Write-Host "  Changing Windows Defender ImagePath to system32\drivers\wd\WdBoot.sys";
                    # try to re-enable Start to 0
                    try {
                        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WdBoot" -Name "ImagePath" -Value "system32\drivers\wd\WdBoot.sys";
                        if ($LASTEXITCODE -eq 1) {
                            Write-Warning "Unknown Error: $LASTEXITCODE"
                            try { Stop-Transcript } catch {}
                            exit 1
                        }
                    }
                    catch {
                        # Start catch
                        Write-Warning "Exception caught";
                        Write-Warning "$_";
                    } # End catch
                }

            }
            else {
                Write-Host " **** safemode: No changes have been made ****"
            } # End safemode Check
        }
        else {
            Write-Host " 'Windows Defender Early-Launch' is already Enabled($WdEarlyLaunchGroup)";
        }
    }
    else {
        Write-Host ""
        Write-Host "Path does not exist: HKLM:\SYSTEM\CurrentControlSet\Services\WdBoot"
    } # End If Test-Path
} # End Function to check and reenable windows defender

function Unload-DLLs {
    if ($global:safemode -eq "No") {
        $Path = ""
        $ProgramPaths = ""
        $ProgramPaths = @(
            (${Env:Programfiles} + "\Cylance\Desktop")
            #,(${Env:ProgramFiles(x86)} + "\Cylance\Desktop")
        )
        Write-Host "Attempting to unregister DLL files"
        foreach ($path in $ProgramPaths) {
            if (Test-Path $path) {
                Get-ChildItem -Path $path -Recurse -include *.dll |
                Foreach-Object {
                    $regsvrp = Start-Process regsvr32.exe -ArgumentList "/u /s `"$_`"" -PassThru
                    $regsvrp.WaitForExit(5000) # Wait (up to) 5 seconds
                    If ($regsvrp.ExitCode -ne 0) {
                        Write-Host "Successfully unregistered: $_"
                    }
                    elseif ($regsvrp.ExitCode -ne 1) {
                        Write-Host "Invalid Argument: $_"
                    }
                    elseif ($regsvrp.ExitCode -ne 2) {
                        Write-Host "OleInitialize Failed: $_"
                    }
                    elseif ($regsvrp.ExitCode -ne 3) {
                        Write-Host "LoadLibrary Failed: $_"
                    }
                    elseif ($regsvrp.ExitCode -ne 4) {
                        Write-Host "GetProcAddress failed: $_"
                    }
                    elseif ($regsvrp.ExitCode -ne 5) {
                        Write-Host "DllRegisterServer or DllUnregisterServer failed: $_"
                    }
                }
            }
        }
    }
}

function SC-Stop_Delete-CylanceDrv {
    if ($global:safemode -eq "No") {
        $Driver = "CylanceDrv"
        # Output the current filters
        Write-Host ""
        Write-Host "Listing Driver filters"
        try {
            & fltmc filters
        }
        catch {
            Write-Host "Error"
            Write-Information "$_";
        }

        # Attempt to Stop the Driver
        Write-Host ""
        Write-Host "Attempting to stop $Driver"
        & sc.exe stop $Driver | out-null
        if ( $LASTEXITCODE -eq 0 ) {
            Write-Host "$Driver was stopped successfully."
            Write-Host ""
        }
        elseif ( $LASTEXITCODE -eq 5 ) {
            Write-Warning "Access Denied! Please reboot the endpoint and re-run the script."
            Write-Host ""
        }
        elseif ( $LASTEXITCODE -eq 1072 ) {
            Write-Warning "Service is marked for deletion and will be removed during the next reboot."
            Write-Host ""
        }
        elseif ( $LASTEXITCODE -eq 1060 ) {
            Write-Host "The specified service $Driver does not exist as an installed service."
            Write-Host ""
        }
        elseif ( $LASTEXITCODE -eq 1062 ) {
            Write-Warning "The service $Driver has not been started."
            Write-Host ""
        }
        elseif ( $LASTEXITCODE -eq 10611 ) {
            Write-Warning "The service cannot accept control messages at this time"
            Write-Host ""
        }
        else {
            Write-Warning "Unknown Error: $LASTEXITCODE"
            Write-Host ""
        }

        # Attempt to Delete the Cylance Driver
        Write-Host "Attempting to delete $Driver"
        & sc.exe delete $Driver | out-null
        #TODO: See why we get a 0 code when we cant stop or delete the Driver. to repro, don't use ForceStop.exe
        if ( $LASTEXITCODE -eq 0 ) {
            Write-Host "$Driver was deleted successfully."
            Write-Host ""
        }
        elseif ( $LASTEXITCODE -eq 5 ) {
            Write-Warning "Access Denied! Please reboot the endpoint and re-run the script."
            Write-Host ""
        }
        elseif ( $LASTEXITCODE -eq 1072 ) {
            Write-Warning "Service is marked for deletion and will be removed during the next reboot."
            Write-Host ""
        }
        elseif ( $LASTEXITCODE -eq 1060 ) {
            Write-Host "The specified service $Driver does not exist as an installed service."
            Write-Host ""
        }
        elseif ( $LASTEXITCODE -eq 1062 ) {
            Write-Warning "The service $Driver has not been started."
            Write-Host ""
        }
        elseif ( $LASTEXITCODE -eq 10611 ) {
            Write-Warning "The service cannot accept control messages at this time"
            Write-Host ""
        }
        else {
            Write-Warning "Unknown Error: $LASTEXITCODE"
            Write-Host ""
        }
        Write-Host ""

        # Output the current filters

        Write-Host "Listing Driver filters"
        try {
            & fltmc filters
        }
        catch {
            Write-Host "Error"
            Write-Information "$_";
        }
        Write-Host ""

        # Output the Cyalnce Dll's
        Write-Host "Listing Programs with injected Cylance Dll files"
        & tasklist.exe /M Cy*
        if ( $LASTEXITCODE -ne 0 ) {
            Write-Warning "Unknown Error: $LASTEXITCODE"
            Write-Host ""
        }
        Write-Host ""

        #sc qc CylanceDRV> dump to logs
        Write-Host "Query the configuration information for Driver"
        & sc.exe qc $Driver
        if ( $LASTEXITCODE -eq 0 ) {
        }
        elseif ( $LASTEXITCODE -eq 1060 ) {
            Write-Host "The specified service $Driver does not exist as an installed service."
            Write-Host ""
        }
        else {
            Write-Warning "Unknown Error: $LASTEXITCODE"
            Write-Host ""
        }

        #sc query CylanceDRV> dump to logs
        Write-Host ""
        Write-Host "Query the status for $Driver"
        & sc.exe query $Driver
        if ( $LASTEXITCODE -eq 0 ) {
        }
        elseif ( $LASTEXITCODE -eq 1060 ) {
            Write-Host "The specified service $Driver does not exist as an installed service."
            Write-Host ""
        }
        else {
            Write-Warning "Unknown Error: $LASTEXITCODE"
            Write-Host ""
        }
    }
}

function Restart-Check {
    Write-Host ""
    $Procces = ""
    $Proccess = ""
    $Proccess = @(
        'CylanceSvc' # Cylance Protect 2.1+
        , 'CylanceUI' # Cylance Protect 2.1+
        , 'CyOptics' # Optics 2.5+
        #, 'CyUpdate' # Cylance Protect Updater
    )

    foreach ($Procces in $Proccess) {

        if ((get-process "$Procces" -ea SilentlyContinue) -eq $Null) {
            Write-Host ""
        }
        else {
            Write-Host "$Procces Is still running."
            $global:RestartRequired++
        }

    }
}

function Cleanup {
    #Cleanup the output folder
    if (Test-Path -Path "$global:dirPath\*.reg" -PathType Leaf) {
        if (!(Test-Path -Path $global:RegBackupFolder)) {
            New-Item $global:RegBackupFolder -ItemType Directory -Force
            Move-Item -Path $global:dirPath\*.reg $global:RegBackupFolder
        }
        else {
            Move-Item -Path $global:dirPath\*.reg $global:RegBackupFolder
        }
    }

}

function Main {
    Check-Permissions # call Check-Permissions
    Check_DisableRegistryTools # call Check_DisableRegistryTools GPO
    variables # Call the variables
    PartialCleanupBackup # call the PartialCleanup function for ProgramData
    GetProtectVersion # Get the version of protect in variables
    Backup-Files-n-Folders # backup any db, status.json files before add/remove
    Stop-CylanceSVC # Service should already be stopped but checking incase.
    Stop-CyOptics # Service should already be stopped but checking incase.
    modify-Self-Protection-Desktop # Set local Admin
    modify-Self-Protection-Optics # Set local Admin
    if ($global:Protect3 -eq 0) {
        Write-Host ""
        Write-Host "Executing Deregistration"
        modify-LastStateRestorePoint-InstallToken # Delete lastStateRestorePoint and Install Token
        Pre-DeRegistration # Removes all keys needed to deregister and apply base policy
        Stop-CylanceSVC # Service should already be stopped but checking incase.
        Stop-CyOptics # Service should already be stopped but checking incase.
        Start-CylanceSVC # This will add back some missing keys from Pre-DeRegistration.
        Start-CyOptics # Service should already be stopped but checking incase.
        Stop-CylanceSVC # Service should already be stopped but checking incase.
        Stop-CyOptics  # Service should already be stopped but checking incase.
    } else {
        #modify-LastStateRestorePoint-InstallToken # Delete lastStateRestorePoint and Install Token
        #Pre-DeRegistration # Removes all keys needed to deregister and apply base policy
        Stop-CylanceSVC # Service should already be stopped but checking incase.
        Stop-CyOptics # Service should already be stopped but checking incase.
        #Start-CylanceSVC # This will add back some missing keys from Pre-DeRegistration.
        #Start-CyOptics # Service should already be stopped but checking incase.
        Stop-CylanceSVC # Service should already be stopped but checking incase.
        Stop-CyOptics  # Service should already be stopped but checking incase.
    }
    # TODO C:\Windows\System32\drivers\CyDevFltV264.sys - ?
    Try_Add/Remove # Attempts uninstall using Add/Remove programs msiexec
    Unload-DLLs # REGSVR32 /U on all Dlls (the uninstaller does not unregister these files so they stay in tasklist /M Cy* until reboot)
    SC-Stop_Delete-CylanceDrv #(This is not needed when msiexec is run however, we need to have a backup plan)
    modify-Self-Protection-Desktop # We need to ensure that Self Protection is enabled and set to Local Admin
    modify-Self-Protection-Optics # We need to ensure that Self Protection is enabled and set to Local Admin
    modify-LastStateRestorePoint-InstallToken # We need to ensure that LastStateRestorePoint/InstallToken is deleted
    modify-Services # We need to ensure that all existing services for Cylance are set to Disabled
    Stop-Delete-Services # We need to attempt to stop and delete the services
    Backup_Reg_Keys # Do a backup on any reg keys that will be deleted
    Search_Reg_CyDevFlt # Remove CyDevFlt entries from Registry
    Search_Reg_CyDevFltV2 # Remove CyDevFltV2 entries from Registry
    Take-Ownership-Permission-Individual-Files # Take ownership and permissions on Individual system32 Files
    Take-Ownership-Permission-Folder-Files # Take ownership and permissions on folders and sub-files
    Delete-Files-n-Folders #Delete files and folders
    PartialCleanupRestore # call the PartialCleanupRestore function for ProgramData
    ReEnable-Windows-Defender # Re-enable Windows Defender if its still marked disabled
    Restart-Check # One Last Check to see if a restart is needed
    Cleanup # Cleanup the exported log folder
    Write-Host "Script Finished. Starting reboot check."
    Write-Host ""
    Write-Host ""

    If ($global:RestartWarning -gt '0') {
        if ($global:RestartRequired -gt '0') {
            Write-Warning "Script Finished but services are still running. A restart and re-run of the script is required"
            try { Stop-Transcript } catch {} # Stop logging here
            If ($Pause -eq "No") {
                exit 1
            }
            else {
                pause
            }
        }
        else {
            Write-Warning "Script Finished. A restart and re-run the script may be required!"
            try { Stop-Transcript } catch {} # Stop logging here
            If ($Pause -eq "No") {
                exit 1
            }
            else {
                pause
            }
        }
    }
    elseif ($global:ElamRestart -gt '0') {
        Write-Warning "Script Finished. A restart is required prior to reinstallation of Protect!"
        try { Stop-Transcript } catch {} # Stop logging here
        If ($Pause -eq "No") {
            exit 1
        }
        else {
            pause
        }
    }
    elseif ($global:RestartRequired -gt '0') {
        Write-Warning "Script Finished but services are still running. A restart and re-run of the script is required"
        try { Stop-Transcript } catch {} # Stop logging here
        If ($Pause -eq "No") {
            exit 1
        }
        else {
            pause
        }
    }
    try { Stop-Transcript } catch {} # Stop logging here
    Write-Host ""
    Write-Host ""
    exit 0
}

    #DUBUG Remove this from released versions of the script
    # This cant be in a function or .Path does not work
    if ($global:safemode -eq "No") {
        $mypath = ""
        $mypath = $MyInvocation.MyCommand.Path
        $mypath = Split-Path $mypath -Parent
        $mypath = $mypath + "\ProtectShutdownApp.exe"

        if(Test-Path "$mypath" -PathType Leaf) {
            Write-Host "Trace - Stopping Cylance Service"
            Start-Process -NoNewWindow -Wait -ErrorAction Stop -FilePath $mypath
            Start-Sleep -Seconds 20
        } elseif (Test-Path ".\ProtectShutdownApp.exe" -PathType Leaf ){
            Write-Host "Trace - Stopping Cylance Service"
            Start-Process -NoNewWindow -Wait -ErrorAction Stop -FilePath $mypath
            Start-Sleep -Seconds 20
        }
    }

Main


# SIG # Begin signature block
# MIIpBwYJKoZIhvcNAQcCoIIo+DCCKPQCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUybY89DSD9/poeRN7uVNsvrEJ
# rpyggg4ZMIIGsDCCBJigAwIBAgIQCK1AsmDSnEyfXs2pvZOu2TANBgkqhkiG9w0B
# AQwFADBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVk
# IFJvb3QgRzQwHhcNMjEwNDI5MDAwMDAwWhcNMzYwNDI4MjM1OTU5WjBpMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lD
# ZXJ0IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEg
# Q0ExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA1bQvQtAorXi3XdU5
# WRuxiEL1M4zrPYGXcMW7xIUmMJ+kjmjYXPXrNCQH4UtP03hD9BfXHtr50tVnGlJP
# DqFX/IiZwZHMgQM+TXAkZLON4gh9NH1MgFcSa0OamfLFOx/y78tHWhOmTLMBICXz
# ENOLsvsI8IrgnQnAZaf6mIBJNYc9URnokCF4RS6hnyzhGMIazMXuk0lwQjKP+8bq
# HPNlaJGiTUyCEUhSaN4QvRRXXegYE2XFf7JPhSxIpFaENdb5LpyqABXRN/4aBpTC
# fMjqGzLmysL0p6MDDnSlrzm2q2AS4+jWufcx4dyt5Big2MEjR0ezoQ9uo6ttmAaD
# G7dqZy3SvUQakhCBj7A7CdfHmzJawv9qYFSLScGT7eG0XOBv6yb5jNWy+TgQ5urO
# kfW+0/tvk2E0XLyTRSiDNipmKF+wc86LJiUGsoPUXPYVGUztYuBeM/Lo6OwKp7AD
# K5GyNnm+960IHnWmZcy740hQ83eRGv7bUKJGyGFYmPV8AhY8gyitOYbs1LcNU9D4
# R+Z1MI3sMJN2FKZbS110YU0/EpF23r9Yy3IQKUHw1cVtJnZoEUETWJrcJisB9IlN
# Wdt4z4FKPkBHX8mBUHOFECMhWWCKZFTBzCEa6DgZfGYczXg4RTCZT/9jT0y7qg0I
# U0F8WD1Hs/q27IwyCQLMbDwMVhECAwEAAaOCAVkwggFVMBIGA1UdEwEB/wQIMAYB
# Af8CAQAwHQYDVR0OBBYEFGg34Ou2O/hfEYb7/mF7CIhl9E5CMB8GA1UdIwQYMBaA
# FOzX44LScV1kTN8uZz/nupiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAK
# BggrBgEFBQcDAzB3BggrBgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9v
# Y3NwLmRpZ2ljZXJ0LmNvbTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4
# oDagNIYyaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJv
# b3RHNC5jcmwwHAYDVR0gBBUwEzAHBgVngQwBAzAIBgZngQwBBAEwDQYJKoZIhvcN
# AQEMBQADggIBADojRD2NCHbuj7w6mdNW4AIapfhINPMstuZ0ZveUcrEAyq9sMCcT
# Ep6QRJ9L/Z6jfCbVN7w6XUhtldU/SfQnuxaBRVD9nL22heB2fjdxyyL3WqqQz/WT
# auPrINHVUHmImoqKwba9oUgYftzYgBoRGRjNYZmBVvbJ43bnxOQbX0P4PpT/djk9
# ntSZz0rdKOtfJqGVWEjVGv7XJz/9kNF2ht0csGBc8w2o7uCJob054ThO2m67Np37
# 5SFTWsPK6Wrxoj7bQ7gzyE84FJKZ9d3OVG3ZXQIUH0AzfAPilbLCIXVzUstG2MQ0
# HKKlS43Nb3Y3LIU/Gs4m6Ri+kAewQ3+ViCCCcPDMyu/9KTVcH4k4Vfc3iosJocsL
# 6TEa/y4ZXDlx4b6cpwoG1iZnt5LmTl/eeqxJzy6kdJKt2zyknIYf48FWGysj/4+1
# 6oh7cGvmoLr9Oj9FpsToFpFSi0HASIRLlk2rREDjjfAVKM7t8RhWByovEMQMCGQ8
# M4+uKIw8y4+ICw2/O/TOHnuO77Xry7fwdxPm5yg/rBKupS8ibEH5glwVZsxsDsrF
# hsP2JjMMB0ug0wcCampAMEhLNKhRILutG4UI4lkNbcoFUCvqShyepf2gpx8GdOfy
# 1lKQ/a+FSCH5Vzu0nAPthkX0tGFuv2jiJmCG6sivqf6UHedjGzqGVnhOMIIHYTCC
# BUmgAwIBAgIQAdu5Fyxj14eWxAf6BPuYvjANBgkqhkiG9w0BAQsFADBpMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lD
# ZXJ0IFRydXN0ZWQgRzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEg
# Q0ExMB4XDTIzMDExMjAwMDAwMFoXDTI0MDExMjIzNTk1OVowZjELMAkGA1UEBhMC
# VVMxEzARBgNVBAgTCkNhbGlmb3JuaWExEjAQBgNVBAcTCVNhbiBSYW1vbjEWMBQG
# A1UEChMNQ3lsYW5jZSwgSW5jLjEWMBQGA1UEAxMNQ3lsYW5jZSwgSW5jLjCCAiIw
# DQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALf+rNtTW3vZc2t+75W/aRwMUhaj
# eD1UvEFK00guRTUn2uoiHdDzPJLQENzRECNf/NeEaNYZqCM9HHfARWgqzQcmiq1H
# Os/1TKb+JKieQTqBJe8RXT7qo3bWPEhdeSRxVhIVg6+oGO7CvN+Dsm/afCH9Wu7I
# GJLrt+yFbRqyfWhFqOCgaAAEE0wqIRi+VZQEI+ktT1sKAN3mGKwOdJ6CJxDX23S2
# AnENiOMYOyHn+cB0xoPZ987knbNhU6dggriwOSRzPEil5u7b0hhUEKkl+Hrg8hXU
# eCgf4vQgHD1gLJ54Z7WNM/va9Pix3nhk3sq5uOYkW/VwTALNnW5IVjE0zQ8KL26i
# Kph2W8/wQNvFo7VlmrThxj1+qqtspxamUXXWTMuDjllUtNoAJDYX4VcprAuVS21W
# 9Dzu77mb+Io2Ff0ZyYQJ02h8yDAYUOhW1ryNVs6wgZzZgQJIDNmweNiDL05F7AiH
# vAbcHKCJKaSlyNgyexaLsLQpwnbADOXnFyV1Sly1lLPmxbMwq6UaECpSDL1XCF9X
# tqV06FhA0QtfuOpVb69Z8uvsZKcpNvKmvTdxTzKXkVh3Epx6nJxK9JZlySgbzQ1t
# iZVI2/rECqRYIcwb2+Qp3BQ3Dlpto8UfGdWc1u04l9QbxJQTCbWTCdmu3pZ8Ob6Y
# 6egN7juODbqc/d61AgMBAAGjggIGMIICAjAfBgNVHSMEGDAWgBRoN+Drtjv4XxGG
# +/5hewiIZfROQjAdBgNVHQ4EFgQU6YeLFCWhSmqpRhJ7rHkybWo3AKIwDgYDVR0P
# AQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMIG1BgNVHR8Ega0wgaowU6BR
# oE+GTWh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRHNENv
# ZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3JsMFOgUaBPhk1odHRwOi8v
# Y3JsNC5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVzdGVkRzRDb2RlU2lnbmluZ1JT
# QTQwOTZTSEEzODQyMDIxQ0ExLmNybDA+BgNVHSAENzA1MDMGBmeBDAEEATApMCcG
# CCsGAQUFBwIBFhtodHRwOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwgZQGCCsGAQUF
# BwEBBIGHMIGEMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20w
# XAYIKwYBBQUHMAKGUGh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2Vy
# dFRydXN0ZWRHNENvZGVTaWduaW5nUlNBNDA5NlNIQTM4NDIwMjFDQTEuY3J0MAwG
# A1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBABhxHTpw2pUALcx1kV+DwUSh
# hoQSYC7B4jleGrTEAaKDZ2Y6Pz3FGT1bcghxh6mwZbzME0NqicZlqoYKmV6NkQRJ
# BeB5NNsDz+0JOYSUkISDcV7IZ7HcBJ9Pc7l5uMBC9M/EbtoowrIqXl7ascdYCA7w
# IVeuY8icTsU1z5SBw9CGZoSfTiB2ID2Q1E4LU2K6TDHzDGFVhDWkvkleji81RKFD
# Ic6T+dpBC9R+5ew3Ayq53IX4n84YUSGEucXCKa9R2nOZxNUEGFh/sd9+gyb/El/I
# DyVDesDSYVgyCu3UV5REtV8ektoeEwO5X0xlJkk6PwH890BlK4uLNJgj89R/YUpx
# lnKRJBZaSnBq6Q/P841vdEHUXxbyXIcQAmfFUVyoalY5PFfe3LWSzo1Vf5uiSjfj
# opIIlzHwNp5jK6UVo2T3Vg73UUQ52XPWz1kGKb3Uj77VzS0GuTMcD+IfmNnldItA
# UnoK6IQInWO+SPBUwiz53dp31mkiPvXqWBt/oXUOkfJExZFsOMws/6i4EINcAGOl
# JQhovmhI+H/A16I2/eN2/3j9/i5bQZZJhHijGnh+1l+X+9rBvmW/r03pjgLPhKQQ
# xEAxoFfWlRZDP0xtD6Ru8OiidLAuA1VtQbE35uF9BWAMTcm6iwLV8+kSuezsCuPU
# nSJUicLpm38j3wgajX0wMYIaWDCCGlQCAQEwfTBpMQswCQYDVQQGEwJVUzEXMBUG
# A1UEChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQg
# RzQgQ29kZSBTaWduaW5nIFJTQTQwOTYgU0hBMzg0IDIwMjEgQ0ExAhAB27kXLGPX
# h5bEB/oE+5i+MAkGBSsOAwIaBQCgcDAQBgorBgEEAYI3AgEMMQIwADAZBgkqhkiG
# 9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIB
# FTAjBgkqhkiG9w0BCQQxFgQUhldI3AbhVsl6c/1qMe9K/KlZt2MwDQYJKoZIhvcN
# AQEBBQAEggIASsbH478+N2B1MqYE/KTQGaWBW3wVs6NuvXEP43fu+jDtwZFMl7Pa
# JWlUz5Z7vlX4J8LtOfljxPA9PjSGMYZKZ//NDtFviQ+mPCeCp9Xny5hs20vZIhmU
# g34n0jzub6zPcxZ7QNSeRFhwMqdyl1GICsHUt+Ls6hvvawZBhaiqovQchPUnED22
# y7lUgQi0uxKZdHl05sMm48bIR/FockNF4zbcl8m8yqHJELEk87iluOJKlLC+/jwI
# wOOl1pRtKjH2IJEy+Ht7hqY5bIQb+d4BRoC+1uREWvnMSLh1CggqLZ3GxKCXzquS
# GK9PWqJd2CKIT3zzf17SZ3zr/D/IgVL9FkM2VTlRdqaNrwX2mZZUKfpuYtW4YOxu
# vim8+ieB3l+ylr5Zw2qnWR4PriKQkwnae2DLqTu7ykDz3ZDzeFwM1m/0ju+NGpwd
# rpryzOG6TV4IOVPbQiLJq2biYQ/aaBbsAmyqb4E2iS5nnrBw0Sd0U1+zjTCHfB0l
# Cpqe5PAtf4H33xSYJ/91+M1fcAwg9kCUKk2PQ16nElMa110qdEIeOrQW6fDxO9gU
# C07lh0htOmxpfVBEgJh6wkSNdlhiqNbk9RwqUfTv/nTxlaOFmrrrSTG5pgF9OwHR
# 3vNSmARC6eA0ZbVeY1aL3IoNu38obZnXMnJYh1XoOXubpcGJZmY3hLGhghc+MIIX
# OgYKKwYBBAGCNwMDATGCFyowghcmBgkqhkiG9w0BBwKgghcXMIIXEwIBAzEPMA0G
# CWCGSAFlAwQCAQUAMHgGCyqGSIb3DQEJEAEEoGkEZzBlAgEBBglghkgBhv1sBwEw
# MTANBglghkgBZQMEAgEFAAQgeuvO4IvU0VtXh4rzc5KD6BQz5D7VI+XpbfzqIE6i
# dDgCEQD/rVDjengZ5ltALcPV0L6vGA8yMDIzMDQyNzEzMzYyMFqgghMHMIIGwDCC
# BKigAwIBAgIQDE1pckuU+jwqSj0pB4A9WjANBgkqhkiG9w0BAQsFADBjMQswCQYD
# VQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xOzA5BgNVBAMTMkRpZ2lD
# ZXJ0IFRydXN0ZWQgRzQgUlNBNDA5NiBTSEEyNTYgVGltZVN0YW1waW5nIENBMB4X
# DTIyMDkyMTAwMDAwMFoXDTMzMTEyMTIzNTk1OVowRjELMAkGA1UEBhMCVVMxETAP
# BgNVBAoTCERpZ2lDZXJ0MSQwIgYDVQQDExtEaWdpQ2VydCBUaW1lc3RhbXAgMjAy
# MiAtIDIwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQDP7KUmOsap8mu7
# jcENmtuh6BSFdDMaJqzQHFUeHjZtvJJVDGH0nQl3PRWWCC9rZKT9BoMW15GSOBwx
# Apb7crGXOlWvM+xhiummKNuQY1y9iVPgOi2Mh0KuJqTku3h4uXoW4VbGwLpkU7sq
# FudQSLuIaQyIxvG+4C99O7HKU41Agx7ny3JJKB5MgB6FVueF7fJhvKo6B332q27l
# Zt3iXPUv7Y3UTZWEaOOAy2p50dIQkUYp6z4m8rSMzUy5Zsi7qlA4DeWMlF0ZWr/1
# e0BubxaompyVR4aFeT4MXmaMGgokvpyq0py2909ueMQoP6McD1AGN7oI2TWmtR7a
# eFgdOej4TJEQln5N4d3CraV++C0bH+wrRhijGfY59/XBT3EuiQMRoku7mL/6T+R7
# Nu8GRORV/zbq5Xwx5/PCUsTmFntafqUlc9vAapkhLWPlWfVNL5AfJ7fSqxTlOGaH
# UQhr+1NDOdBk+lbP4PQK5hRtZHi7mP2Uw3Mh8y/CLiDXgazT8QfU4b3ZXUtuMZQp
# i+ZBpGWUwFjl5S4pkKa3YWT62SBsGFFguqaBDwklU/G/O+mrBw5qBzliGcnWhX8T
# 2Y15z2LF7OF7ucxnEweawXjtxojIsG4yeccLWYONxu71LHx7jstkifGxxLjnU15f
# VdJ9GSlZA076XepFcxyEftfO4tQ6dwIDAQABo4IBizCCAYcwDgYDVR0PAQH/BAQD
# AgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwIAYDVR0g
# BBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMB8GA1UdIwQYMBaAFLoW2W1NhS9z
# KXaaL3WMaiCPnshvMB0GA1UdDgQWBBRiit7QYfyPMRTtlwvNPSqUFN9SnDBaBgNV
# HR8EUzBRME+gTaBLhklodHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRU
# cnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3JsMIGQBggrBgEF
# BQcBAQSBgzCBgDAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29t
# MFgGCCsGAQUFBzAChkxodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNl
# cnRUcnVzdGVkRzRSU0E0MDk2U0hBMjU2VGltZVN0YW1waW5nQ0EuY3J0MA0GCSqG
# SIb3DQEBCwUAA4ICAQBVqioa80bzeFc3MPx140/WhSPx/PmVOZsl5vdyipjDd9Rk
# /BX7NsJJUSx4iGNVCUY5APxp1MqbKfujP8DJAJsTHbCYidx48s18hc1Tna9i4mFm
# oxQqRYdKmEIrUPwbtZ4IMAn65C3XCYl5+QnmiM59G7hqopvBU2AJ6KO4ndetHxy4
# 7JhB8PYOgPvk/9+dEKfrALpfSo8aOlK06r8JSRU1NlmaD1TSsht/fl4JrXZUinRt
# ytIFZyt26/+YsiaVOBmIRBTlClmia+ciPkQh0j8cwJvtfEiy2JIMkU88ZpSvXQJT
# 657inuTTH4YBZJwAwuladHUNPeF5iL8cAZfJGSOA1zZaX5YWsWMMxkZAO85dNdRZ
# PkOaGK7DycvD+5sTX2q1x+DzBcNZ3ydiK95ByVO5/zQQZ/YmMph7/lxClIGUgp2s
# CovGSxVK05iQRWAzgOAj3vgDpPZFR+XOuANCR+hBNnF3rf2i6Jd0Ti7aHh2MWsge
# mtXC8MYiqE+bvdgcmlHEL5r2X6cnl7qWLoVXwGDneFZ/au/ClZpLEQLIgpzJGgV8
# unG1TnqZbPTontRamMifv427GFxD9dAq6OJi7ngE273R+1sKqHB+8JeEeOMIA11H
# LGOoJTiXAdI/Otrl5fbmm9x+LMz/F0xNAKLY1gEOuIvu5uByVYksJxlh9ncBjDCC
# Bq4wggSWoAMCAQICEAc2N7ckVHzYR6z9KGYqXlswDQYJKoZIhvcNAQELBQAwYjEL
# MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3
# LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgVHJ1c3RlZCBSb290IEc0
# MB4XDTIyMDMyMzAwMDAwMFoXDTM3MDMyMjIzNTk1OVowYzELMAkGA1UEBhMCVVMx
# FzAVBgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMTswOQYDVQQDEzJEaWdpQ2VydCBUcnVz
# dGVkIEc0IFJTQTQwOTYgU0hBMjU2IFRpbWVTdGFtcGluZyBDQTCCAiIwDQYJKoZI
# hvcNAQEBBQADggIPADCCAgoCggIBAMaGNQZJs8E9cklRVcclA8TykTepl1Gh1tKD
# 0Z5Mom2gsMyD+Vr2EaFEFUJfpIjzaPp985yJC3+dH54PMx9QEwsmc5Zt+FeoAn39
# Q7SE2hHxc7Gz7iuAhIoiGN/r2j3EF3+rGSs+QtxnjupRPfDWVtTnKC3r07G1decf
# BmWNlCnT2exp39mQh0YAe9tEQYncfGpXevA3eZ9drMvohGS0UvJ2R/dhgxndX7RU
# CyFobjchu0CsX7LeSn3O9TkSZ+8OpWNs5KbFHc02DVzV5huowWR0QKfAcsW6Th+x
# tVhNef7Xj3OTrCw54qVI1vCwMROpVymWJy71h6aPTnYVVSZwmCZ/oBpHIEPjQ2OA
# e3VuJyWQmDo4EbP29p7mO1vsgd4iFNmCKseSv6De4z6ic/rnH1pslPJSlRErWHRA
# KKtzQ87fSqEcazjFKfPKqpZzQmiftkaznTqj1QPgv/CiPMpC3BhIfxQ0z9JMq++b
# Pf4OuGQq+nUoJEHtQr8FnGZJUlD0UfM2SU2LINIsVzV5K6jzRWC8I41Y99xh3pP+
# OcD5sjClTNfpmEpYPtMDiP6zj9NeS3YSUZPJjAw7W4oiqMEmCPkUEBIDfV8ju2Tj
# Y+Cm4T72wnSyPx4JduyrXUZ14mCjWAkBKAAOhFTuzuldyF4wEr1GnrXTdrnSDmuZ
# DNIztM2xAgMBAAGjggFdMIIBWTASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQW
# BBS6FtltTYUvcyl2mi91jGogj57IbzAfBgNVHSMEGDAWgBTs1+OC0nFdZEzfLmc/
# 57qYrhwPTzAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwgwdwYI
# KwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5j
# b20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdp
# Q2VydFRydXN0ZWRSb290RzQuY3J0MEMGA1UdHwQ8MDowOKA2oDSGMmh0dHA6Ly9j
# cmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFRydXN0ZWRSb290RzQuY3JsMCAGA1Ud
# IAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEA
# fVmOwJO2b5ipRCIBfmbW2CFC4bAYLhBNE88wU86/GPvHUF3iSyn7cIoNqilp/GnB
# zx0H6T5gyNgL5Vxb122H+oQgJTQxZ822EpZvxFBMYh0MCIKoFr2pVs8Vc40BIiXO
# lWk/R3f7cnQU1/+rT4osequFzUNf7WC2qk+RZp4snuCKrOX9jLxkJodskr2dfNBw
# CnzvqLx1T7pa96kQsl3p/yhUifDVinF2ZdrM8HKjI/rAJ4JErpknG6skHibBt94q
# 6/aesXmZgaNWhqsKRcnfxI2g55j7+6adcq/Ex8HBanHZxhOACcS2n82HhyS7T6NJ
# uXdmkfFynOlLAlKnN36TU6w7HQhJD5TNOXrd/yVjmScsPT9rp/Fmw0HNT7ZAmyEh
# QNC3EyTN3B14OuSereU0cZLXJmvkOHOrpgFPvT87eK1MrfvElXvtCl8zOYdBeHo4
# 6Zzh3SP9HSjTx/no8Zhf+yvYfvJGnXUsHicsJttvFXseGYs2uJPU5vIXmVnKcPA3
# v5gA3yAWTyf7YGcWoWa63VXAOimGsJigK+2VQbc61RWYMbRiCQ8KvYHZE/6/pNHz
# V9m8BPqC3jLfBInwAM1dwvnQI38AC+R2AibZ8GV2QqYphwlHK+Z/GqSFD/yYlvZV
# VCsfgPrA8g4r5db7qS9EFUrnEw4d2zc4GqEr9u3WfPwwggWNMIIEdaADAgECAhAO
# mxiO+dAt5+/bUOIIQBhaMA0GCSqGSIb3DQEBDAUAMGUxCzAJBgNVBAYTAlVTMRUw
# EwYDVQQKEwxEaWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20x
# JDAiBgNVBAMTG0RpZ2lDZXJ0IEFzc3VyZWQgSUQgUm9vdCBDQTAeFw0yMjA4MDEw
# MDAwMDBaFw0zMTExMDkyMzU5NTlaMGIxCzAJBgNVBAYTAlVTMRUwEwYDVQQKEwxE
# aWdpQ2VydCBJbmMxGTAXBgNVBAsTEHd3dy5kaWdpY2VydC5jb20xITAfBgNVBAMT
# GERpZ2lDZXJ0IFRydXN0ZWQgUm9vdCBHNDCCAiIwDQYJKoZIhvcNAQEBBQADggIP
# ADCCAgoCggIBAL/mkHNo3rvkXUo8MCIwaTPswqclLskhPfKK2FnC4SmnPVirdprN
# rnsbhA3EMB/zG6Q4FutWxpdtHauyefLKEdLkX9YFPFIPUh/GnhWlfr6fqVcWWVVy
# r2iTcMKyunWZanMylNEQRBAu34LzB4TmdDttceItDBvuINXJIB1jKS3O7F5OyJP4
# IWGbNOsFxl7sWxq868nPzaw0QF+xembud8hIqGZXV59UWI4MK7dPpzDZVu7Ke13j
# rclPXuU15zHL2pNe3I6PgNq2kZhAkHnDeMe2scS1ahg4AxCN2NQ3pC4FfYj1gj4Q
# kXCrVYJBMtfbBHMqbpEBfCFM1LyuGwN1XXhm2ToxRJozQL8I11pJpMLmqaBn3aQn
# vKFPObURWBf3JFxGj2T3wWmIdph2PVldQnaHiZdpekjw4KISG2aadMreSx7nDmOu
# 5tTvkpI6nj3cAORFJYm2mkQZK37AlLTSYW3rM9nF30sEAMx9HJXDj/chsrIRt7t/
# 8tWMcCxBYKqxYxhElRp2Yn72gLD76GSmM9GJB+G9t+ZDpBi4pncB4Q+UDCEdslQp
# JYls5Q5SUUd0viastkF13nqsX40/ybzTQRESW+UQUOsxxcpyFiIJ33xMdT9j7CFf
# xCBRa2+xq4aLT8LWRV+dIPyhHsXAj6KxfgommfXkaS+YHS312amyHeUbAgMBAAGj
# ggE6MIIBNjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTs1+OC0nFdZEzfLmc/
# 57qYrhwPTzAfBgNVHSMEGDAWgBRF66Kv9JLLgjEtUYunpyGd823IDzAOBgNVHQ8B
# Af8EBAMCAYYweQYIKwYBBQUHAQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2Nz
# cC5kaWdpY2VydC5jb20wQwYIKwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2lj
# ZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcnQwRQYDVR0fBD4wPDA6
# oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElE
# Um9vdENBLmNybDARBgNVHSAECjAIMAYGBFUdIAAwDQYJKoZIhvcNAQEMBQADggEB
# AHCgv0NcVec4X6CjdBs9thbX979XB72arKGHLOyFXqkauyL4hxppVCLtpIh3bb0a
# FPQTSnovLbc47/T/gLn4offyct4kvFIDyE7QKt76LVbP+fT3rDB6mouyXtTP0UNE
# m0Mh65ZyoUi0mcudT6cGAxN3J0TU53/oWajwvy8LpunyNDzs9wPHh6jSTEAZNUZq
# aVSwuKFWjuyk1T3osdz9HNj0d1pcVIxv76FQPfx2CWiEn2/K2yCNNWAcAgPLILCs
# WKAOQGPFmCLBsln1VWvPJ6tsds5vIy30fnFqI2si/xK4VC0nftg62fC2h5b9W9Fc
# rBjDTZ9ztwGpn1eqXijiuZQxggN2MIIDcgIBATB3MGMxCzAJBgNVBAYTAlVTMRcw
# FQYDVQQKEw5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgVHJ1c3Rl
# ZCBHNCBSU0E0MDk2IFNIQTI1NiBUaW1lU3RhbXBpbmcgQ0ECEAxNaXJLlPo8Kko9
# KQeAPVowDQYJYIZIAWUDBAIBBQCggdEwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJ
# EAEEMBwGCSqGSIb3DQEJBTEPFw0yMzA0MjcxMzM2MjBaMCsGCyqGSIb3DQEJEAIM
# MRwwGjAYMBYEFPOHIk2GM4KSNamUvL2Plun+HHxzMC8GCSqGSIb3DQEJBDEiBCD3
# POAoRgSMvmgHY106HAVyLu8Tfpm5/AuUdFs0RgettzA3BgsqhkiG9w0BCRACLzEo
# MCYwJDAiBCDH9OG+MiiJIKviJjq+GsT8T+Z4HC1k0EyAdVegI7W2+jANBgkqhkiG
# 9w0BAQEFAASCAgAbET8Q0ypJzcXpEPs2QL7hLAMksQUD2L81TNu7x9wC6kDUUXJp
# MuHjEjdlAdepVQ135D8Ht71AymOft1qKCQHsebStovWt+89KYZ+C9ffzpsjiZppc
# gQZl6ns/ivl32bArfe/ZjhmhQ+qaWFMvSACcmnZE32Jtw1yjJuhsa7SaiftDOQBR
# tCbqB7kttIVkuzEa+ULswQgK/aviTiKjbh7N+k0zO5NH+RkNUe67yDtPB52iV4Og
# p4bNBLNiwp3sc0cPT4xCkvxUbqb4dMBI5arTRFVhFZVhTXIRcMRh/RIoGH86jHwh
# 34uKkPU6jZLkuYGRNlFYgJVV6TIpz+zpaTOQyQoXks9NQWG9XUN0lEfDt3C1iR6w
# a9kL03JCl835t4uCSCt4NzfNF+JyxeKxRO4bPVYHQwXsoUf/2D/jgH7aoz5Xbapp
# 7Ki3p6XxgPgeeWJYeeHZQ7KwC7SPzMTXcmeg8x4cGENA67ORJcnlddzPZ4KhDp/d
# k7jxVZFwh1qOprrKmBtuyufeD77/dt+63z/LRn3WvAxTscYMi24RKvI7AJdjKtDv
# ISPht+8QbiJ90ZfDw4OhQ3fdSZwLnprPJaWLmxLUgT9Fdi0SsDdDncpRyDEYCylf
# pM8xgDCShzPL66vF0MalDv4TdVgaZ6DO3X+T//3PIx/UbSTHLh9TXvskAg==
# SIG # End signature block
