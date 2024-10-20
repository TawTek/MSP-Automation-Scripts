#---Variables
$Info = {
**********************************************************************************************************
*  SYNOPSIS: Uninstall Sophos Endpoint Agent
*  DESCRIPTION:

    > Checks if Sophos Endpoint Defence service is running
    > Attempts uninstallation using uninstaller with arguments
    > Checks if uninstallation succeded by checking if service is still running
    > Ancilliary function to check if pending reboot may be preventing removal

*  CREATED: 23-07-06 | TawTek
*  UPDATED: 23-07-06 | TawTek
*  VERSION: 1.0

*  CHANGELOG:

    > 23-07-06  Developed script
**********************************************************************************************************
}
$VerbosePreference = "Continue"
$App = "Sophos Endpoint Agent"
$Uninstaller = "C:\Program Files\Sophos\Sophos Endpoint Agent\SophosUninstall.exe"
$ServiceName_Sophos = "Sophos Endpoint Defense Service"
$Arg = "--quiet"

###---Writes informational text to console---###
function Write-Info {
    Write-Host $Info
}

###---Checks if Sophos service exists---###
function Confirm-Service {
    Write-Verbose "Checking if $ServiceName_Sophos exists."
    if (Get-Service $ServiceName_Sophos -ErrorAction SilentlyContinue) {
        Write-Verbose "$ServiceName_Sophos exists, $App is installed, continuing removal."
    } else {
        Write-Verbose "$ServiceName_Sophos does not exist. $App is not installed. Terminating script."
        exit
    }
}

###---Runs Sophos uninstaller from local Program Files---###
function Remove-Sophos {
    Write-Verbose "Uninstalling $App."
    Start-Process -FilePath $Uninstaller -ArgumentList $Arg -wait
}

###---Checks if Sophos service exists after attempted uninstall---###
function Confirm-Removal {
    if ((Get-Service $ServiceName_Sophos -ErrorAction SilentlyContinue) -and (Test-PendingReboot)) {
            Write-Verbose "$App has not been uninstalled"
            Write-Verbose "Reboot is required before proceeding with removal. Please reboot then run script again."
            } elseif (Get-Service $ServiceName_Sophos -ErrorAction SilentlyContinue) {
                Write-Verbose "$App has not been uninstalled due to an error. Please attempt manual removal."
    } else {
        Write-Verbose "$App has been removed."
        }
}

###---Ancillary function to check for pending reboots if removal fails---###
function Test-PendingReboot {
    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { return $true}
    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { return $true}
    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { return $true}
    try { 
        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()
        if (($status -ne $null) -and $status.RebootPending) {
            return $true
        }
    }
    catch { }
    return $false
}

Write-Info
Confirm-Service
Remove-Sophos
Confirm-Removal