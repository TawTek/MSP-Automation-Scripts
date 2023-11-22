#---Parameters
param(
    [string] $SetupDownloader=''
)
#---Variables [General]
$Info = {
**********************************************************************************************************
*  SYNOPSIS: Deploy Bitdefender GravityZone
*  DESCRIPTION:

    > Uses parameter string to pass filename with square brackets
    > Checks for temporary directory and if missing, creates one in C:\Temp
    > Adds regkey to disable IE first run setup (prevents downloads if it was never run before)
    > Checks PowerShell version and executes correct cmdlet for downloading app installer
    > Downloads app installer and outputs a temporary filename without square brackets
    > Renames app installer to correct filename using parameter
    > Runs app installer with arguments defined
    > Deletes temporary folder after installation is complete

*  CREATED: 23-06-01 | TawTek
*  UPDATED: 23-07-06 | TawTek
*  VERSION: 4.0

*  CHANGELOG:

    > 23-06-04  Added Test-Path for temp directory
    > 23-06-24  Added if/else for PowerShell version to execute correct cmdlet to download app installer
    > 23-06-26  Added function Confirm-Service to check if BDGZ or S1 service is installed
                Added function Confirm-AppInstall to check if BDGZ service exists after attempted install
    > 23-07-03  Added Test-Path for checking if installer already exists and rearranged functions order
    > 23-07-06  Added function Test-PendingReboot to check if reboot pending before installation
                Added check to see what AntiVirus may already be installed causing BDGZ to fail install
                Fixed installer path check to use -LiteralPath to account for square brackets

* GITHUB: https://github.com/TawTek
**********************************************************************************************************
}
$VerbosePreference = "Continue"
$TempDirectory = "C:\Temp\BDGZ"
$PowerShellVersion = $PSVersionTable.PSVersion
#---Varilables [App Specific]
$App = "Bitdefender GravityZone"
$DownloadApp = "$SetupDownloader"
$TempFileName = "bdgz_temp.exe"
$TempFilePath = Join-Path -Path $TempDirectory -ChildPath $TempFileName
$RenamedFilePath = Join-Path -Path $TempDirectory -ChildPath $SetupDownloader
$ServiceName_BDGZ = “EPProtectedService”
$ServiceName_S1 = "SentinelAgent"
$Arg = "/bdparams /silent"

###---Writes informational text to console---###
function Write-Info {
    Write-Host $Info
}

###---Checks if Bitdefender or S1 service exists---###
function Confirm-Service {
    Write-Verbose "Checking if $ServiceName_BDGZ or $ServiceName_S1 exists."
    if (Get-Service $ServiceName_BDGZ -ErrorAction SilentlyContinue) {
        Write-Verbose "$ServiceName_BDGZ exists, $App is already installed. Terminating script."
        exit
    } elseif (Get-Service $ServiceName_S1 -ErrorAction SilentlyContinue) {
        Write-Verbose "$ServiceName_S1 exists, $App will not be installed. Terminating script."
        exit
    }
    else {
        Write-Verbose "$ServiceName_BDGZ does not exists, continuing script."
    }
}

###---Creates temporary directory---###
function Confirm-TempPath {
    Write-Verbose "Checking if $TempDirectory exists."
    if(Test-Path -Path $TempDirectory) {
        Write-Verbose "$TempDirectory exists."
    } else {
        Write-Verbose "Creating $TempDirectory."
        New-Item -Path $TempDirectory -ItemType "directory"
        Write-Verbose "$TempDirectory created."
    }
}

###---Checks if installer exists---###
function Confirm-Installer {
    Write-Verbose "Checking if $App installer already exists."
    if (Test-Path -LiteralPath $RenamedFilePath) {
        Write-Verbose "$App installer exists, skipping download"
        Write-Verbose "Installing $App."
        Start-Process -FilePath $RenamedFilePath -ArgumentList $Arg -wait
    } else {
        Write-Verbose "$App installer does not exist, continuing to download installer."
        Get-BDGZ
    }
}

###---Downloads and Installs BDGZ---###
function Get-BDGZ {
    Write-Verbose "Downloading $App installer to $TempDirectory."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2
    if($PowerShellVersion -lt "3.0") {
        Import-Module BitsTransfer
        Start-BitsTransfer -Source $DownloadApp -Destination $TempFilePath
        Move-Item -LiteralPath $TempFilePath $RenamedFilePath
    } else {
        [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
        Invoke-WebRequest -Uri $DownloadApp -UseBasicParsing -OutFile $TempFilePath
        Rename-Item -LiteralPath $TempFilePath -NewName $RenamedFilePath
    }
    Write-Verbose "$App has finished downloading."
    Write-Verbose "Installing $App."
    Start-Process -FilePath $RenamedFilePath -ArgumentList $Arg -wait
}

###---Checks if Bitdefender service exists after attempted install---###
function Confirm-AppInstall {
    if (Get-Service $ServiceName_BDGZ -ErrorAction SilentlyContinue) {
        Write-Verbose "$ServiceName_BDGZ exists, $App has been installed."
        Write-Verbose "Deleting temporary directory folder."
        Remove-Item $TempDirectory -recurse -force
        Write-Verbose "Temporary directory has been deleted."
    } else {
        if (Test-PendingReboot) {
            Write-Verbose "Reboot is required before proceeding with installation. Please reboot then run script again."
        } else {
            Write-Verbose "$App has not been installed due to an error. Please attempt manual installation."
            Write-Verbose "The following AntiVirus products may already be installed and need removal first"
            Get-CimInstance -Namespace root/SecurityCenter2 -Classname AntiVirusProduct
        }
    }
}

###---Ancillary function to check for pending reboots---###
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
Confirm-TempPath
Confirm-Installer
Confirm-AppInstall
