#---Parameters
param(
    [string]$Parameter=''
)
#---Variables [General]
$Info = {
*************************************************************************************************************************
*  Synopsis: Template to install application using parameters defined
*  Description:

    > Specify what the parameter should be, and then use that variable wherever you need to pass its value to
    > Checks for temporary directory and if missing, creates one in C:\Temp
    > Adds regkey to disable IE first run setup (prevents downloads if it was never run before)
    > Checks PowerShell version and executes correct cmdlet for downloading app installer
    > Downloads app installer and outputs a temporary filename without square brackets
    > Runs app installer with arguments defined
    > Deletes temporary folder after installation is complete

*  Created:
*  Updated:
*  Version:
*************************************************************************************************************************
}
$VerbosePreference = "Continue"
$TempDirectory = "C:\Temp\"
$PowerShellVersion = $PSVersionTable.PSVersion
#---Varilables [App Specific]
$App = ""
$DownloadApp = "http://www.url.com/"
$TempFilePath = Join-Path -Path $TempDirectory -ChildPath $TempFileName
$Arg = ""

###---Writes script informational text to console---###
function Write-Info {
    Write-Host $Info
}

###---Creates temporary directory---###
function Set-TempPath {
    Write-Verbose "Checking if $TempDirectory exists."
    if( Test-Path -Path $TempDirectory) {
        Write-Verbose "$TempDirectory exists."
    } else {
        Write-Verbose "Creating $TempDirectory."
        New-Item -Path $TempDirectory -ItemType "directory"
        Write-Verbose "$TempDirectory created."
    }
}

###---Downloads and Installs Application---###
function Install-App {
    Write-Verbose "Downloading $App installer to $TempDirectory."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2
    if( $PowerShellVersion -lt "3.0") {
        Import-Module BitsTransfer
        Start-BitsTransfer -Source $DownloadApp -Destination $TempFilePath
    } else {
        [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
        Invoke-WebRequest -Uri $DownloadApp -UseBasicParsing -OutFile $TempFilePath
    }
    Write-Verbose "$App has finished downloading."
    Write-Verbose "Installing $App."
    Start-Process -FilePath $TempFilePath -ArgumentList $Arg -wait
    Write-Verbose "$App has been installed."
}

###---Removes temporary directory---###
function Remove-TempPath {
    Write-Verbose "Deleting temporary directory folder."
    Remove-Item $TempDirectory -recurse -force
    Write-Verbose "Temporary directory has been deleted."
}

Write-Info
Set-TempPath
Install-App
Remove-TempPath