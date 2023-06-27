#---Variables [General]
$Info = {
*************************************************************************************************************************
*  Synopsis: Deploy Citrix Workspace
*  Description:

    > Checks for temporary directory and if missing, creates one in C:\Temp
    > Checks if the prerequisite .NET 4.8 or greater is installed by checking version in registry, if not, downloads 
      and installs it
    > Downloads and runs app installer with defined arguments
    > Deletes temporary folder after installation is complete

*  Created: 23-06-26
*  Updated: 23-06-27
*  Version: 2.0
*************************************************************************************************************************
}
$VerbosePreference = "Continue"
$TempDirectory = "C:\temp\CitrixWorkspace"
#---Variables [Microsoft .NET Framework 4.8]
$App_NET48 = "Microsoft .NET Framework 4.8"
$Download_NET48 = "https://download.visualstudio.microsoft.com/download/pr/2d6bb6b2-226a-4baa-bdec-798822606ff1/8494001c276a4b96804cde7829c04d7f/ndp48-x86-x64-allos-enu.exe"
$Installer_NET48 = "Microsoft .NET Framework v4.8.exe" 
$TempPath_NET48 = Join-Path -Path $TempDirectory -ChildPath $Installer_NET48
$Arg_NET48 = "/q /norestart"
$NETVersion = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full' -Name Release).Release
#---Variables [Citrix Workspace]
$App_CitrixWorkspace = "Citrix Workspace"
$Download_CitrixWorkspace = "https://downloadplugins.citrix.com/Windows/CitrixWorkspaceApp.exe"
$Installer_CitrixWorkspace = "CitrixWorkspaceApp.exe"
$TempPath_CitrixWorkspace =  Join-Path -Path $TempDirectory -ChildPath $Installer_CitrixWorkspace
$Arg_CitrixWorkspace = "/silent"

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

###---Checks if .NET 4.8 or greater is installed, if not, downloads and installs---###
function Install-NET48 {
    Write-Verbose "Checking if $App_NET48 or later is installed."
    if( $NETVersion -ge "528040") {
        Write-Verbose "$App_NET48 or greater is installed"
    } else {
        Write-Verbose "$App_NET48 or greater is not installed."
        Write-Verbose "Downloading $App_NET48 installer to $TempPath_NET48."
        Invoke-WebRequest -Uri $Download_NET48 -OutFile $TempPath_NET48
        Write-Verbose "$Installer_NET48 has finished downloading."
        Write-Verbose "Installing $App_NET48"
        Start-Process $TempPath_NET48 -ArgumentList $Arg_NET48 -wait
        Write-Verbose "$App_NET48 has been installed."
    }
}

###---Downloads and installs Citrix Workspace---###
function Install-CitrixWorkspace {
    Write-Verbose "Downloading $App_CitrixWorkspace installer to $TempPath_CitrixWorkspace."
    Invoke-WebRequest -Uri $Download_CitrixWorkspace -OutFile $TempPath_CitrixWorkspace
    Write-Verbose "$Installer_CitrixWorkspace has finished downloading."
    Write-Verbose "Installing $App_CitrixWorkspace."
    Start-Process -FilePath $TempPath_CitrixWorkspace -ArgumentList $Arg_CitrixWorkspace -wait
    Write-Verbose "$App_CitrixWorkspace has been installed."
}

###---Removes temporary directory---###
function Remove-TempPath {
    Write-Verbose "Deleting temporary directory folder."
    Remove-Item $TempDirectory -recurse -force
    Write-Verbose "Temporary directory has been deleted."
}

Write-Info
Set-TempPath
Install-NET48
Install-CitrixWorkspace
Remove-TempPath