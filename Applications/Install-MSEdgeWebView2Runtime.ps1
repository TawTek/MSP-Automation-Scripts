<#----------------------------------------------------------------------------------------------------------
<DEVELOPMENT>
------------------------------------------------------------------------------------------------------------
CREATED: 23-08-18 | TawTek
UPDATED: 23-08-25 | TawTek
VERSION: 2.0
------------------------------------------------------------------------------------------------------------
<DESCRIPTION> Download and install Microsoft Edge WebView2 Runtime
------------------------------------------------------------------------------------------------------------
    > Checks if app is already installed
    > Checks for temporary directory and if missing, creates one in C:\Temp
    > Checks if app installer already exists
    > Adds regkey to disable IE first run setup (prevents downloads if it was never run before)
    > Checks PowerShell version and executes correct cmdlet for downloading app installer
    > Downloads app installer
    > Runs app installer with arguments defined
    > Checks if App installed, outputs results
    > Deletes temporary folder after installation is complete
------------------------------------------------------------------------------------------------------------
<CHANGELOG>
------------------------------------------------------------------------------------------------------------
    > 23-08-18  Devloped first iteration
    > 23-08-25  Reformatted for standardization
                Changed logic sequence for modularity
------------------------------------------------------------------------------------------------------------
<GITHUB> https://github.com/TawTek/MSP-Automation-Scripts
----------------------------------------------------------------------------------------------------------#>

#-Variables [Global]
$VerbosePreference = "Continue"
$EA_Silent         = @{ErrorAction = "SilentlyContinue"}
$EA_Stop           = @{ErrorAction = "Stop"}
$TempDir           = "C:\Temp\MSEdgeView2"
$PSVer             = $PSVersionTable.PSVersion

#-Variables [App]
$App          = "Microsoft Edge WebView2 Runtime"
$DownloadURL  = "https://msedge.sf.dl.delivery.mp.microsoft.com/filestreamingservice/files/69fd90fb-8382-4294-8f45-b97c88717998/MicrosoftEdgeWebView2RuntimeInstallerX64.exe"
$Installer    = "MicrosoftEdgeWebView2RuntimeInstallerX64.exe"
$TempFilePath = Join-Path -Path $TempDir -ChildPath $Installer
$Arg          = "/silent /install"

<#------------------------------------------------------------------------------------------------------------
SCRIPT:FUNCTIONS
------------------------------------------------------------------------------------------------------------#>

##--Checks if app is already installed
function Test-App {
    if (Get-Package -Name "Microsoft Edge WebView2 Runtime" @EA_Silent) {
        Write-Verbose "$App is already installed and is version $((Get-Package -Name "Microsoft Edge WebView2 Runtime").Version)."
        Write-Verbose "Terminating script."
        exit
    } else {}
}

##--Creates temporary directory
function Set-TempDir {
    Write-Verbose "Checking if $TempDir exists."
    if( Test-Path -Path $TempDir) {
        Write-Verbose "$TempDir exists."
    } else {
        Write-Verbose "Creating $TempDir."
        New-Item -Path $TempDir -ItemType "Directory" > $null
        Write-Verbose "$TempDir created."
    }
}

##--Checks if installer exists, downloads if not
function Get-App {
    Write-Verbose "Checking if $App installer exists."
    if (Test-Path -Path $TempFilePath) {
        Write-Verbose "$App installer exists, skipping download."
    } else {
        Write-Verbose "$App installer does not exist, continuing to download installer."
        Write-Verbose "Downloading $App installer to $TempDir."
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main" -Name "DisableFirstRunCustomize" -Value 2
        if ($PSVer -lt "3.0") {
            Import-Module BitsTransfer
            Start-BitsTransfer -Source $DownloadURL -Destination $TempFilePath @EA_Stop
        } else {
            [Net.ServicePointManager]::SecurityProtocol = "tls12, tls11, tls"
            Invoke-WebRequest -Uri $DownloadURL -UseBasicParsing -OutFile $TempFilePath @EA_Stop
        }
        Write-Verbose "$App has finished downloading."
    }
}

##--Installs app
function Install-App {
    Write-Verbose "Installing $App."
    Start-Process -FilePath $TempFilePath -ArgumentList $Arg -wait
}

##--Checks if app installed
function Test-AppInstall {
    if (Get-Package -Name "Microsoft Edge WebView2 Runtime" @EA_Silent){
        Write-Verbose "$App has been installed."
    } else {
        Write-Verbose "$App has not been installed. Please attempt manual installation."
        exit
    }
}

##--Removes temporary directory
function Remove-TempDir {
    Write-Verbose "Deleting temporary directory."
    Remove-Item $TempDir -recurse -force
    Write-Verbose "Temporary directory has been deleted."
}

<#------------------------------------------------------------------------------------------------------------
SCRIPT:EXECUTIONS
------------------------------------------------------------------------------------------------------------#>

Test-App
Set-TempDir
Get-App
Install-App
Test-AppInstall
Remove-TempDir