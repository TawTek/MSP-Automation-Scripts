<#----------------------------------------------------------------------------------------------------------
<DEVELOPMENT>
------------------------------------------------------------------------------------------------------------
CREATED: YY-MM-DD | NAME [TITLE]
UPDATED: YY-MM-DD | NAME [TITLE]
VERSION: X.X
------------------------------------------------------------------------------------------------------------
<DESCRIPTION> BRIEF SUMMARY OF WHAT IS BEING INSTALLED
------------------------------------------------------------------------------------------------------------
    > Checks for temporary directory and if missing, creates one in C:\Temp
    > Checks if app installer exists, skips download if so
    > Adds regkey to disable IE first run setup (prevents downloads if it was never run before)
    > Checks PowerShell version and executes correct cmdlet for downloading app installer
    > Runs app installer with arguments defined
    > Deletes temporary directory after app install is verified
------------------------------------------------------------------------------------------------------------
<CHANGELOG>
------------------------------------------------------------------------------------------------------------
    > YY-MM-DD  CHANGES
    > YY-MM-DD  CHANGES
------------------------------------------------------------------------------------------------------------
<GITHUB>
----------------------------------------------------------------------------------------------------------#>

#-Parameters
param(
    [string] $Parameter
)

#-Variables [Global]
$VerbosePreference = "Continue"
$EA_Silent = @{ErrorAction = "SilentlyContinue"}
$EA_Stop = @{ErrorAction = "Stop"}
$TempDir = "C:\Temp\FOLDERNAME"
$PSVer = $PSVersionTable.PSVersion

#-Variables [App]
$App = "APPNAME"
$DownloadURL = "URL"
$Installer = "FILENAME.EXTENSION"
$TempFilePath = Join-Path -Path $TempDir -ChildPath $Installer
$Arg = "MSI/EXE-PARAMETERS"

<#------------------------------------------------------------------------------------------------------------
SCRIPT:FUNCTIONS
------------------------------------------------------------------------------------------------------------#>

##--Creates temporary directory
function Set-TempDir {
    Write-Verbose "Checking if $TempDir exists."
    if (Test-Path -Path $TempDir) {
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

<#
function Test-App {
    OPTIONAL: This is where you would write a function to test if app installed successfully
    This will depend on the app and how you want to test for it
    For example, you can test for an app service that is supposed to run [like an AV does]
    Or you can use Get-Package cmdlet, or check registry for installed programs
    There are many other ways to test as well, so it will depend on your method
}#>

##--Removes temporary directory
function Remove-TempDir {
    Write-Verbose "Deleting temporary directory."
    Remove-Item $TempDir -recurse -force
    Write-Verbose "Temporary directory has been deleted."
}

<#------------------------------------------------------------------------------------------------------------
SCRIPT:EXECUTIONS
------------------------------------------------------------------------------------------------------------#>

Set-TempDir
Get-App
Install-App
#Test-App
Remove-TempDir