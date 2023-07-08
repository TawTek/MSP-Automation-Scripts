param (
    [Parameter(Mandatory=$false)]
    [switch]$DelTeamViewer = $false,
	[Parameter(Mandatory=$false)]
	[switch]$Cleanup,
	[Parameter(Mandatory=$false)]
	[switch]$Uninstall,
	[Parameter(Mandatory=$false)]
	[switch]$ShowError
)
$Info = {
--------------------------------------------------------------------------------------------------------------------------
Ninja Uninstall Script with support for reamoving TeamViewer if '-DelTeamViewer' parameter is used to be deleted:

Usage: 
    > [-Uninstall]
        -Uninstall calls msiexec {ninjaRmmAgent product ID}
    > [-Cleanup]
        -Cleanup removes keys, files, services
    > [-DelTeamViewer]
        -DelTeamViewer deletes TeamViewer

Examples:

NewAgentRemoval.ps1 -Uninstall
disables uninstall prevention and uninstalls using msiexec, does not check if there are any leftovers

NewAgentRemoval.ps1 -Cleanup
removes keys, files, services related to NinjaRMMProduct, does not use amy msiexec, uninstall prevention status is ignored

NewAgentRemoval.ps1  -Uninstall -Cleanup
combines two actions together
order of arguments does not matter, msiexec is called first, cleanup goes second
--------------------------------------------------------------------------------------------------------------------------
}
$ErrorActionPreference = 'SilentlyContinue'

if($ShowError -eq $true) {
    $ErrorActionPreference = 'Continue'
}

Write-Progress -Activity "Running Ninja Removal Script" -PercentComplete 0

#Set-PSDebug -Trace 2

if([system.environment]::Is64BitOperatingSystem)
{
    $ninjaPreSoftKey = 'HKLM:\SOFTWARE\WOW6432Node\NinjaRMM LLC'
    $uninstallKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
    $exetomsiKey = 'HKLM:\SOFTWARE\WOW6432Node\EXEMSI.COM\MSI Wrapper\Installed'
}
else
{
    $ninjaPreSoftKey = 'HKLM:\SOFTWARE\NinjaRMM LLC'
    $uninstallKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    $exetomsiKey = 'HKLM:\SOFTWARE\EXEMSI.COM\MSI Wrapper\Installed'
}

$ninjaSoftKey = Join-Path $ninjaPreSoftKey -ChildPath 'NinjaRMMAgent'

$ninjaDir = [string]::Empty
$ninjaDataDir = Join-Path -Path $env:ProgramData -ChildPath "NinjaRMMAgent"

###################################################################################################
# locating NinjaRMMAgent
###################################################################################################
$ninjaDirRegLocation = $(Get-ItemPropertyValue $ninjaSoftKey -Name Location) 
if($ninjaDirRegLocation)
{
    if(Join-Path -Path $ninjaDirRegLocation -ChildPath "NinjaRMMAgent.exe" | Test-Path)
    {
        #location confirmed from registry location
        $ninjaDir = $ninjaDirRegLocation
    }
}

Write-Progress -Activity "Running Ninja Removal Script" -PercentComplete 10

if(!$ninjaDir)
{
    #attempt to get the path from service
    $ss = Get-WmiObject win32_service -Filter 'Name Like "NinjaRMMAgent"'
    if($ss)
    {
        $ninjaDirService = ($(Get-WmiObject win32_service -Filter 'Name Like "NinjaRMMAgent"').PathName | Split-Path).Replace("`"", "")
        if(Join-Path -Path $ninjaDirService -ChildPath "NinjaRMMAgentPatcher.exe" | Test-Path)
        {
            #location confirmed from service location
            $ninjaDir = $ninjaDirService
        }
    }
}

if($ninjaDir)
{
    $ninjaDir.Replace('/','\')
}

if($Uninstall)
{
    Write-Progress -Activity "Running Ninja Removal Script" -Status "Running Uninstall" -PercentComplete 25
    #there are few measures agent takes to prevent accidental uninstllation
    #disable those measures now
    #it automatically takes care if those measures are already removed
    #it is not possible to check those measures outside of the agent since agent's development comes parralel to this script
    Start "$ninjaDir\NinjaRMMAgent.exe" -disableUninstallPrevention NOUI
    # Executes uninstall.exe in Ninja install directory
    $Arguments = @(
        "/uninstall"
        $(Get-WmiObject -Class win32_product -Filter "Name='NinjaRMMAgent'").IdentifyingNumber
        "/quiet"
        "/log"
        "NinjaRMMAgent_uninstall.log"
        "/L*v"
        "WRAPPED_ARGUMENTS=`"--mode unattended`""
    )
Start-Process -FilePath "msiexec.exe"  -Verb RunAs -Wait -NoNewWindow -WhatIf -ArgumentList $Arguments
Write-Progress -Activity "Running Ninja Removal Script" -Status "Uninstall Completed" -PercentComplete 40
sleep 1
}


if($Cleanup)
{
    Write-Progress -Activity "Running Ninja Removal Script" -Status "Running Cleanup" -PercentComplete 50
    $service=Get-Service "NinjaRMMAgent"
    if($service)
    {
        Stop-Service $service -Force
        & sc.exe DELETE NinjaRMMAgent
        #Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NinjaRMMAgent
    }
    $proxyservice=Get-Process "NinjaRMMProxyProcess64"
    if($proxyservice)
    {
        Stop-Process $proxyservice -Force
    }
    $nmsservice=Get-Service "nmsmanager"
    if($nmsservice)
    {
        Stop-Service $nmsservice -Force
        & sc.exe DELETE nmsmanager
    }
    # Delete Ninja install directory and all contents
    if(Test-Path $ninjaDir)
    {
        & cmd.exe /c rd /s /q $ninjaDir
    }

    if(Test-Path $ninjaDataDir)
    {
        & cmd.exe /c rd /s /q $ninjaDataDir
    }

    #Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\NinjaRMM LLC\NinjaRMMAgent
    Remove-Item -Path  -Recurse -Force

    # Will search registry locations for NinjaRMMAgent value and delete parent key
    # Search $uninstallKey
    $keys = Get-ChildItem $uninstallKey | Get-ItemProperty -name 'DisplayName'
    foreach ($key in $keys) {
        if ($key.'DisplayName' -eq 'NinjaRMMAgent'){
            Remove-Item $key.PSPath -Recurse -Force
            }
    }

    #Search $installerKey
    $keys = Get-ChildItem 'HKLM:\SOFTWARE\Classes\Installer\Products' | Get-ItemProperty -name 'ProductName'
    foreach ($key in $keys) {
        if ($key.'ProductName' -eq 'NinjaRMMAgent'){
            Remove-Item $key.PSPath -Recurse -Force
            }
    }
    # Computer\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\A0313090625DD2B4F824C1EAE0958B08\InstallProperties
    $keys = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products'
    foreach ($key in $keys) {
        $kn = $key.Name -replace 'HKEY_LOCAL_MACHINE' , 'HKLM:'; 
        $k1 = Join-Path $kn -ChildPath 'InstallProperties';
        if( $(Get-ItemProperty -Path $k1 -Name DisplayName).DisplayName -eq 'NinjaRMMAgent')
        {
            $toremove = 
            Get-Item -LiteralPath $kn | Remove-Item -Recurse -Force
        }
    }

    #Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\EXEMSI.COM\MSI Wrapper\Installed\NinjaRMMAgent 5.3.3681
    Get-ChildItem $exetomsiKey | Where-Object -Property Name -CLike '*NinjaRMMAgent*'  | Remove-Item -Recurse -Force

    #HKLM:\SOFTWARE\WOW6432Node\NinjaRMM LLC
    Get-Item -Path $ninjaPreSoftKey | Remove-Item -Recurse -Force

    # agent creates this key by mistake but we delete it here
    Get-Item -Path "HKLM:\SOFTWARE\WOW6432Node\WOW6432Node\NinjaRMM LLC" | Remove-Item -Recurse -Force

Write-Progress -Activity "Running Ninja Removal Script" -Status "Cleanup Completed" -PercentComplete 75
sleep 1
}

if(Get-Item -Path $ninjaPreSoftKey)
{
    echo "Failed to remove NinjaRMMAgent reg keys ", $ninjaPreSoftKey
}

if(Get-Service "NinjaRMMAgent")
{
    echo "Failed to remove NinjaRMMAgent service"
}

if($ninjaDir)
{
    if(Test-Path $ninjaDir)
    {
        echo "Failed to remove NinjaRMMAgent program folder"
        if(Join-Path -Path $ninjaDir -ChildPath "NinjaRMMAgent.exe" | Test-Path)
        {
            echo "Failed to remove NinjaRMMAgent.exe"
        }

        if(Join-Path -Path $ninjaDir -ChildPath "NinjaRMMAgentPatcher.exe" | Test-Path)
        {
            echo "Failed to remove NinjaRMMAgentPatcher.exe"
        }
    }
}

# Uninstall TeamViewer only if -DelTeamViewer parameter specified
if($DelTeamViewer -eq $true){
Write-Progress -Activity "Running Ninja Removal Script" -Status "TeamViewer Removal Starting" -PercentComplete 80
    $tvProcess = Get-Process -Name 'teamviewer*'
    Stop-Process -InputObject $tvProcess -Force # Stops TeamViewer process
# Call uninstaller - 32/64-bit (if exists)
$tv64Uninstaller = Test-Path ${env:ProgramFiles(x86)}"\TeamViewer\uninstall.exe"
if ($tv64Uninstaller) {
    & ${env:ProgramFiles(x86)}"\TeamViewer\uninstall.exe" /S | out-null
}
$tv32Uninstaller = Test-Path ${env:ProgramFiles}"\TeamViewer\uninstall.exe"
if ($tv32Uninstaller) {
    & ${env:ProgramFiles}"\TeamViewer\uninstall.exe" /S | out-null
}
# Ensure all registry keys have been removed - 32/64-bit (if exists)
    Remove-Item -path HKLM:\SOFTWARE\TeamViewer -Recurse
    Remove-Item -path HKLM:\SOFTWARE\WOW6432Node\TeamViewer -Recurse 
    Remove-Item -path HKLM:\SOFTWARE\WOW6432Node\TVInstallTemp -Recurse 
    Remove-Item -path HKLM:\SOFTWARE\TeamViewer -Recurse
    Remove-Item -path HKLM:\SOFTWARE\Wow6432Node\TeamViewer -Recurse
Write-Progress -Activity "Running Ninja Removal Script" -Status "TeamViewer Removal Completed" -PercentComplete 90
sleep 1
}

Write-Progress -Activity "Running Ninja Removal Script" -Status "Completed" -PercentComplete 100
sleep 1

$error | out-file C:\Windows\Temp\NinjaRemovalScriptError.txt