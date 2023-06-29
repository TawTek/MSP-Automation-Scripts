#---Variables
$Info = {
*************************************************************************************************************************
*  Synopsis: Inject drivers into boot.wim and create new ISO for UEFI boot
*  Description:

    >

*  Created:
*  Updated:
*  Version:
*************************************************************************************************************************
}
$MountPath = "C:\temp\Mount\"
$BootWim = "c:\temp\iso\sources\boot.wim"
$BootDrivers = "C:\temp\drivers"
$ISOFolder = "c:\temp\iso"
$ISOFile = "windowsiso.iso"
$Oscdimg = "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg"
$a = Test-Path "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg"

###---Writes script informational text to console---###
function Write-Info {
    Write-Host $Info
}

function Test-Path {
    If (-not $a){
        Invoke-Webrequest -uri https://download.microsoft.com/download/6/7/4/674ec7db-7c89-4f2b-8363-689055c2b430/adk/Installers/52be7e8e9164388a9e6c24d01f6f1625.cab -outfile c:\temp\52be7e8e9164388a9e6c24d01f6f1625.cab
        Invoke-Webrequest -uri https://download.microsoft.com/download/6/7/4/674ec7db-7c89-4f2b-8363-689055c2b430/adk/Installers/5d984200acbde182fd99cbfbe9bad133.cab -outfile c:\temp\5d984200acbde182fd99cbfbe9bad133.cab
        Invoke-Webrequest -uri https://download.microsoft.com/download/6/7/4/674ec7db-7c89-4f2b-8363-689055c2b430/adk/Installers/9d2b092478d6cca70d5ac957368c00ba.cab -outfile c:\temp\9d2b092478d6cca70d5ac957368c00ba.cab
        Invoke-Webrequest -uri https://download.microsoft.com/download/6/7/4/674ec7db-7c89-4f2b-8363-689055c2b430/adk/Installers/bbf55224a0290f00676ddc410f004498.cab -outfile c:\temp\bbf55224a0290f00676ddc410f004498.cab
        Invoke-Webrequest -uri "https://download.microsoft.com/download/6/7/4/674ec7db-7c89-4f2b-8363-689055c2b430/adk/Installers/Oscdimg (DesktopEditions)-x86_en-us.msi" -usebasicparsing -outfile "c:\temp\Oscdimg (DesktopEditions)-x86_en-us.msi"
        Start-Process -FilePath "c:\temp\Oscdimg (DesktopEditions)-x86_en-us.msi" /qn
        Copy "c:\program files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg\oscdimg.exe" "oscdimg.exe"
    }
} # Think about extracting MSI file instead of running it

function Add-Drivers {
    Mount-WindowsImage -Path $MountPath -ImagePath $BootWim -Index 1
    Add-WindowsDriver -Path $MountPath -Driver $BootDrivers -Recurse
    Dismount-WindowsImage -Path $MountPath –Save
    Mount-WindowsImage -Path $MountPath -ImagePath $BootWim -Index 2
    Add-WindowsDriver -Path $MountPath -Driver $BootDrivers -Recurse
    Dismount-WindowsImage -Path $MountPath –Save
}

function New-ISO {
    Set-Location -Path $Oscdimg
    Start-Process -FilePath "oscdimg.exe" -m -o -u2 -udfver102 -bootdata:2#p0,e,b$ISOFolder\boot\etfsboot.com#pEF,e,b$ISOFolder\efi\microsoft\boot\efisys.bin $ISOFolder $ISOFolder\$ISOFile
}

Write-Info
Test-Path
Add-Drivers
New-ISO