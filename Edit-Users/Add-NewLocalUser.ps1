<#----------------------------------------------------------------------------------------------------------
DEVELOPMENT
------------------------------------------------------------------------------------------------------------
    > CREATED: 23-07-22 | TawTek
    > UPDATED: 23-08-18 | TawTek
    > VERSION: 4.0
------------------------------------------------------------------------------------------------------------
SYNOPSIS+DESCRIPTION - Create new local user account
------------------------------------------------------------------------------------------------------------
    > Specify parameters for new user account
    > Checks if user account already exists, terminates script if found
    > Creates new user per specified parameters
    > Adds registry keys to disable OOBE + Privacy Experience (speeds up first login drastically)
    > Checks if local Administrator is disabled, disables if not (if parameter defined)
------------------------------------------------------------------------------------------------------------
CHANGELOG
------------------------------------------------------------------------------------------------------------
    > 23-07-22  Developed first iteration of script
    > 23-08-05  Added check for local Administrator account and disable if active
                Reorganized variables into $NewUserParams to utilize splatting for better organization
                Added PasswordNeverExpires parameter to $NewUserParams
                Segregated script into functions for modularity
    > 23-08-13  Added $AdministratorDisabled parameter as a toggle for running Test-Administrator check
                Rearranged variables for cleaner error output and handling
    > 23-08-18  Added logic for adding regkeys to bypass OOBE + Privacy Experience
                Reformatted comments
------------------------------------------------------------------------------------------------------------
GITHUB - https://github.com/TawTek/MSP-Automation-Scripts
----------------------------------------------------------------------------------------------------------#>

#-Parameters
param(
    [string] $NewUser,
    [string] $Group,
    [string] $Password,
    [string] $OOBEbypass,
    [string] $AdministratorDisabled
)

#-Variables
$VerbosePreference = "Continue"
$EA_Silent         = @{ErrorAction = "SilentlyContinue"}
$EA_Stop           = @{ErrorAction = "Stop"}
$CheckUser         = Get-LocalUser -Name $NewUser @EA_Silent

<#------------------------------------------------------------------------------------------------------------
SCRIPT:FUNCTIONS
------------------------------------------------------------------------------------------------------------#>

function Test-User {
    if ($NewUser -and $Group -and $Password) {
        Write-Verbose "Checking if $NewUser exists."
        if ($CheckUser) {
            Write-Verbose "$NewUser already exists, terminating script."
            exit
        } else {
            Write-Verbose "$NewUser does not exist. Creating user account."
        }
    } else {
        Write-Verbose "All parameters must be defined: enter Username, Group, and Password when executing script."
        exit
    }
}

##--Checks if all parameters are defined and whether $NewUser exists and creates if not
function New-User {
    $NewUserParams = @{
        'AccountNeverExpires'  = $true;
        'Password'             = (ConvertTo-SecureString -AsPlainText -Force $Password);
        'Name'                 = $NewUser;
        'PasswordNeverExpires' = $true
    }
    New-LocalUser @NewUserParams @EA_Stop | Add-LocalGroupMember -Group $Group @EA_Stop
    Write-Verbose "$NewUser account has been created according to defined parameters"
}

##--Modify RegKey to bypass OOBE + Privacy Experience
function Set-RegKey {
    if ($OOBEbypass -eq $True) {
        Write-Verbose "Modifying registry to prevent OOBE and Privacy Expereience upon first login."
        ###---Declare RegKey variables
        $RegKey = @{
            Path         = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Name         = "EnableFirstLogonAnimation"
            Value        = 0
            PropertyType = "DWORD"
        }
        if (-not (Test-Path $RegKey.Path)) {
            Write-Verbose "$($RegKey.Path) does not exist. Creatng path."
            New-Item -Path $RegKey.Path -Force
            Write-Verbose "$($RegKey.Path) path has been created."
        }
        New-ItemProperty @RegKey -Force
        Write-Verbose "Registry key has been added/modified"
        ###---Clear and redeclare RegKey variables
        $RegKey = @{}
        $RegKey = @{
            Path         = "HKLM:\Software\Policies\Microsoft\Windows\OOBE"
            Name         = "DisablePrivacyExperience"
            Value        = 1
            PropertyType = "DWORD"
        }
        if (-not (Test-Path $RegKey.Path)) {
            Write-Verbose "$($RegKey.Path) does not exist. Creatng path."
            New-Item -Path $RegKey.Path -Force
            Write-Verbose "$($RegKey.Path) path has been created."
        }
        New-ItemProperty @RegKey -Force
        Write-Verbose "Registry key has been added/modified"
        ###---Clear and redeclare RegKey variables    
        $RegKey = @{}
        $RegKey = @{
            Path         = "HKCU:\Software\Policies\Microsoft\Windows\OOBE"
            Name         = "DisablePrivacyExperience"
            Value        = 1
            PropertyType = "DWORD"
        }
        if (-not (Test-Path $RegKey.Path)) {
            Write-Verbose "$($RegKey.Path) does not exist. Creatng path."
            New-Item -Path $RegKey.Path -Force
            Write-Verbose "$($RegKey.Path) path has been created."
        }
        New-ItemProperty @RegKey -Force
        Write-Verbose "Registry key has been added/modified"
    } else {}
}

##--Checks if local Administrator account is disabled and disables if not
function Test-Administrator {
    if ($AdministratorDisabled -eq $True) {
        Write-Verbose "Checking if local Administrator account is disabled."
        if ((get-localuser 'Administrator').enabled) {
            Disable-LocalUser 'Administrator'
            Write-Verbose "Local Administrator account has been disabled."
        } else {
            Write-Verbose "Local Administrator account is already disabled."
        }
    } else {}
}

<#------------------------------------------------------------------------------------------------------------
SCRIPT:EXECUTIONS
------------------------------------------------------------------------------------------------------------#>

Test-User
New-User
Set-RegKey
Test-Administrator