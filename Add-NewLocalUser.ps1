<#----------------------------------------------------------------------------------------------------------
DEVELOPMENT
------------------------------------------------------------------------------------------------------------
    > CREATED: 23-07-22 | TawTek
    > UPDATED: 23-08-18 | TawTek
    > VERSION: 4.0
------------------------------------------------------------------------------------------------------------
DESCRIPTION - Create new local user account
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
GITHUB - https://github.com/TawTek/MSP-Automation-Scripts/blob/main/Add-NewLocalUser.ps1
----------------------------------------------------------------------------------------------------------#>

#-Parameters
param(
    [string] $NewUser,
    [string] $Group,
    [string] $Password,
    [string] $AdministratorDisabled
)
#-Variables
$VerbosePreference = "Continue"
$CheckUser = Get-LocalUser -Name $NewUser -ErrorAction SilentlyContinue

<#------------------------------------------------------------------------------------------------------------
SCRIPT:FUNCTIONS
------------------------------------------------------------------------------------------------------------#>

##--Checks if all parameters are defined and whether $NewUser exists and creates if not
function New-User {
    if ($NewUser -and $Group -and $Password){
        Write-Verbose "Checking if $NewUser exists."
        if ($CheckUser){
            Write-Verbose "$NewUser already exists, terminating script."
        } else {
            Write-Verbose "$NewUser does not exist. Creating user account."
            ###---Utilize splatting using parameters defined to create new local user
            $NewUserParams = @{
                'AccountNeverExpires' = $true;
                'Password' = (ConvertTo-SecureString -AsPlainText -Force $Password);
                'Name' = $NewUser;
                'PasswordNeverExpires' = $true
            }
            New-LocalUser @NewUserParams -ErrorAction Stop | Add-LocalGroupMember -Group $Group -ErrorAction Stop
            Write-Verbose "$NewUser account has been created belonging to the $Group group with password set as $Password"
        }
        Write-Verbose "Modifying registry to prevent OOBE and Privacy Expereience upon first login."
    } else {
        Write-Verbose "All parameters must be defined: enter Username, User Group, and Password when executing script."
        exit
    }
}

##--Bypass OOBE + Privacy Experience
function Set-OOBEbypass {
    ###---Declare RegKey variables
    $RegKey = @{
        Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
        Name = "EnableFirstLogonAnimation"
        Value = 0
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
        Path = "HKLM:\Software\Policies\Microsoft\Windows\OOBE"
        Name = "DisablePrivacyExperience"
        Value = 1
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
        Path = "HKCU:\Software\Policies\Microsoft\Windows\OOBE"
        Name = "DisablePrivacyExperience"
        Value = 1
        PropertyType = "DWORD"
    }
    if (-not (Test-Path $RegKey.Path)) {
        Write-Verbose "$($RegKey.Path) does not exist. Creatng path."
        New-Item -Path $RegKey.Path -Force
        Write-Verbose "$($RegKey.Path) path has been created."
    }
    New-ItemProperty @RegKey -Force
    Write-Verbose "Registry key has been added/modified"
}

##--Checks if local Administrator account is disabled and disables if not
function Test-Administrator {
    if ($AdministratorDisabled -eq $True){
        Write-Verbose "Checking if local Administrator account is disabled."
        if ((Get-LocalUser 'Administrator').enabled) {
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

New-User
Set-OOBEbypass
Test-Administrator
